// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
//
// Copyright (c) 2020 Marvell International Ltd. All rights reserved.
//

#include "prestera.h"
#include "prestera_hw.h"

#define PRESTERA_DEFAULT_TC_NUM	8

static int mvsw_pr_flower_parse_actions(struct mvsw_pr_switch *sw,
					struct prestera_acl_block *block,
					struct prestera_acl_rule *rule,
					struct flow_action *flow_action,
					struct netlink_ext_ack *extack)
{
	const struct flow_action_entry *act;
	struct prestera_acl_rule_action_entry *a_entry;
	int i;

	if (!flow_action_has_entries(flow_action))
		return 0;

	flow_action_for_each(i, act, flow_action) {
		/* allocate action entry */
		a_entry = kmalloc(sizeof(*a_entry), GFP_KERNEL);
		if (!a_entry)
			return -ENOMEM;

		switch (act->id) {
		case FLOW_ACTION_ACCEPT:
			a_entry->id = MVSW_ACL_RULE_ACTION_ACCEPT;
			prestera_acl_rule_action_add(rule, a_entry);
			break;
		case FLOW_ACTION_DROP:
			a_entry->id = MVSW_ACL_RULE_ACTION_DROP;
			prestera_acl_rule_action_add(rule, a_entry);
			break;
		case FLOW_ACTION_TRAP:
			a_entry->id = MVSW_ACL_RULE_ACTION_TRAP;
			prestera_acl_rule_action_add(rule, a_entry);
			break;
		case FLOW_ACTION_POLICE:
			a_entry->id = MVSW_ACL_RULE_ACTION_POLICE;
			a_entry->police.rate = act->police.rate_bytes_ps;
			a_entry->police.burst =
				div_u64(a_entry->police.rate *
					PSCHED_NS2TICKS(act->police.burst),
					PSCHED_TICKS_PER_SEC);
			prestera_acl_rule_action_add(rule, a_entry);
			break;
		default:
			kfree(a_entry);
			NL_SET_ERR_MSG_MOD(extack, "Unsupported action");
			pr_err("Unsupported action\n");
			return -EOPNOTSUPP;
		}
	}

	return 0;
}

static int mvsw_pr_flower_parse_meta(struct prestera_acl_rule *rule,
				     struct flow_cls_offload *f,
				     struct prestera_acl_block *block)
{
	struct flow_rule *f_rule = flow_cls_offload_flow_rule(f);
	struct prestera_acl_rule_match_entry *m_entry;
	struct mvsw_pr_port *port;
	struct net_device *ingress_dev;
	struct flow_match_meta match;

	flow_rule_match_meta(f_rule, &match);
	if (match.mask->ingress_ifindex != 0xFFFFFFFF) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "Unsupported ingress ifindex mask");
		return -EINVAL;
	}

	ingress_dev = __dev_get_by_index(prestera_acl_block_net(block),
					 match.key->ingress_ifindex);
	if (!ingress_dev) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "Can't find specified ingress port to match on");
		return -EINVAL;
	}

	if (!mvsw_pr_netdev_check(ingress_dev)) {
		NL_SET_ERR_MSG_MOD(f->common.extack,
				   "Can't match on switchdev ingress port");
		return -EINVAL;
	}
	port = netdev_priv(ingress_dev);

	/* add port key,mask */
	m_entry = kmalloc(sizeof(*m_entry), GFP_KERNEL);
	if (!m_entry)
		return -ENOMEM;

	m_entry->type = MVSW_ACL_RULE_MATCH_ENTRY_TYPE_PORT;
	m_entry->keymask.u64.key = port->hw_id | ((u64)port->dev_id << 32);
	m_entry->keymask.u64.mask = ~(u64)0;
	prestera_acl_rule_match_add(rule, m_entry);

	return 0;
}

static int mvsw_pr_flower_parse(struct mvsw_pr_switch *sw,
				struct prestera_acl_block *block,
				struct prestera_acl_rule *rule,
				struct flow_cls_offload *f)
{
	struct flow_rule *f_rule = flow_cls_offload_flow_rule(f);
	struct flow_dissector *dissector = f_rule->match.dissector;
	struct prestera_acl_rule_match_entry *m_entry;
	u16 n_proto_mask = 0;
	u16 n_proto_key = 0;
	u16 addr_type = 0;
	u8 ip_proto = 0;
	u32 hwtc = 0;
	int err;

	if (dissector->used_keys &
	    ~(BIT(FLOW_DISSECTOR_KEY_META) |
	      BIT(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_ICMP) |
	      BIT(FLOW_DISSECTOR_KEY_PORTS) |
	      BIT(FLOW_DISSECTOR_KEY_PORTS_RANGE) |
	      BIT(FLOW_DISSECTOR_KEY_VLAN))) {
		NL_SET_ERR_MSG_MOD(f->common.extack, "Unsupported key");
		return -EOPNOTSUPP;
	}

	if (f->classid) {
		/* The classid values of TC_H_MIN_PRIORITY through
		 * TC_H_MIN_PRIORITY + PRESTERA_DEFAULT_TC_NUM - 1 represents
		 * the hardware traffic classes.
		 */
		hwtc = TC_H_MIN(f->classid) - TC_H_MIN_PRIORITY;
		if (hwtc >= PRESTERA_DEFAULT_TC_NUM) {
			NL_SET_ERR_MSG_MOD(f->common.extack,
					   "Unsupported HW TC");
			return -EINVAL;
		}
		prestera_acl_rule_hw_tc_set(rule, hwtc);
	}

	prestera_acl_rule_priority_set(rule, f->common.prio);

	if (flow_rule_match_key(f_rule, FLOW_DISSECTOR_KEY_META)) {
		err = mvsw_pr_flower_parse_meta(rule, f, block);
		if (err)
			return err;
	}

	if (flow_rule_match_key(f_rule, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_match_control match;

		flow_rule_match_control(f_rule, &match);
		addr_type = match.key->addr_type;
	}

	if (flow_rule_match_key(f_rule, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_match_basic match;

		flow_rule_match_basic(f_rule, &match);
		n_proto_key = ntohs(match.key->n_proto);
		n_proto_mask = ntohs(match.mask->n_proto);

		if (n_proto_key == ETH_P_ALL) {
			n_proto_key = 0;
			n_proto_mask = 0;
		}

		/* add eth type key,mask */
		m_entry = kmalloc(sizeof(*m_entry), GFP_KERNEL);
		if (!m_entry)
			return -ENOMEM;

		m_entry->type = MVSW_ACL_RULE_MATCH_ENTRY_TYPE_ETH_TYPE;
		m_entry->keymask.u16.key = n_proto_key;
		m_entry->keymask.u16.mask = n_proto_mask;
		prestera_acl_rule_match_add(rule, m_entry);

		/* add ip proto key,mask */
		m_entry = kmalloc(sizeof(*m_entry), GFP_KERNEL);
		if (!m_entry)
			return -ENOMEM;

		m_entry->type = MVSW_ACL_RULE_MATCH_ENTRY_TYPE_IP_PROTO;
		m_entry->keymask.u8.key = match.key->ip_proto;
		m_entry->keymask.u8.mask = match.mask->ip_proto;
		prestera_acl_rule_match_add(rule, m_entry);
		ip_proto = match.key->ip_proto;
	}

	if (flow_rule_match_key(f_rule, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_match_eth_addrs match;

		flow_rule_match_eth_addrs(f_rule, &match);

		/* add ethernet dst key,mask */
		m_entry = kmalloc(sizeof(*m_entry), GFP_KERNEL);
		if (!m_entry)
			return -ENOMEM;

		m_entry->type = MVSW_ACL_RULE_MATCH_ENTRY_TYPE_ETH_DMAC;
		memcpy(&m_entry->keymask.mac.key,
		       &match.key->dst, sizeof(match.key->dst));
		memcpy(&m_entry->keymask.mac.mask,
		       &match.mask->dst, sizeof(match.mask->dst));
		prestera_acl_rule_match_add(rule, m_entry);

		/* add ethernet src key,mask */
		m_entry = kmalloc(sizeof(*m_entry), GFP_KERNEL);
		if (!m_entry)
			return -ENOMEM;

		m_entry->type = MVSW_ACL_RULE_MATCH_ENTRY_TYPE_ETH_SMAC;
		memcpy(&m_entry->keymask.mac.key,
		       &match.key->src, sizeof(match.key->src));
		memcpy(&m_entry->keymask.mac.mask,
		       &match.mask->src, sizeof(match.mask->src));
		prestera_acl_rule_match_add(rule, m_entry);
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_match_ipv4_addrs match;

		flow_rule_match_ipv4_addrs(f_rule, &match);

		m_entry = kmalloc(sizeof(*m_entry), GFP_KERNEL);
		if (!m_entry)
			return -ENOMEM;

		m_entry->type = MVSW_ACL_RULE_MATCH_ENTRY_TYPE_IP_SRC;
		memcpy(&m_entry->keymask.u32.key,
		       &match.key->src, sizeof(match.key->src));
		memcpy(&m_entry->keymask.u32.mask,
		       &match.mask->src, sizeof(match.mask->src));
		prestera_acl_rule_match_add(rule, m_entry);

		m_entry = kmalloc(sizeof(*m_entry), GFP_KERNEL);
		if (!m_entry)
			return -ENOMEM;

		m_entry->type = MVSW_ACL_RULE_MATCH_ENTRY_TYPE_IP_DST;
		memcpy(&m_entry->keymask.u32.key,
		       &match.key->dst, sizeof(match.key->dst));
		memcpy(&m_entry->keymask.u32.mask,
		       &match.mask->dst, sizeof(match.mask->dst));
		prestera_acl_rule_match_add(rule, m_entry);
	}

	if (flow_rule_match_key(f_rule, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_match_ports match;

		if (ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_UDP) {
			NL_SET_ERR_MSG_MOD
			    (f->common.extack,
			     "Only UDP and TCP keys are supported");
			return -EINVAL;
		}

		flow_rule_match_ports(f_rule, &match);

		m_entry = kmalloc(sizeof(*m_entry), GFP_KERNEL);
		if (!m_entry)
			return -ENOMEM;
		m_entry->type = MVSW_ACL_RULE_MATCH_ENTRY_TYPE_L4_PORT_SRC;
		m_entry->keymask.u16.key = ntohs(match.key->src);
		m_entry->keymask.u16.mask = ntohs(match.mask->src);
		prestera_acl_rule_match_add(rule, m_entry);

		m_entry = kmalloc(sizeof(*m_entry), GFP_KERNEL);
		if (!m_entry)
			return -ENOMEM;
		m_entry->type = MVSW_ACL_RULE_MATCH_ENTRY_TYPE_L4_PORT_DST;
		m_entry->keymask.u16.key = ntohs(match.key->dst);
		m_entry->keymask.u16.mask = ntohs(match.mask->dst);
		prestera_acl_rule_match_add(rule, m_entry);
	}

	if (flow_rule_match_key(f_rule, FLOW_DISSECTOR_KEY_PORTS_RANGE)) {
		struct flow_match_ports_range match;

		flow_rule_match_ports_range(f_rule, &match);

		m_entry = kmalloc(sizeof(*m_entry), GFP_KERNEL);
		if (!m_entry)
			return -ENOMEM;
		m_entry->type =
			MVSW_ACL_RULE_MATCH_ENTRY_TYPE_L4_PORT_RANGE_SRC;
		m_entry->keymask.u32.key = ntohs(match.key->tp_min.src) |
				(u32)ntohs(match.key->tp_max.src) << 16;
		m_entry->keymask.u32.mask = ntohs(match.mask->tp_min.src) |
				(u32)ntohs(match.mask->tp_max.src) << 16;
		prestera_acl_rule_match_add(rule, m_entry);

		m_entry = kmalloc(sizeof(*m_entry), GFP_KERNEL);
		if (!m_entry)
			return -ENOMEM;
		m_entry->type =
			MVSW_ACL_RULE_MATCH_ENTRY_TYPE_L4_PORT_RANGE_DST;
		m_entry->keymask.u32.key = ntohs(match.key->tp_min.dst) |
				(u32)ntohs(match.key->tp_max.dst) << 16;
		m_entry->keymask.u32.mask = ntohs(match.mask->tp_min.dst) |
				(u32)ntohs(match.mask->tp_max.dst) << 16;
		prestera_acl_rule_match_add(rule, m_entry);
	}

	if (flow_rule_match_key(f_rule, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_match_vlan match;

		flow_rule_match_vlan(f_rule, &match);

		if (match.mask->vlan_id != 0) {
			m_entry = kmalloc(sizeof(*m_entry), GFP_KERNEL);
			if (!m_entry)
				return -ENOMEM;
			m_entry->type = MVSW_ACL_RULE_MATCH_ENTRY_TYPE_VLAN_ID;
			m_entry->keymask.u16.key = match.key->vlan_id;
			m_entry->keymask.u16.mask = match.mask->vlan_id;
			prestera_acl_rule_match_add(rule, m_entry);
		}

		m_entry = kmalloc(sizeof(*m_entry), GFP_KERNEL);
		if (!m_entry)
			return -ENOMEM;
		m_entry->type = MVSW_ACL_RULE_MATCH_ENTRY_TYPE_VLAN_TPID;
		m_entry->keymask.u16.key = ntohs(match.key->vlan_tpid);
		m_entry->keymask.u16.mask = ntohs(match.mask->vlan_tpid);
		prestera_acl_rule_match_add(rule, m_entry);
	}

	if (flow_rule_match_key(f_rule, FLOW_DISSECTOR_KEY_ICMP)) {
		struct flow_match_icmp match;

		flow_rule_match_icmp(f_rule, &match);

		m_entry = kmalloc(sizeof(*m_entry), GFP_KERNEL);
		if (!m_entry)
			return -ENOMEM;
		m_entry->type = MVSW_ACL_RULE_MATCH_ENTRY_TYPE_ICMP_TYPE;
		m_entry->keymask.u8.key = match.key->type;
		m_entry->keymask.u8.mask = match.mask->type;
		prestera_acl_rule_match_add(rule, m_entry);

		m_entry = kmalloc(sizeof(*m_entry), GFP_KERNEL);
		if (!m_entry)
			return -ENOMEM;
		m_entry->type = MVSW_ACL_RULE_MATCH_ENTRY_TYPE_ICMP_CODE;
		m_entry->keymask.u8.key = match.key->code;
		m_entry->keymask.u8.mask = match.mask->code;
		prestera_acl_rule_match_add(rule, m_entry);
	}

	return mvsw_pr_flower_parse_actions(sw, block, rule,
					    &f->rule->action,
					    f->common.extack);
}

int mvsw_pr_flower_replace(struct mvsw_pr_switch *sw,
			   struct prestera_acl_block *block,
			   struct flow_cls_offload *f)
{
	struct prestera_acl_rule *rule;
	int err;

	rule = prestera_acl_rule_create(block, f->cookie);
	if (IS_ERR(rule))
		return PTR_ERR(rule);

	err = mvsw_pr_flower_parse(sw, block, rule, f);
	if (err)
		goto err_flower_parse;

	err = prestera_acl_rule_add(sw, rule);
	if (err)
		goto err_rule_add;

	return 0;

err_rule_add:
err_flower_parse:
	prestera_acl_rule_destroy(rule);
	return err;
}

void mvsw_pr_flower_destroy(struct mvsw_pr_switch *sw,
			    struct prestera_acl_block *block,
			    struct flow_cls_offload *f)
{
	struct prestera_acl_rule *rule;

	rule = prestera_acl_rule_lookup(prestera_acl_block_ruleset_get(block),
					f->cookie);
	if (rule) {
		prestera_acl_rule_del(sw, rule);
		prestera_acl_rule_destroy(rule);
	}
}

int mvsw_pr_flower_stats(struct mvsw_pr_switch *sw,
			 struct prestera_acl_block *block,
			 struct flow_cls_offload *f)
{
	struct prestera_acl_rule *rule;
	u64 packets;
	u64 lastuse;
	u64 bytes;
	int err;

	rule = prestera_acl_rule_lookup(prestera_acl_block_ruleset_get(block),
					f->cookie);
	if (!rule)
		return -EINVAL;

	err = prestera_acl_rule_get_stats(sw, rule, &packets, &bytes, &lastuse);
	if (err)
		return err;

	flow_stats_update(&f->stats, bytes, packets, 0, lastuse,
			  FLOW_ACTION_HW_STATS_IMMEDIATE);
	return 0;
}
