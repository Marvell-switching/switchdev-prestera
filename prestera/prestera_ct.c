// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include <linux/rhashtable.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/tc_act/tc_ct.h>
#include <linux/bitops.h>

#include "prestera.h"
#include "prestera_log.h"
#include "prestera_hw.h"
#include "prestera_ct.h"
#include "prestera_acl.h"
#include "prestera_counter.h"

#define PRESTERA_ACL_CT_CHAIN 1
#define PRESTERA_ACL_CT_TRAP_PRIO 0xfffffffe
#define PRESTERA_ACL_CT_MATCHES 4
#define PRESTERA_ACL_CT_HW_TC	18

enum mangle_act_mask {
	MANGLE_ACT_IP4_SRC_BIT = BIT(0),
	MANGLE_ACT_IP4_DST_BIT = BIT(1),
	MANGLE_ACT_PORT_SRC_BIT = BIT(2),
	MANGLE_ACT_PORT_DST_BIT = BIT(3)
};

struct prestera_ct_tuple {
	u16 zone;
	struct prestera_acl_rule_entry_key re_key;
	struct prestera_acl_rule_entry_arg re_arg;
	struct prestera_acl_rule_entry *re;
};

struct prestera_ct_priv {
	struct prestera_acl *acl;
	struct rhashtable zone_ht;
	struct prestera_acl_rule_entry *re;
	u32 vtcam_id;
	u16 pcl_id;
	u32 index;
};

struct prestera_ct_entry {
	struct rhash_head node;
	unsigned long cookie;
	struct prestera_ct_tuple tuple;
	volatile struct {
		u64 lastuse, packets, bytes;
	} stats; /* cache */
};

struct prestera_ct_ft {
	struct rhash_head node;
	u16 zone;
	refcount_t refcount;
	struct prestera_ct_priv *ct_priv;
	struct nf_flowtable *nf_ft;
	struct rhashtable ct_entries_ht;
};

static const struct rhashtable_params ct_entry_ht_params = {
	.head_offset = offsetof(struct prestera_ct_entry, node),
	.key_offset = offsetof(struct prestera_ct_entry, cookie),
	.key_len = sizeof(((struct prestera_ct_entry *)0)->cookie),
	.automatic_shrinking = true,
};

static const struct rhashtable_params ct_zone_ht_params = {
	.head_offset = offsetof(struct prestera_ct_ft, node),
	.key_offset = offsetof(struct prestera_ct_ft, zone),
	.key_len = sizeof(((struct prestera_ct_ft *)0)->zone),
	.automatic_shrinking = true,
};

static struct workqueue_struct *prestera_ct_owq;

static int prestera_ct_chain_init(struct prestera_ct_priv *priv)
{
	struct prestera_acl_rule_entry_key re_key;
	struct prestera_acl_rule_entry_arg re_arg;
	struct prestera_acl_iface iface;
	u16 pcl_id;
	u32 uid = 0;
	int err;

	err = idr_alloc_u32(&priv->acl->uid, NULL, &uid, U8_MAX, GFP_KERNEL);
	if (err)
		return err;

	/* create vtcam with specific keymask/template */
	memset(&re_key, 0, sizeof(re_key));
	rule_match_set_u16(re_key.match.mask, PCL_ID,
			   PRESTERA_ACL_KEYMASK_PCL_ID);
	rule_match_set_u16(re_key.match.mask, ETH_TYPE, 0xFFFF);
	rule_match_set_u8(re_key.match.mask, IP_PROTO, 0xFF);
	rule_match_set_u32(re_key.match.mask, IP_SRC, 0xFFFFFFFF);
	rule_match_set_u32(re_key.match.mask, IP_DST, 0xFFFFFFFF);
	rule_match_set_u16(re_key.match.mask, L4_PORT_SRC, 0xFFFF);
	rule_match_set_u16(re_key.match.mask, L4_PORT_DST, 0xFFFF);

	err = prestera_acl_vtcam_id_get(priv->acl, PRESTERA_ACL_CT_CHAIN,
					PRESTERA_HW_VTCAM_DIR_INGRESS,
					re_key.match.mask, &priv->vtcam_id);
	if (err)
		goto err_vtcam_create;

	/* make pcl-id based on uid and chain */
	pcl_id = PRESTERA_ACL_PCL_ID_MAKE(uid, PRESTERA_ACL_CT_CHAIN);

	/* bind iface index to pcl-id to be able to jump to this from
	 * any other rules.
	 */
	iface.index = uid;
	iface.type = PRESTERA_ACL_IFACE_TYPE_INDEX;
	err = prestera_hw_vtcam_iface_bind(priv->acl->sw, &iface,
					   priv->vtcam_id, pcl_id);
	if (err)
		goto err_rule_entry_bind;

	memset(&re_key, 0, sizeof(re_key));
	re_key.prio = PRESTERA_ACL_CT_TRAP_PRIO;
	rule_match_set_u16(re_key.match.key, PCL_ID, pcl_id);
	rule_match_set_u16(re_key.match.mask, PCL_ID,
			   PRESTERA_ACL_KEYMASK_PCL_ID);

	memset(&re_arg, 0, sizeof(re_arg));
	re_arg.trap.valid = 1;
	re_arg.trap.i.hw_tc = PRESTERA_ACL_CT_HW_TC;
	re_arg.vtcam_id = priv->vtcam_id;

	priv->re = prestera_acl_rule_entry_create(priv->acl, &re_key, &re_arg);
	if (!priv->re) {
		err = -EINVAL;
		goto err_rule_entry_create;
	}

	priv->pcl_id = pcl_id;
	priv->index = uid;
	return 0;

err_rule_entry_create:
	prestera_hw_vtcam_iface_unbind(priv->acl->sw, &iface, priv->vtcam_id);
err_rule_entry_bind:
	prestera_acl_vtcam_id_put(priv->acl, priv->vtcam_id);
err_vtcam_create:
	idr_remove(&priv->acl->uid, uid);
	return err;
}

struct prestera_ct_priv *prestera_ct_init(struct prestera_acl *acl)
{
	struct prestera_ct_priv *ct_priv;

	ct_priv = kzalloc(sizeof(*ct_priv), GFP_KERNEL);
	if (!ct_priv)
		return ERR_PTR(-ENOMEM);

	rhashtable_init(&ct_priv->zone_ht, &ct_zone_ht_params);
	ct_priv->acl = acl;

	if (prestera_ct_chain_init(ct_priv))
		return ERR_PTR(-EINVAL);

	prestera_ct_owq = alloc_ordered_workqueue("%s_ordered", 0,
						  "prestera_ct");
	if (!prestera_ct_owq)
		return ERR_PTR(-ENOMEM);

	return ct_priv;
}

void prestera_ct_clean(struct prestera_ct_priv *ct_priv)
{
	u8 uid = ct_priv->pcl_id & PRESTERA_ACL_KEYMASK_PCL_ID_USER;

	if (!ct_priv)
		return;

	destroy_workqueue(prestera_ct_owq);

	prestera_acl_rule_entry_destroy(ct_priv->acl, ct_priv->re);
	prestera_acl_vtcam_id_put(ct_priv->acl, ct_priv->vtcam_id);
	idr_remove(&ct_priv->acl->uid, uid);
	rhashtable_destroy(&ct_priv->zone_ht);
	kfree(ct_priv);
}

int prestera_ct_match_parse(struct flow_cls_offload *f,
			    struct netlink_ext_ack *extack)
{
	struct flow_rule *f_rule = flow_cls_offload_flow_rule(f);
	struct flow_dissector_key_ct *mask, *key;
	bool trk, est, untrk, unest, new;
	u16 ct_state_on, ct_state_off;
	u16 ct_state, ct_state_mask;
	struct flow_match_ct match;

	if (!flow_rule_match_key(f_rule, FLOW_DISSECTOR_KEY_CT))
		return 0;

	flow_rule_match_ct(f_rule, &match);

	key = match.key;
	mask = match.mask;

	ct_state = key->ct_state;
	ct_state_mask = mask->ct_state;

	if (ct_state_mask & ~(TCA_FLOWER_KEY_CT_FLAGS_TRACKED |
			      TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED |
			      TCA_FLOWER_KEY_CT_FLAGS_NEW)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "only ct_state trk, est and new are supported for offload");
		return -EOPNOTSUPP;
	}

	ct_state_on = ct_state & ct_state_mask;
	ct_state_off = (ct_state & ct_state_mask) ^ ct_state_mask;

	trk = ct_state_on & TCA_FLOWER_KEY_CT_FLAGS_TRACKED;
	new = ct_state_on & TCA_FLOWER_KEY_CT_FLAGS_NEW;
	est = ct_state_on & TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED;

	untrk = ct_state_off & TCA_FLOWER_KEY_CT_FLAGS_TRACKED;
	unest = ct_state_off & TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED;

	MVSW_LOG_INFO("trk=%d new=%d est=%d untrk=%d unest=%d",
		      trk, new, est, untrk, unest);

	if (new) {
		NL_SET_ERR_MSG_MOD(extack,
				   "matching on ct_state +new isn't supported");
		return -EOPNOTSUPP;
	}

	return 0;
}

int prestera_ct_parse_action(const struct flow_action_entry *act,
			     struct prestera_acl_rule *rule,
			     struct netlink_ext_ack *extack)

{
	struct prestera_ct_attr *ct_attr;

	ct_attr = &rule->attr.ct_attr;

	ct_attr->zone = act->ct.zone;
	ct_attr->ct_action = act->ct.action;
	ct_attr->nf_ft = act->ct.flow_table;

	return 0;
}

static struct flow_action_entry *
prestera_ct_get_ct_metadata_action(struct flow_rule *flow_rule)
{
	struct flow_action *flow_action = &flow_rule->action;
	struct flow_action_entry *act;
	int i;

	flow_action_for_each(i, act, flow_action) {
		if (act->id == FLOW_ACTION_CT_METADATA)
			return act;
	}

	return NULL;
}

static int
prestera_ct_flow_rule_to_tuple(struct flow_rule *rule,
			       struct prestera_ct_tuple *tuple)
{
	struct prestera_acl_match *r_match = &tuple->re_key.match;
	struct flow_match_ipv4_addrs ipv4_match;
	struct flow_match_ports ports_match;
	struct flow_match_control control;
	struct flow_match_basic basic;
	u16 addr_type;
	u8 ip_proto;

	flow_rule_match_basic(rule, &basic);
	flow_rule_match_control(rule, &control);

	ip_proto = basic.key->ip_proto;
	addr_type = control.key->addr_type;

	if (addr_type != FLOW_DISSECTOR_KEY_IPV4_ADDRS)
		return -EOPNOTSUPP;

	flow_rule_match_ipv4_addrs(rule, &ipv4_match);

	rule_match_set(r_match->key, IP_SRC, ipv4_match.key->src);
	rule_match_set(r_match->mask, IP_SRC, ipv4_match.mask->src);

	rule_match_set(r_match->key, IP_DST, ipv4_match.key->dst);
	rule_match_set(r_match->mask, IP_DST, ipv4_match.mask->dst);

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_PORTS))
		return -EOPNOTSUPP;

	flow_rule_match_ports(rule, &ports_match);
	switch (ip_proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		rule_match_set(r_match->key,
			       L4_PORT_SRC, ports_match.key->src);
		rule_match_set(r_match->mask,
			       L4_PORT_SRC, ports_match.mask->src);

		rule_match_set(r_match->key,
			       L4_PORT_DST, ports_match.key->dst);
		rule_match_set(r_match->mask,
			       L4_PORT_DST, ports_match.mask->dst);
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (!flow_rule_match_key(rule, FLOW_DISSECTOR_KEY_META))
		return -EOPNOTSUPP;

	/* metadata match is set but not information is present.
	 * Issue? Need to investigate on kernel side.
	 */
	return 0;
}

static int
__prestera_ct_tuple_get_mangle(struct flow_rule *rule,
			       struct prestera_ct_tuple *tuple)
{
	struct flow_action *flow_action = &rule->action;
	struct flow_action_entry *act;
	u32 offset, val;
	int i;
	struct prestera_mangle_cfg *mc;

	mc = &tuple->re_arg.nh.k.mangle;
	flow_action_for_each(i, act, flow_action) {
		if (act->id != FLOW_ACTION_MANGLE)
			continue;

		offset = act->mangle.offset;
		val = act->mangle.val;
		switch (act->mangle.htype) {
		case FLOW_ACT_MANGLE_HDR_TYPE_IP4:
			if (offset == offsetof(struct iphdr, saddr)) {
				mc->sip.u.ipv4 =
					cpu_to_be32(val);
				mc->sip_valid = true;
			} else if (offset == offsetof(struct iphdr, daddr)) {
				mc->dip.u.ipv4 =
					cpu_to_be32(val);
				mc->dip_valid = true;
			} else {
				return -EOPNOTSUPP;
			}
			break;
		case FLOW_ACT_MANGLE_HDR_TYPE_TCP:
			if (offset == offsetof(struct tcphdr, source)) {
				mc->l4_src = cpu_to_be16(val);
				mc->l4_src_valid = true;
			} else if (offset == offsetof(struct tcphdr, dest)) {
				mc->l4_dst = cpu_to_be16(val);
				mc->l4_dst_valid = true;
			} else {
				return -EOPNOTSUPP;
			}
			break;
		case FLOW_ACT_MANGLE_HDR_TYPE_UDP:
			if (offset == offsetof(struct udphdr, source)) {
				mc->l4_src = cpu_to_be16(val);
				mc->l4_src_valid = true;
			} else if (offset == offsetof(struct udphdr, dest)) {
				mc->l4_dst = cpu_to_be16(val);
				mc->l4_dst_valid = true;
			} else {
				return -EOPNOTSUPP;
			}
			break;
		default:
			return -EOPNOTSUPP;
		}
	}

	return 0;
}

static int __prestera_ct_tuple_get_nh(struct prestera_switch *sw,
				      struct prestera_ct_tuple *tuple)
{
	struct prestera_ip_addr ip;
	struct prestera_nexthop_group_key nh_grp_key;
	struct prestera_mangle_cfg *mc;

	mc = &tuple->re_arg.nh.k.mangle;
	memset(&ip, 0, sizeof(ip));
	memcpy(&ip.u.ipv4,
	       mc->sip_valid ?
	       (void *)&rule_match_get_u32(tuple->re_key.match.key, IP_DST) :
	       (void *)&mc->dip.u.ipv4,
	       sizeof(ip.u.ipv4));

	/* TODO: VRF */
	/* TODO: ECMP */
	if (prestera_util_kern_dip2nh_grp_key(sw, RT_TABLE_MAIN, &ip,
					      &nh_grp_key) != 1)
		return -ENOTSUPP;

	tuple->re_arg.nh.k.n = nh_grp_key.neigh[0];

	return 0;
}

static int __prestera_ct_tuple2acl_add(struct prestera_acl *acl,
				       struct prestera_ct_tuple *tuple)
{
	tuple->re = prestera_acl_rule_entry_find(acl, &tuple->re_key);
	if (tuple->re) {
		tuple->re = NULL;
		return -EEXIST;
	}

	tuple->re = prestera_acl_rule_entry_create(acl, &tuple->re_key,
						   &tuple->re_arg);
	if (!tuple->re)
		return -EINVAL;

	return 0;
}

static int
prestera_ct_block_flow_offload_add(struct prestera_ct_ft *ft,
				   struct flow_cls_offload *flow)
{
	struct flow_rule *flow_rule = flow_cls_offload_flow_rule(flow);
	struct flow_action_entry *meta_action;
	unsigned long cookie = flow->cookie;
	struct prestera_ct_entry *entry;
	int err;

	meta_action = prestera_ct_get_ct_metadata_action(flow_rule);
	if (!meta_action)
		return -EOPNOTSUPP;

	entry = rhashtable_lookup_fast(&ft->ct_entries_ht, &cookie,
				       ct_entry_ht_params);
	if (entry)
		return 0;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->tuple.zone = ft->zone;
	entry->cookie = flow->cookie;
	entry->tuple.re_key.prio = flow->common.prio;
	entry->tuple.re_arg.vtcam_id = ft->ct_priv->vtcam_id;

	/* set pcl-id for this rule */
	rule_match_set_u16(entry->tuple.re_key.match.key,
			   PCL_ID, ft->ct_priv->pcl_id);
	rule_match_set_u16(entry->tuple.re_key.match.mask,
			   PCL_ID, PRESTERA_ACL_KEYMASK_PCL_ID);

	err = prestera_ct_flow_rule_to_tuple(flow_rule, &entry->tuple);
	if (err)
		goto err_set;

	/* Do we need sanity check before "valid = 1" ? */
	entry->tuple.re_arg.nh.valid = 1;

	err = __prestera_ct_tuple_get_mangle(flow_rule, &entry->tuple);
	if (err)
		goto err_set;

	/* setup counter */
	entry->tuple.re_arg.count.valid = true;
	err = prestera_acl_chain_to_client(PRESTERA_ACL_CT_CHAIN,
					   true /* ingress */,
					   &entry->tuple.re_arg.count.client);
	if (err)
		goto err_set;

	err = __prestera_ct_tuple_get_nh(ft->ct_priv->acl->sw, &entry->tuple);
	if (err)
		goto err_set;

	/* HW offload */
	err = __prestera_ct_tuple2acl_add(ft->ct_priv->acl, &entry->tuple);
	if (err)
		goto err_set;

	err = rhashtable_insert_fast(&ft->ct_entries_ht, &entry->node,
				     ct_entry_ht_params);
	if (err)
		goto err_insert;

	return 0;

err_insert:
	prestera_acl_rule_entry_destroy(ft->ct_priv->acl, entry->tuple.re);

err_set:
	kfree(entry);
	return err;
}

static int
prestera_ct_block_flow_offload_del(struct prestera_ct_ft *ft,
				   struct flow_cls_offload *flow)
{
	unsigned long cookie = flow->cookie;
	struct prestera_ct_entry *entry;

	entry = rhashtable_lookup_fast(&ft->ct_entries_ht, &cookie,
				       ct_entry_ht_params);
	if (!entry)
		return -ENOENT;

	prestera_acl_rule_entry_destroy(ft->ct_priv->acl, entry->tuple.re);
	rhashtable_remove_fast(&ft->ct_entries_ht,
			       &entry->node, ct_entry_ht_params);
	kfree(entry);
	return 0;
}

static int
prestera_ct_block_flow_offload_stats(struct prestera_ct_ft *ft,
				     struct flow_cls_offload *f)
{
	unsigned long cookie = f->cookie;
	struct prestera_ct_entry *entry;
	u64 packets, bytes;
	int err;

	entry = rhashtable_lookup_fast(&ft->ct_entries_ht, &cookie,
				       ct_entry_ht_params);
	if (!entry)
		return -ENOENT;

	err = prestera_counter_stats_get(ft->ct_priv->acl->sw->counter,
					 entry->tuple.re->counter.block,
					 entry->tuple.re->counter.id,
					 &packets, &bytes);
	if (err)
		return err;

	if (packets != entry->stats.packets || bytes != entry->stats.bytes) {
		entry->stats.packets = packets;
		entry->stats.bytes = bytes;
		entry->stats.lastuse = jiffies;
	}

	flow_stats_update(&f->stats,
			  entry->stats.bytes,
			  entry->stats.packets,
			  0,
			  entry->stats.lastuse,
			  FLOW_ACTION_HW_STATS_DELAYED);

	return 0;
}

static int
prestera_ct_block_flow_offload(enum tc_setup_type type, void *type_data,
			       void *cb_priv)
{
	struct flow_cls_offload *f = type_data;
	struct prestera_ct_ft *ft = cb_priv;
	int err;

	if (type != TC_SETUP_CLSFLOWER)
		return -EOPNOTSUPP;

	switch (f->command) {
	case FLOW_CLS_REPLACE:
		rtnl_lock();
		err = prestera_ct_block_flow_offload_add(ft, f);
		rtnl_unlock();
		break;
	case FLOW_CLS_DESTROY:
		rtnl_lock();
		err = prestera_ct_block_flow_offload_del(ft, f);
		rtnl_unlock();
		break;
	case FLOW_CLS_STATS:
		err = prestera_ct_block_flow_offload_stats(ft, f);
		break;
	default:
		err =  -EOPNOTSUPP;
		break;
	}

	return err;
}

static struct prestera_ct_ft *
__prestera_ct_ft_offload_add_cb(struct prestera_ct_priv *ct_priv,
				u16 zone, struct nf_flowtable *nf_ft)
{
	struct prestera_ct_ft *ft;
	int err;

	ft = rhashtable_lookup_fast(&ct_priv->zone_ht, &zone,
				    ct_zone_ht_params);
	if (ft) {
		refcount_inc(&ft->refcount);
		return ft;
	}

	ft = kzalloc(sizeof(*ft), GFP_KERNEL);
	if (!ft)
		return ERR_PTR(-ENOMEM);

	/* ft->net = read_pnet(&nf_ft->net); */
	ft->zone = zone;
	ft->nf_ft = nf_ft;
	ft->ct_priv = ct_priv;
	refcount_set(&ft->refcount, 1);

	err = rhashtable_init(&ft->ct_entries_ht, &ct_entry_ht_params);
	if (err)
		goto err_init;

	err = rhashtable_insert_fast(&ct_priv->zone_ht, &ft->node,
				     ct_zone_ht_params);
	if (err)
		goto err_insert;

	err = nf_flow_table_offload_add_cb(ft->nf_ft,
					   prestera_ct_block_flow_offload, ft);
	if (err)
		goto err_add_cb;

	return ft;

err_add_cb:
	rhashtable_remove_fast(&ct_priv->zone_ht, &ft->node, ct_zone_ht_params);
err_insert:
	rhashtable_destroy(&ft->ct_entries_ht);
err_init:
	kfree(ft);
	return ERR_PTR(err);
}

/* Add gateway rule in def chain and add TRAP rule in CT chain */
static int __prestera_ct_rule2gateway(struct prestera_switch *sw,
				      struct prestera_acl_rule *rule)
{
	struct prestera_ct_priv *ct_priv = sw->acl->ct_priv;

	/* TODO: fill this in flower parse */

	/* just update the action for this rule */
	rule->re_arg.jump.valid = 1;
	rule->re_arg.jump.i.index = ct_priv->index;

	rule->re = prestera_acl_rule_entry_find(sw->acl, &rule->re_key);
	if (WARN_ON(rule->re)) {
		rule->re = NULL;
		return -EEXIST;
	}

	rule->re = prestera_acl_rule_entry_create(sw->acl, &rule->re_key,
						  &rule->re_arg);
	if (!rule->re)
		return -EINVAL;

	return 0;
}

int prestera_ct_ft_offload_add_cb(struct prestera_switch *sw,
				  struct prestera_acl_rule *rule)
{
	struct prestera_ct_attr *ct_attr;
	int err;

	ct_attr = &rule->attr.ct_attr;

	if (ct_attr->ct_action & TCA_CT_ACT_CLEAR)
		return -EOPNOTSUPP;

	ct_attr->ft = __prestera_ct_ft_offload_add_cb(sw->acl->ct_priv,
						      ct_attr->zone,
						      ct_attr->nf_ft);
	if (IS_ERR(ct_attr->ft))
		return PTR_ERR(ct_attr->ft);

	err = __prestera_ct_rule2gateway(sw, rule);
	if (err) {
		prestera_ct_ft_offload_del_cb(sw, rule);
		return err;
	}

	return 0;
}

static void prestera_ct_flush_ft_entry(void *ptr, void *arg)
{
	struct prestera_ct_priv *ct_priv = arg;
	struct prestera_ct_entry *entry = ptr;

	prestera_acl_rule_entry_destroy(ct_priv->acl, entry->tuple.re);
	kfree(entry);
}

struct prestera_ct_ft_cb_work {
	struct work_struct work;
	struct prestera_switch *sw;
	struct prestera_ct_ft *ft;
};

static void __prestera_ct_ft_cb_work(struct work_struct *work)
{
	struct prestera_ct_ft_cb_work *ct_work;
	struct prestera_switch *sw;
	struct prestera_ct_ft *ft;

	ct_work = container_of(work, struct prestera_ct_ft_cb_work, work);
	sw = ct_work->sw;
	ft = ct_work->ft;

	/* Will take ct_lock inside.
	 * Also ensures, that there is no more events.
	 */
	nf_flow_table_offload_del_cb(ft->nf_ft,
				     prestera_ct_block_flow_offload, ft);

	/* This code can be executed without rtnl_lock,
	 * because nf_flow_table_offload_del_cb already delete all entries ?
	 */
	rtnl_lock();
	rhashtable_free_and_destroy(&ft->ct_entries_ht,
				    prestera_ct_flush_ft_entry,
				    sw->acl->ct_priv);
	rtnl_unlock();
	kfree(ft);

	kfree(ct_work);
}

void prestera_ct_ft_offload_del_cb(struct prestera_switch *sw,
				   struct prestera_acl_rule *rule)
{
	struct prestera_ct_attr *ct_attr;
	struct prestera_ct_ft *ft;
	struct prestera_ct_ft_cb_work *ct_work;

	ct_attr = &rule->attr.ct_attr;
	ft = ct_attr->ft;

	if (rule->re)
		prestera_acl_rule_entry_destroy(sw->acl, rule->re);

	if (!refcount_dec_and_test(&ft->refcount))
		return;

	/* Delete this ft from HT to prevent occurring in search results of
	 * __prestera_ct_ft_offload_add_cb. Prevents reusing after refcnt
	 * became zero.
	 */
	rhashtable_remove_fast(&sw->acl->ct_priv->zone_ht,
			       &ft->node, ct_zone_ht_params);

	ct_work = kzalloc(sizeof(*ct_work), GFP_ATOMIC);
	if (WARN_ON(!ct_work))
		return;

	ct_work->sw = sw;
	ct_work->ft = ft;
	INIT_WORK(&ct_work->work, __prestera_ct_ft_cb_work);
	queue_work(prestera_ct_owq, &ct_work->work);
}
