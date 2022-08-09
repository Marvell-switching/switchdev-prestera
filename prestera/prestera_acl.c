// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include <linux/rhashtable.h>

#include "prestera.h"
#include "prestera_hw.h"
#include "prestera_log.h"
#include "prestera_ct.h"
#include "prestera_acl.h"

#define PRESTERA_ACL_RULE_DEF_HW_TC	3
#define ACL_KEYMASK_SIZE	\
	(sizeof(__be32) * __PRESTERA_ACL_RULE_MATCH_TYPE_MAX)
/* Need to merge it with router_manager */
#define MVSW_PR_NH_ACTIVE_JIFFER_FILTER 3000 /* ms */

struct prestera_acl_ruleset_ht_key {
	struct prestera_flow_block *block;
	u32 chain_index;
};

struct prestera_acl_ruleset {
	struct rhash_head ht_node; /* Member of acl HT */
	struct prestera_acl_ruleset_ht_key ht_key;
	struct rhashtable rule_ht;
	struct prestera_acl *acl;
	unsigned long rule_count;
	refcount_t refcount;
	void *keymask;
	bool offload;
	u32 vtcam_id;
	u16 pcl_id;
	u32 index;
	bool ingress;
};

struct prestera_acl_vtcam {
	struct list_head list;
	__be32 keymask[__PRESTERA_ACL_RULE_MATCH_TYPE_MAX];
	bool is_keymask_set;
	refcount_t refcount;
	u8 direction;
	u8 lookup;
	u32 id;
};

static const struct rhashtable_params prestera_acl_ruleset_ht_params = {
	.key_len = sizeof(struct prestera_acl_ruleset_ht_key),
	.key_offset = offsetof(struct prestera_acl_ruleset, ht_key),
	.head_offset = offsetof(struct prestera_acl_ruleset, ht_node),
	.automatic_shrinking = true,
};

static const struct rhashtable_params prestera_acl_rule_ht_params = {
	.key_len = sizeof(unsigned long),
	.key_offset = offsetof(struct prestera_acl_rule, cookie),
	.head_offset = offsetof(struct prestera_acl_rule, ht_node),
	.automatic_shrinking = true,
};

static const struct rhashtable_params __prestera_nh_mangle_entry_ht_params = {
	.key_offset  = offsetof(struct prestera_nh_mangle_entry, key),
	.head_offset = offsetof(struct prestera_nh_mangle_entry, ht_node),
	.key_len     = sizeof(struct prestera_nh_mangle_entry_key),
	.automatic_shrinking = true,
};

static const struct rhashtable_params __prestera_acl_rule_entry_ht_params = {
	.key_offset  = offsetof(struct prestera_acl_rule_entry, key),
	.head_offset = offsetof(struct prestera_acl_rule_entry, ht_node),
	.key_len     = sizeof(struct prestera_acl_rule_entry_key),
	.automatic_shrinking = true,
};

int prestera_acl_chain_to_client(u32 chain_index, bool ingress, u32 *client)
{
	u32 ingress_client_map[] = {
		PRESTERA_HW_COUNTER_CLIENT_INGRESS_LOOKUP_0,
		PRESTERA_HW_COUNTER_CLIENT_INGRESS_LOOKUP_1,
		PRESTERA_HW_COUNTER_CLIENT_INGRESS_LOOKUP_2
	};

	if (!ingress) {
		/* prestera supports only one chain on egress */
		if (chain_index > 0)
			return -EINVAL;

		*client = PRESTERA_HW_COUNTER_CLIENT_EGRESS_LOOKUP;
		return 0;
	}

	if (chain_index >= ARRAY_SIZE(ingress_client_map))
		return -EINVAL;

	*client = ingress_client_map[chain_index];
	return 0;
}

struct prestera_acl_nat_port *
prestera_acl_nat_port_get(struct prestera_acl *acl, u32 port_hw_id,
			  u32 port_dev_id)
{
	struct prestera_acl_nat_port *nat_port;
	struct list_head *pos, *n;

	list_for_each_safe(pos, n, &acl->nat_port_list) {
		nat_port = list_entry(pos, typeof(*nat_port), list);
		if (nat_port->port->hw_id == port_hw_id &&
		    nat_port->port->dev_id == port_dev_id) {
			refcount_inc(&nat_port->refcount);
			return nat_port;
		}
	}

	return NULL;
}

void prestera_acl_nat_port_put(struct prestera_acl_nat_port *nat_port)
{
	if (!refcount_dec_and_test(&nat_port->refcount))
		return;

	list_del(&nat_port->list);
	kfree(nat_port);
}

struct prestera_port *
prestera_acl_nat_port_to_port(struct prestera_acl_nat_port *nat_port)
{
	return nat_port->port;
}

static struct prestera_acl_nat_port *
prestera_acl_nat_port_create(struct prestera_acl *acl,
			     struct prestera_port *port)
{
	struct prestera_acl_nat_port *nat_port;

	nat_port = kzalloc(sizeof(*nat_port), GFP_KERNEL);
	if (!nat_port)
		return ERR_PTR(-ENOMEM);

	nat_port->port = port;
	refcount_set(&nat_port->refcount, 1);
	list_add(&nat_port->list, &acl->nat_port_list);

	return nat_port;
}

static bool prestera_acl_chain_is_supported(u32 chain_index, bool ingress)
{
	if (!ingress)
		/* prestera supports only one chain on egress */
		return chain_index == 0;

	return (chain_index & ~PRESTERA_ACL_CHAIN_MASK) == 0;
}

static struct prestera_acl_ruleset *
prestera_acl_ruleset_create(struct prestera_acl *acl,
			    struct prestera_flow_block *block,
			    u32 chain_index)
{
	struct prestera_acl_ruleset *ruleset;
	u32 uid = 0;
	int err;

	if (!prestera_acl_chain_is_supported(chain_index, block->ingress))
		return ERR_PTR(-EINVAL);

	ruleset = kzalloc(sizeof(*ruleset), GFP_KERNEL);
	if (!ruleset)
		return ERR_PTR(-ENOMEM);

	ruleset->acl = acl;
	ruleset->ingress = block->ingress;
	ruleset->ht_key.block = block;
	ruleset->ht_key.chain_index = chain_index;
	refcount_set(&ruleset->refcount, 1);

	err = rhashtable_init(&ruleset->rule_ht, &prestera_acl_rule_ht_params);
	if (err)
		goto err_rhashtable_init;

	err = idr_alloc_u32(&acl->uid, NULL, &uid, U8_MAX, GFP_KERNEL);
	if (err)
		goto err_ruleset_create;

	/* make pcl-id based on uid and chain */
	ruleset->pcl_id = PRESTERA_ACL_PCL_ID_MAKE((u8)uid, chain_index);
	ruleset->index = uid;

	err = rhashtable_insert_fast(&acl->ruleset_ht, &ruleset->ht_node,
				     prestera_acl_ruleset_ht_params);
	if (err)
		goto err_ruleset_ht_insert;

	return ruleset;

err_ruleset_ht_insert:
	idr_remove(&acl->uid, uid);
err_ruleset_create:
	rhashtable_destroy(&ruleset->rule_ht);
err_rhashtable_init:
	kfree(ruleset);
	return ERR_PTR(err);
}

void prestera_acl_ruleset_keymask_set(struct prestera_acl_ruleset *ruleset,
				      void *keymask)
{
	ruleset->keymask = kmemdup(keymask, ACL_KEYMASK_SIZE, GFP_KERNEL);
}

int prestera_acl_ruleset_offload(struct prestera_acl_ruleset *ruleset)
{
	struct prestera_acl_iface iface;
	u32 vtcam_id;
	int dir;
	int err;

	dir = ruleset->ingress ?
		PRESTERA_HW_VTCAM_DIR_INGRESS : PRESTERA_HW_VTCAM_DIR_EGRESS;

	if (ruleset->offload)
		return -EEXIST;

	err = prestera_acl_vtcam_id_get(ruleset->acl,
					ruleset->ht_key.chain_index,
					dir,
					ruleset->keymask, &vtcam_id);
	if (err)
		goto err_vtcam_create;

	if (ruleset->ht_key.chain_index) {
		/* for chain > 0, bind iface index to pcl-id to be able
		 * to jump from any other ruleset to this one using the index.
		 */
		iface.index = ruleset->index;
		iface.type = PRESTERA_ACL_IFACE_TYPE_INDEX;
		err = prestera_hw_vtcam_iface_bind(ruleset->acl->sw, &iface,
						   vtcam_id, ruleset->pcl_id);
		if (err)
			goto err_ruleset_bind;
	}

	ruleset->vtcam_id = vtcam_id;
	ruleset->offload = true;
	return 0;

err_ruleset_bind:
	prestera_acl_vtcam_id_put(ruleset->acl, ruleset->vtcam_id);
err_vtcam_create:
	return err;
}

static void prestera_acl_ruleset_destroy(struct prestera_acl_ruleset *ruleset)
{
	struct prestera_acl *acl = ruleset->acl;
	u8 uid = ruleset->pcl_id & PRESTERA_ACL_KEYMASK_PCL_ID_USER;
	int err;

	rhashtable_remove_fast(&acl->ruleset_ht, &ruleset->ht_node,
			       prestera_acl_ruleset_ht_params);

	if (ruleset->offload) {
		if (ruleset->ht_key.chain_index) {
			struct prestera_acl_iface iface = {
				.type = PRESTERA_ACL_IFACE_TYPE_INDEX,
				.index = ruleset->index
			};
			err = prestera_hw_vtcam_iface_unbind(acl->sw, &iface,
							     ruleset->vtcam_id);
			WARN_ON(err);
		}
		WARN_ON(prestera_acl_vtcam_id_put(acl, ruleset->vtcam_id));
	}

	idr_remove(&acl->uid, uid);
	rhashtable_destroy(&ruleset->rule_ht);
	kfree(ruleset->keymask);
	kfree(ruleset);
}

static struct prestera_acl_ruleset *
__prestera_acl_ruleset_lookup(struct prestera_acl *acl,
			      struct prestera_flow_block *block,
			      u32 chain_index)
{
	struct prestera_acl_ruleset_ht_key ht_key;

	memset(&ht_key, 0, sizeof(ht_key));
	ht_key.block = block;
	ht_key.chain_index = chain_index;
	return rhashtable_lookup_fast(&acl->ruleset_ht, &ht_key,
				      prestera_acl_ruleset_ht_params);
}

struct prestera_acl_ruleset *
prestera_acl_ruleset_lookup(struct prestera_acl *acl,
			    struct prestera_flow_block *block,
			    u32 chain_index)
{
	struct prestera_acl_ruleset *ruleset;

	ruleset = __prestera_acl_ruleset_lookup(acl, block, chain_index);
	if (!ruleset)
		return ERR_PTR(-ENOENT);

	refcount_inc(&ruleset->refcount);
	return ruleset;
}

struct prestera_acl_ruleset *
prestera_acl_ruleset_get(struct prestera_acl *acl,
			 struct prestera_flow_block *block,
			 u32 chain_index)
{
	struct prestera_acl_ruleset *ruleset;

	ruleset = __prestera_acl_ruleset_lookup(acl, block, chain_index);
	if (ruleset) {
		refcount_inc(&ruleset->refcount);
		return ruleset;
	}

	return prestera_acl_ruleset_create(acl, block, chain_index);
}

void prestera_acl_ruleset_put(struct prestera_acl_ruleset *ruleset)
{
	if (!refcount_dec_and_test(&ruleset->refcount))
		return;

	prestera_acl_ruleset_destroy(ruleset);
}

int prestera_acl_ruleset_bind(struct prestera_acl_ruleset *ruleset,
			      struct prestera_port *port)
{
	struct prestera_acl_iface iface = {
		.type = PRESTERA_ACL_IFACE_TYPE_PORT,
		.port = port
	};

	return prestera_hw_vtcam_iface_bind(port->sw, &iface, ruleset->vtcam_id,
					    ruleset->pcl_id);
}

int prestera_acl_ruleset_unbind(struct prestera_acl_ruleset *ruleset,
				struct prestera_port *port)
{
	struct prestera_acl_iface iface = {
		.type = PRESTERA_ACL_IFACE_TYPE_PORT,
		.port = port
	};

	return prestera_hw_vtcam_iface_unbind(port->sw, &iface,
					      ruleset->vtcam_id);
}

static int prestera_acl_ruleset_block_bind(struct prestera_acl_ruleset *ruleset,
					   struct prestera_flow_block *block)
{
	struct prestera_flow_block_binding *binding;
	int err;

	block->ruleset_zero = ruleset;
	list_for_each_entry(binding, &block->binding_list, list) {
		err = prestera_acl_ruleset_bind(ruleset, binding->port);
		if (err)
			goto rollback;
	}
	return 0;

rollback:
	list_for_each_entry_continue_reverse(binding, &block->binding_list,
					     list)
		err = prestera_acl_ruleset_unbind(ruleset, binding->port);
	block->ruleset_zero = NULL;

	return err;
}

static void
prestera_acl_ruleset_block_unbind(struct prestera_acl_ruleset *ruleset,
				  struct prestera_flow_block *block)
{
	struct prestera_flow_block_binding *binding;

	list_for_each_entry(binding, &block->binding_list, list)
		prestera_acl_ruleset_unbind(ruleset, binding->port);
	block->ruleset_zero = NULL;
}

void prestera_acl_block_prio_update(struct prestera_switch *sw,
				    struct prestera_flow_block *block)
{
	struct prestera_acl *acl = sw->acl;
	struct prestera_acl_rule *rule;
	u32 new_prio = UINT_MAX;

	list_for_each_entry(rule, &acl->rules, list) {
		if (rule->priority < new_prio)
			new_prio = rule->priority;
	}

	block->flower_min_prio = new_prio;
}

unsigned int prestera_acl_block_rule_count(struct prestera_flow_block *block)
{
	return block ? block->rule_count : 0;
}

void
prestera_acl_rule_keymask_pcl_id_set(struct prestera_acl_rule *rule, u16 pcl_id)
{
	struct prestera_acl_match *r_match = &rule->re_key.match;
	__be16 pcl_id_mask = htons(PRESTERA_ACL_KEYMASK_PCL_ID);
	__be16 pcl_id_key = htons(pcl_id);

	rule_match_set(r_match->key, PCL_ID, pcl_id_key);
	rule_match_set(r_match->mask, PCL_ID, pcl_id_mask);
}

struct net *prestera_acl_block_net(struct prestera_flow_block *block)
{
	return block->net;
}

struct prestera_switch *prestera_acl_block_sw(struct prestera_flow_block *block)
{
	return block->sw;
}

struct prestera_acl_rule *
prestera_acl_rule_lookup(struct prestera_acl_ruleset *ruleset,
			 unsigned long cookie)
{
	return rhashtable_lookup_fast(&ruleset->rule_ht, &cookie,
				      prestera_acl_rule_ht_params);
}

u32 prestera_acl_ruleset_index_get(const struct prestera_acl_ruleset *ruleset)
{
	return ruleset->index;
}

bool prestera_acl_ruleset_is_offload(struct prestera_acl_ruleset *ruleset)
{
	return ruleset->offload;
}

struct prestera_acl_rule *
prestera_acl_rule_create(struct prestera_acl_ruleset *ruleset,
			 unsigned long cookie, u32 chain_index)
{
	struct prestera_acl_rule *rule;

	rule = kzalloc(sizeof(*rule), GFP_KERNEL);
	if (!rule)
		return ERR_PTR(-ENOMEM);

	rule->ruleset = ruleset;
	rule->cookie = cookie;
	rule->chain_index = chain_index;
	rule->hw_tc = PRESTERA_ACL_RULE_DEF_HW_TC;

	refcount_inc(&ruleset->refcount);

	return rule;
}

void prestera_acl_rule_flag_set(struct prestera_acl_rule *rule,
				unsigned long flag)
{
	set_bit(flag, &rule->attr.flags);
}

bool
prestera_acl_rule_flag_test(const struct prestera_acl_rule *rule,
			    unsigned long flag)
{
	return test_bit(flag, &rule->attr.flags);
}

void prestera_acl_rule_priority_set(struct prestera_acl_rule *rule,
				    u32 priority)
{
	rule->priority = priority;
}

u8 prestera_acl_rule_hw_tc_get(struct prestera_acl_rule *rule)
{
	return rule->hw_tc;
}

void prestera_acl_rule_hw_tc_set(struct prestera_acl_rule *rule, u8 hw_tc)
{
	rule->hw_tc = hw_tc;
}

static int prestera_acl_nat_port_neigh_lookup(struct prestera_port *port,
					      struct prestera_neigh_info *ni)
{
	struct prestera_kern_neigh_cache *n_cache;
	struct prestera_neigh_info *n_info;
	struct rhashtable_iter iter;
	int err = -ENOENT;

	rhashtable_walk_enter(&port->sw->router->kern_neigh_cache_ht, &iter);
	rhashtable_walk_start(&iter);
	while ((n_cache = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(n_cache))
			continue;
		n_info = prestera_kern_neigh_cache_to_neigh_info(n_cache);
		if (n_info->iface.type == PRESTERA_IF_PORT_E &&
		    n_info->iface.dev_port.port_num == port->hw_id &&
		    n_info->iface.dev_port.hw_dev_num == port->dev_id) {
			memcpy(ni, n_info, sizeof(*n_info));
			err = 0;
			break;
		}
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
	return err;
}

void prestera_acl_rule_destroy(struct prestera_acl_rule *rule)
{
	if (rule->nat_port)
		prestera_acl_nat_port_put(rule->nat_port);

	if (rule->jump_ruleset)
		/* release ruleset kept by jump action */
		prestera_acl_ruleset_put(rule->jump_ruleset);

	prestera_acl_ruleset_put(rule->ruleset);
	kfree(rule);
}

int prestera_acl_rule_add(struct prestera_switch *sw,
			  struct prestera_acl_rule *rule)
{
	int err;
	struct prestera_acl_ruleset *ruleset = rule->ruleset;
	struct prestera_flow_block *block = ruleset->ht_key.block;
	struct prestera_flow_block_binding *binding;
	struct prestera_acl_nat_port *nat_port;
	struct prestera_neigh_info n_info;

	err = rule_flag_test(rule, CT) && rule_flag_test(rule, GOTO) ?
	      -ENOTSUPP : 0;
	if (err)
		goto err_sanity;

	/* try to add rule to hash table first */
	err = rhashtable_insert_fast(&ruleset->rule_ht, &rule->ht_node,
				     prestera_acl_rule_ht_params);
	if (err)
		goto err_ht_insert;

	prestera_acl_rule_keymask_pcl_id_set(rule, ruleset->pcl_id);
	rule->re_arg.vtcam_id = ruleset->vtcam_id;
	rule->re_key.prio = rule->priority;

	if (rule_flag_test(rule, CT)) {
		err = prestera_ct_ft_offload_add_cb(sw, rule);
		if (err)
			goto err_rule_add;

		goto hw_handled;
	}

	rule->re = prestera_acl_rule_entry_find(sw->acl, &rule->re_key);
	err = WARN_ON(rule->re) ? -EEXIST : 0;
	if (err)
		goto err_rule_add;

	rule->re = prestera_acl_rule_entry_create(sw->acl, &rule->re_key,
						  &rule->re_arg);
	err = !rule->re ? -EINVAL : 0;
	if (err)
		goto err_rule_add;

	if (!rule_flag_test(rule, NAT))
		goto nat_port_neigh_not_found;

	/* TODO: assign port to NAT here instead of doing this in
	 * flower action.
	 *
	 * Get first interface bound to the block same as
	 * in NAT action for now
	 */
	binding = list_first_entry(&block->binding_list,
				   struct prestera_flow_block_binding, list);
	nat_port = prestera_acl_nat_port_get(sw->acl, binding->port->hw_id,
					     binding->port->dev_id);
	if (!nat_port) {
		nat_port = prestera_acl_nat_port_create(sw->acl, binding->port);
		MVSW_LOG_INFO("NAT port created");
		err = !nat_port ? -EINVAL : 0;
		if (err)
			goto err_rule_add_nat;
	}
	rule->nat_port = nat_port;

	/* try to lookup neigh for this port and update HW */
	err = prestera_acl_nat_port_neigh_lookup(nat_port->port, &n_info);
	if (err == -ENOENT) {
		MVSW_LOG_INFO("Neighbour for NAT port not found");
		goto nat_port_neigh_not_found;
	}
	if (err)
		goto err_rule_add_nat;

	MVSW_LOG_INFO("Found a neighbour for NAT port");
	err = prestera_hw_nat_port_neigh_update(nat_port->port, n_info.ha);
	if (err)
		goto err_rule_add_nat;

hw_handled:
nat_port_neigh_not_found:
	/* bind the block (all ports) to chain index 0, rest of
	 * the chains are bound to goto action
	 */
	if (!ruleset->ht_key.chain_index && !ruleset->rule_count) {
		err = prestera_acl_ruleset_block_bind(ruleset, block);
		if (err)
			goto err_acl_block_bind;
	}

	list_add_tail(&rule->list, &sw->acl->rules);
	ruleset->ht_key.block->rule_count++;
	ruleset->rule_count++;
	return 0;

err_acl_block_bind:
err_rule_add_nat:
	prestera_acl_rule_entry_destroy(sw->acl, rule->re);
err_rule_add:
	rule->re = NULL;
	rhashtable_remove_fast(&ruleset->rule_ht, &rule->ht_node,
			       prestera_acl_rule_ht_params);
err_ht_insert:
err_sanity:
	return err;
}

void prestera_acl_rule_del(struct prestera_switch *sw,
			   struct prestera_acl_rule *rule)
{
	struct prestera_acl_ruleset *ruleset = rule->ruleset;
	struct prestera_flow_block *block = ruleset->ht_key.block;

	rhashtable_remove_fast(&ruleset->rule_ht, &rule->ht_node,
			       prestera_acl_rule_ht_params);
	block->rule_count--;
	ruleset->rule_count--;
	list_del(&rule->list);

	if (rule_flag_test(rule, CT)) {
		prestera_ct_ft_offload_del_cb(sw, rule);
	} else {
		prestera_acl_rule_entry_destroy(sw->acl, rule->re);
		prestera_acl_block_prio_update(sw, block);
	}

	/* unbind block (all ports) */
	if (!ruleset->ht_key.chain_index && !ruleset->rule_count)
		prestera_acl_ruleset_block_unbind(ruleset, block);
}

int prestera_acl_rule_get_stats(struct prestera_acl *acl,
				struct prestera_acl_rule *rule,
				u64 *packets, u64 *bytes, u64 *last_use)
{
	u64 current_packets;
	u64 current_bytes;
	int err;

	err = prestera_counter_stats_get(acl->sw->counter,
					 rule->re->counter.block,
					 rule->re->counter.id,
					 &current_packets, &current_bytes);
	if (err)
		return err;

	*packets = current_packets;
	*bytes = current_bytes;
	*last_use = jiffies;

	return 0;
}

/* HW objects infrastructure */
static struct prestera_nh_mangle_entry *
__prestera_nh_mangle_entry_find(struct prestera_switch *sw,
				struct prestera_nh_mangle_entry_key *key)
{
	struct prestera_nh_mangle_entry *e;

	e = rhashtable_lookup_fast(&sw->acl->nh_mangle_entry_ht, key,
				   __prestera_nh_mangle_entry_ht_params);
	return IS_ERR(e) ? NULL : e;
}

static void
__prestera_nh_mangle_entry_destroy(struct prestera_switch *sw,
				   struct prestera_nh_mangle_entry *e)
{
	rhashtable_remove_fast(&sw->acl->nh_mangle_entry_ht, &e->ht_node,
			       __prestera_nh_mangle_entry_ht_params);
	list_del(&e->nh_neigh_head);
	prestera_nh_neigh_put(sw, e->n);
	WARN_ON(prestera_hw_nh_mangle_del(sw, e->hw_id));
	kfree(e);
}

int prestera_nh_mangle_entry_set(struct prestera_switch *sw,
				 struct prestera_nh_mangle_entry *e)
{
	return prestera_hw_nh_mangle_set(sw, e->hw_id,
					 e->key.mangle.l4_src_valid,
					 e->key.mangle.l4_src,
					 e->key.mangle.l4_dst_valid,
					 e->key.mangle.l4_dst,
					 e->key.mangle.sip_valid,
					 e->key.mangle.sip,
					 e->key.mangle.dip_valid,
					 e->key.mangle.dip,
					 e->n->info);
}

static struct prestera_nh_mangle_entry *
__prestera_nh_mangle_entry_create(struct prestera_switch *sw,
				  struct prestera_nh_mangle_entry_key *key)
{
	struct prestera_nh_mangle_entry *e;
	int err;

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		goto err_kzalloc;

	memcpy(&e->key, key, sizeof(*key));
	e->n = prestera_nh_neigh_get(sw, &e->key.n);
	if (!e->n)
		goto err_nh_get;

	list_add(&e->nh_neigh_head, &e->n->nh_mangle_entry_list);

	err = prestera_hw_nh_mangle_add(sw, &e->hw_id);
	if (err)
		goto err_hw_add;

	err = prestera_nh_mangle_entry_set(sw, e);
	if (err)
		goto err_set;

	err = rhashtable_insert_fast(&sw->acl->nh_mangle_entry_ht, &e->ht_node,
				     __prestera_nh_mangle_entry_ht_params);
	if (err)
		goto err_ht_insert;

	return e;

err_ht_insert:
err_set:
	WARN_ON(prestera_hw_nh_mangle_del(sw, e->hw_id));
err_hw_add:
	list_del(&e->nh_neigh_head);
	prestera_nh_neigh_put(sw, e->n);
err_nh_get:
	kfree(e);
err_kzalloc:
	return NULL;
}

static void prestera_nh_mangle_entry_put(struct prestera_switch *sw,
					 struct prestera_nh_mangle_entry *e)
{
	if (!e->ref_cnt)
		__prestera_nh_mangle_entry_destroy(sw, e);
}

static struct prestera_nh_mangle_entry *
prestera_nh_mangle_entry_get(struct prestera_switch *sw,
			     struct prestera_nh_mangle_entry_key *key)
{
	struct prestera_nh_mangle_entry *e;

	e = __prestera_nh_mangle_entry_find(sw, key);
	if (!e)
		e = __prestera_nh_mangle_entry_create(sw, key);

	return e;
}

bool prestera_nh_mangle_entry_util_hw_state(struct prestera_switch *sw,
					    struct prestera_nh_mangle_entry *e)
{
	int err;

	/* Antijitter
	 * Prevent situation, when we read state of nh_grp twice in short time,
	 * and state bit is still cleared on second call. So just stuck active
	 * state for MVSW_PR_NH_ACTIVE_JIFFER_FILTER, after last occurred.
	 */
	if (!time_before(jiffies, e->is_active_hw_cache_kick +
			msecs_to_jiffies(MVSW_PR_NH_ACTIVE_JIFFER_FILTER))) {
		err = prestera_hw_nh_mangle_get(sw, e->hw_id,
						&e->is_active_hw_cache);
		if (err) {
			MVSW_LOG_ERROR("Failed to get nh_mangle %pI4n hw_state",
				       &e->key.n.addr.u.ipv4);
			return false;
		}

		e->is_active_hw_cache_kick = jiffies;
	}

	return e->is_active_hw_cache;
}

struct prestera_acl_rule_entry *
prestera_acl_rule_entry_find(struct prestera_acl *acl,
			     struct prestera_acl_rule_entry_key *key)
{
	return rhashtable_lookup_fast(&acl->acl_rule_entry_ht, key,
				      __prestera_acl_rule_entry_ht_params);
}

static int __prestera_acl_rule_entry2hw_del(struct prestera_switch *sw,
					    struct prestera_acl_rule_entry *e)
{
	return prestera_hw_vtcam_rule_del(sw, e->vtcam_id, e->hw_id);
}

static int __prestera_acl_rule_entry2hw_add(struct prestera_switch *sw,
					    struct prestera_acl_rule_entry *e)
{
	struct prestera_acl_hw_action_info act_hw[PRESTERA_ACL_ACTION_MAX];
	int act_num;

	memset(&act_hw, 0, sizeof(act_hw));
	act_num = 0;

	/* accept */
	if (e->accept.valid) {
		act_hw[act_num].id = PRESTERA_ACL_RULE_ACTION_ACCEPT;
		act_num++;
	}
	/* drop */
	if (e->drop.valid) {
		act_hw[act_num].id = PRESTERA_ACL_RULE_ACTION_DROP;
		act_num++;
	}
	/* trap */
	if (e->trap.valid) {
		act_hw[act_num].id = PRESTERA_ACL_RULE_ACTION_TRAP;
		act_hw[act_num].trap = e->trap.i;
		act_num++;
	}
	/* police */
	if (e->police.valid) {
		act_hw[act_num].id = PRESTERA_ACL_RULE_ACTION_POLICE;
		act_hw[act_num].police = e->police.i;
		act_num++;
	}
	/* nat */
	if (e->nat.valid) {
		act_hw[act_num].id = PRESTERA_ACL_RULE_ACTION_NAT;
		act_hw[act_num].nat = e->nat.i;
		act_num++;
	}
	/* jump */
	if (e->jump.valid) {
		act_hw[act_num].id = PRESTERA_ACL_RULE_ACTION_JUMP;
		act_hw[act_num].jump = e->jump.i;
		act_num++;
	}
	/* nh */
	if (e->nh.valid) {
		act_hw[act_num].id = PRESTERA_ACL_RULE_ACTION_NH;
		act_hw[act_num].nh = e->nh.e->hw_id;
		act_num++;
	}
	/* counter */
	if (e->counter.block) {
		act_hw[act_num].id = PRESTERA_ACL_RULE_ACTION_COUNT;
		act_hw[act_num].count.id = e->counter.id;
		act_num++;
	}
	/* egress remark */
	if (e->remark.valid) {
		act_hw[act_num].id = PRESTERA_ACL_RULE_ACTION_REMARK;
		act_hw[act_num].remark = e->remark.i;
		act_num++;
	}

	return prestera_hw_vtcam_rule_add(sw, e->vtcam_id, e->key.prio,
					  e->key.match.key, e->key.match.mask,
					  act_hw, act_num, &e->hw_id);
}

static void
__prestera_acl_rule_entry_act_destruct(struct prestera_switch *sw,
				       struct prestera_acl_rule_entry *e)
{
	/* nh */
	if (e->nh.valid) {
		e->nh.e->ref_cnt--;
		prestera_nh_mangle_entry_put(sw, e->nh.e);
	}
	/* counter */
	prestera_counter_put(sw->counter, e->counter.block, e->counter.id);
}

void prestera_acl_rule_entry_destroy(struct prestera_acl *acl,
				     struct prestera_acl_rule_entry *e)
{
	int ret;

	rhashtable_remove_fast(&acl->acl_rule_entry_ht, &e->ht_node,
			       __prestera_acl_rule_entry_ht_params);

	ret = __prestera_acl_rule_entry2hw_del(acl->sw, e);
	WARN_ON(ret && ret != -ENODEV);

	__prestera_acl_rule_entry_act_destruct(acl->sw, e);
	kfree(e);
}

static int
__prestera_acl_rule_entry_act_construct(struct prestera_switch *sw,
					struct prestera_acl_rule_entry *e,
					struct prestera_acl_rule_entry_arg *arg)
{
	/* accept */
	e->accept.valid = arg->accept.valid;
	/* drop */
	e->drop.valid = arg->drop.valid;
	/* trap */
	e->trap.valid = arg->trap.valid;
	e->trap.i = arg->trap.i;
	/* police */
	e->police.valid = arg->police.valid;
	e->police.i = arg->police.i;
	/* nat */
	e->nat.valid = arg->nat.valid;
	e->nat.i = arg->nat.i;
	/* jump */
	e->jump.valid = arg->jump.valid;
	e->jump.i = arg->jump.i;
	/* nh */
	if (arg->nh.valid) {
		e->nh.e = prestera_nh_mangle_entry_get(sw, &arg->nh.k);
		if (!e->nh.e)
			goto err_out;

		e->nh.e->ref_cnt++;
		e->nh.valid = 1;
	}
	/* counter */
	if (arg->count.valid) {
		int err;

		err = prestera_counter_get(sw->counter, arg->count.client,
					   &e->counter.block,
					   &e->counter.id);
		if (err)
			goto err_out;
	}
	/* remark */
	e->remark.valid = arg->remark.valid;
	e->remark.i = arg->remark.i;

	return 0;

err_out:
	__prestera_acl_rule_entry_act_destruct(sw, e);
	return -EINVAL;
}

/* TODO: move acl_rule entry and lowest objects to
 * appropriate files (hw_nh.c, hw_match.c)
 */
struct prestera_acl_rule_entry *
prestera_acl_rule_entry_create(struct prestera_acl *acl,
			       struct prestera_acl_rule_entry_key *key,
			       struct prestera_acl_rule_entry_arg *arg)
{
	struct prestera_acl_rule_entry *e;
	int err;

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		goto err_kzalloc;

	memcpy(&e->key, key, sizeof(*key));
	e->vtcam_id = arg->vtcam_id;
	err = __prestera_acl_rule_entry_act_construct(acl->sw, e, arg);
	if (err)
		goto err_act_construct;

	err = __prestera_acl_rule_entry2hw_add(acl->sw, e);
	if (err)
		goto err_hw_add;

	err = rhashtable_insert_fast(&acl->acl_rule_entry_ht, &e->ht_node,
				     __prestera_acl_rule_entry_ht_params);
	if (err)
		goto err_ht_insert;

	return e;

err_ht_insert:
	WARN_ON(__prestera_acl_rule_entry2hw_del(acl->sw, e));
err_hw_add:
	__prestera_acl_rule_entry_act_destruct(acl->sw, e);
err_act_construct:
	kfree(e);
err_kzalloc:
	return NULL;
}

static int __prestera_acl_vtcam_id_try_fit(struct prestera_acl *acl, u8 lookup,
					   void *keymask, u32 *vtcam_id)
{
	struct prestera_acl_vtcam *vtcam;
	int i;

	list_for_each_entry(vtcam, &acl->vtcam_list, list) {
		if (lookup != vtcam->lookup)
			continue;

		if (!keymask && !vtcam->is_keymask_set)
			goto vtcam_found;

		if (!(keymask && vtcam->is_keymask_set))
			continue;

		/* try to fit with vtcam keymask */
		for (i = 0; i < __PRESTERA_ACL_RULE_MATCH_TYPE_MAX; i++) {
			__be32 __keymask = ((__be32 *)keymask)[i];

			if (!__keymask)
				/* vtcam keymask in not interested */
				continue;

			if (__keymask & ~vtcam->keymask[i])
				/* keymask does not fit the vtcam keymask */
				break;
		}

		if (i == __PRESTERA_ACL_RULE_MATCH_TYPE_MAX)
			/* keymask fits vtcam keymask, return it */
			goto vtcam_found;
	}

	/* nothing is found */
	return -ENOENT;

vtcam_found:
	refcount_inc(&vtcam->refcount);
	*vtcam_id = vtcam->id;
	return 0;
}

int prestera_acl_vtcam_id_get(struct prestera_acl *acl, u8 lookup, u8 dir,
			      void *keymask, u32 *vtcam_id)
{
	struct prestera_acl_vtcam *vtcam;
	u32 new_vtcam_id;
	int err;

	/* find the vtcam that suits keymask. We do not expect to have
	 * a big number of vtcams, so, the list type for vtcam list is
	 * fine for now
	 */
	list_for_each_entry(vtcam, &acl->vtcam_list, list) {
		if (lookup != vtcam->lookup ||
		    dir != vtcam->direction)
			continue;

		if (!keymask && !vtcam->is_keymask_set) {
			refcount_inc(&vtcam->refcount);
			goto vtcam_found;
		}

		if (keymask && vtcam->is_keymask_set &&
		    !memcmp(keymask, vtcam->keymask, sizeof(vtcam->keymask))) {
			refcount_inc(&vtcam->refcount);
			goto vtcam_found;
		}
	}

	/* vtcam not found, try to create new one */
	vtcam = kzalloc(sizeof(*vtcam), GFP_KERNEL);
	if (!vtcam)
		return -ENOMEM;

	err = prestera_hw_vtcam_create(acl->sw, lookup, keymask, &new_vtcam_id,
				       dir);
	if (err) {
		kfree(vtcam);

		/* cannot create new, try to fit into existing vtcam */
		if (__prestera_acl_vtcam_id_try_fit(acl, lookup,
						    keymask, &new_vtcam_id))
			return err;

		*vtcam_id = new_vtcam_id;
		return 0;
	}

	vtcam->direction = dir;
	vtcam->id = new_vtcam_id;
	vtcam->lookup = lookup;
	if (keymask) {
		memcpy(vtcam->keymask, keymask, sizeof(vtcam->keymask));
		vtcam->is_keymask_set = true;
	}
	refcount_set(&vtcam->refcount, 1);
	list_add_rcu(&vtcam->list, &acl->vtcam_list);

vtcam_found:
	*vtcam_id = vtcam->id;
	return 0;
}

int prestera_acl_vtcam_id_put(struct prestera_acl *acl, u32 vtcam_id)
{
	struct prestera_acl_vtcam *vtcam;
	int err;

	list_for_each_entry(vtcam, &acl->vtcam_list, list) {
		if (vtcam_id != vtcam->id)
			continue;

		if (!refcount_dec_and_test(&vtcam->refcount))
			return 0;

		err = prestera_hw_vtcam_destroy(acl->sw, vtcam->id);
		if (err && err != -ENODEV) {
			refcount_set(&vtcam->refcount, 1);
			return err;
		}

		list_del(&vtcam->list);
		kfree(vtcam);
		return 0;
	}

	return -ENOENT;
}

int prestera_acl_init(struct prestera_switch *sw)
{
	struct prestera_acl *acl;
	int err;

	acl = kzalloc(sizeof(*acl), GFP_KERNEL);
	if (!acl)
		return -ENOMEM;

	acl->sw = sw;
	INIT_LIST_HEAD(&acl->rules);
	INIT_LIST_HEAD(&acl->nat_port_list);
	INIT_LIST_HEAD(&acl->vtcam_list);
	idr_init(&acl->uid);

	err = rhashtable_init(&acl->acl_rule_entry_ht,
			      &__prestera_acl_rule_entry_ht_params);
	if (err)
		goto err_acl_rule_entry_ht_init;

	err = rhashtable_init(&acl->nh_mangle_entry_ht,
			      &__prestera_nh_mangle_entry_ht_params);
	if (err)
		goto err_nh_mangle_entry_ht_init;

	err = rhashtable_init(&acl->ruleset_ht,
			      &prestera_acl_ruleset_ht_params);
	if (err)
		goto err_ruleset_ht_init;

	acl->ct_priv = prestera_ct_init(acl);
	if (IS_ERR(acl->ct_priv)) {
		err = PTR_ERR(acl->ct_priv);
		goto err_ct_init;
	}

	sw->acl = acl;

	return 0;

err_ct_init:
	rhashtable_destroy(&acl->ruleset_ht);
err_ruleset_ht_init:
	rhashtable_destroy(&acl->nh_mangle_entry_ht);
err_nh_mangle_entry_ht_init:
	rhashtable_destroy(&acl->acl_rule_entry_ht);
err_acl_rule_entry_ht_init:
	kfree(acl);
	return err;
}

void prestera_acl_fini(struct prestera_switch *sw)
{
	struct prestera_acl *acl = sw->acl;

	prestera_ct_clean(acl->ct_priv);

	WARN_ON(!idr_is_empty(&acl->uid));
	idr_destroy(&acl->uid);

	WARN_ON(!list_empty(&acl->vtcam_list));
	WARN_ON(!list_empty(&acl->nat_port_list));
	WARN_ON(!list_empty(&acl->rules));

	rhashtable_destroy(&acl->ruleset_ht);
	rhashtable_destroy(&acl->nh_mangle_entry_ht);
	rhashtable_destroy(&acl->acl_rule_entry_ht);

	kfree(acl);
}
