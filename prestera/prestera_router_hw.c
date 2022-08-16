// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include <linux/rhashtable.h>

#include "prestera.h"
#include "prestera_log.h"
#include "prestera_hw.h"
#include "prestera_router_hw.h"
#include "prestera_acl.h"

/*
 *                                Nexthop is pointed
 *                                to port (not rif)
 *                                +-------+
 *                              +>|nexthop|<--+
 *                              | +-------+   |
 *                              |             |
 *            +--+        +-----++         +--+------+
 *   +------->|vr|<-+   +>|nh_grp|         |nh_mangle|<-+
 *   |        +--+  |   | +------+         +---------+  |
 *   |              |   |                               |
 * +-+-------+   +--+---+-+                   +---------+----+
 * |rif_entry|   |fib_node|                   |acl_rule_entry|
 * +---------+   +--------+                   +--------------+
 *  Rif is        Fib - is exit point
 *  used as
 *  entry point
 *  for vr in hw
 */

#define PRESTERA_NHGR_UNUSED (0)
#define PRESTERA_NHGR_DROP (0xFFFFFFFF)
/* Need to merge it with router_manager */
#define PRESTERA_NH_ACTIVE_JIFFER_FILTER 3000 /* ms */

static const struct rhashtable_params __prestera_fib_ht_params = {
	.key_offset  = offsetof(struct prestera_fib_node, key),
	.head_offset = offsetof(struct prestera_fib_node, ht_node),
	.key_len     = sizeof(struct prestera_fib_key),
	.automatic_shrinking = true,
};

static const struct rhashtable_params __prestera_nh_neigh_ht_params = {
	.key_offset  = offsetof(struct prestera_nh_neigh, key),
	.key_len     = sizeof(struct prestera_nh_neigh_key),
	.head_offset = offsetof(struct prestera_nh_neigh, ht_node),
};

static const struct rhashtable_params __prestera_nexthop_group_ht_params = {
	.key_offset  = offsetof(struct prestera_nexthop_group, key),
	.key_len     = sizeof(struct prestera_nexthop_group_key),
	.head_offset = offsetof(struct prestera_nexthop_group, ht_node),
};

static int prestera_nexthop_group_set(struct prestera_switch *sw,
				      struct prestera_nexthop_group *nh_grp);
static bool
prestera_nexthop_group_util_hw_state(struct prestera_switch *sw,
				     struct prestera_nexthop_group *nh_grp);

/* TODO: move to router.h as macros */
static bool prestera_nh_neigh_key_is_valid(struct prestera_nh_neigh_key *key)
{
	return memchr_inv(key, 0, sizeof(*key)) ? true : false;
}

int prestera_router_hw_init(struct prestera_switch *sw)
{
	int err;

	err = rhashtable_init(&sw->router->nh_neigh_ht,
			      &__prestera_nh_neigh_ht_params);
	if (err)
		goto err_nh_neigh_ht_init;

	err = rhashtable_init(&sw->router->nexthop_group_ht,
			      &__prestera_nexthop_group_ht_params);
	if (err)
		goto err_nexthop_grp_ht_init;

	err = rhashtable_init(&sw->router->fib_ht,
			      &__prestera_fib_ht_params);
	if (err)
		goto err_fib_ht_init;

	INIT_LIST_HEAD(&sw->router->vr_list);
	INIT_LIST_HEAD(&sw->router->rif_entry_list);

	return 0;

err_fib_ht_init:
	rhashtable_destroy(&sw->router->nexthop_group_ht);
err_nexthop_grp_ht_init:
	rhashtable_destroy(&sw->router->nh_neigh_ht);
err_nh_neigh_ht_init:
	return err;
}

void prestera_router_hw_fini(struct prestera_switch *sw)
{
	/* Ensure there is no objects */
	prestera_fib_node_destroy_ht(sw);
	prestera_rif_entry_destroy_ht(sw);
	/* Check if there can be nh_mangle ? */

	rhashtable_destroy(&sw->router->nexthop_group_ht);
	rhashtable_destroy(&sw->router->nh_neigh_ht);
	rhashtable_destroy(&sw->router->fib_ht);

	/* Sanity */
	WARN_ON(!list_empty(&sw->router->rif_entry_list));
	WARN_ON(!list_empty(&sw->router->vr_list));
}

static struct prestera_vr *__prestera_vr_find(struct prestera_switch *sw,
					      u32 tb_id)
{
	struct prestera_vr *vr;

	list_for_each_entry(vr, &sw->router->vr_list, router_node) {
		if (vr->tb_id == tb_id)
			return vr;
	}

	return NULL;
}

static struct prestera_vr *__prestera_vr_create(struct prestera_switch *sw,
						u32 tb_id,
						struct netlink_ext_ack *extack)
{
	struct prestera_vr *vr;
	u16 hw_vr_id;
	int err;

	err = prestera_hw_vr_create(sw, &hw_vr_id);
	if (err)
		return ERR_PTR(-ENOMEM);

	vr = kzalloc(sizeof(*vr), GFP_KERNEL);
	if (!vr) {
		err = -ENOMEM;
		goto err_alloc_vr;
	}

	vr->tb_id = tb_id;
	vr->hw_vr_id = hw_vr_id;

	list_add(&vr->router_node, &sw->router->vr_list);

	return vr;

err_alloc_vr:
	prestera_hw_vr_delete(sw, hw_vr_id);
	kfree(vr);
	return ERR_PTR(err);
}

static void __prestera_vr_destroy(struct prestera_switch *sw,
				  struct prestera_vr *vr)
{
	prestera_hw_vr_delete(sw, vr->hw_vr_id);
	list_del(&vr->router_node);
	kfree(vr);
}

static struct prestera_vr *prestera_vr_get(struct prestera_switch *sw, u32 tb_id,
					   struct netlink_ext_ack *extack)
{
	struct prestera_vr *vr;

	vr = __prestera_vr_find(sw, tb_id);
	if (!vr)
		vr = __prestera_vr_create(sw, tb_id, extack);
	if (IS_ERR(vr))
		return ERR_CAST(vr);

	return vr;
}

static void prestera_vr_put(struct prestera_switch *sw, struct prestera_vr *vr)
{
	if (!vr->ref_cnt)
		__prestera_vr_destroy(sw, vr);
}

/* make good things. iface is overhead struct... crutch
 * TODO May be it must be union + vr_id should be removed
 */
static int
__prestera_rif_entry_key_copy(const struct prestera_rif_entry_key *in,
			      struct prestera_rif_entry_key *out)
{
	memset(out, 0, sizeof(*out));
	out->iface.type = in->iface.type;

	switch (out->iface.type) {
	case PRESTERA_IF_PORT_E:
		out->iface.dev_port.hw_dev_num = in->iface.dev_port.hw_dev_num;
		out->iface.dev_port.port_num = in->iface.dev_port.port_num;
		break;
	case PRESTERA_IF_LAG_E:
		out->iface.lag_id = in->iface.lag_id;
		break;
	case PRESTERA_IF_VID_E:
		out->iface.vlan_id = in->iface.vlan_id;
		break;
	default:
		pr_err("Unsupported iface type");
		return -EINVAL;
	}

	return 0;
}

static int __prestera_rif_entry_macvlan_add(const struct prestera_switch *sw,
					    struct prestera_rif_entry *e,
					    const char *addr)
{
	int err;
	struct prestera_rif_macvlan_list_node *n;

	n = kzalloc(sizeof(*n), GFP_KERNEL);
	if (!n) {
		err = -ENOMEM;
		goto err_kzalloc;
	}

	/* vr_id should be unused for this call. If we want to do something
	 * with port (not vlan) - use port_rif_id to vid mapping on Agent side,
	 * or use rif vid, received from Agent... Or we need not to add initial
	 * mac address on rif creation. Why rif init MAC is deleted by index,
	 * but macvlan deleted by MAC ?
	 * Now it is inconsistent.
	 */
	err = prestera_hw_macvlan_add(sw, e->vr->hw_vr_id, addr,
				      e->key.iface.vlan_id, &e->key.iface);
	if (err)
		goto err_hw;

	memcpy(n->addr, addr, sizeof(n->addr));
	list_add(&n->head, &e->macvlan_list);

	return 0;

err_hw:
	kfree(n);
err_kzalloc:
	return err;
}

static void
__prestera_rif_entry_macvlan_del(const struct prestera_switch *sw,
				 struct prestera_rif_entry *e,
				 struct prestera_rif_macvlan_list_node *n)
{
	int err;

	err = prestera_hw_macvlan_del(sw, e->vr->hw_vr_id, n->addr,
				      e->key.iface.vlan_id, &e->key.iface);
	if (err)
		pr_err("%s:%d failed to delete macvlan from hw err = %d",
		       __func__, __LINE__, err);

	list_del(&n->head);
	kfree(n);
}

static void __prestera_rif_entry_macvlan_flush(const struct prestera_switch *sw,
					       struct prestera_rif_entry *e)
{
	struct prestera_rif_macvlan_list_node *n, *tmp;

	list_for_each_entry_safe(n, tmp, &e->macvlan_list, head)
		__prestera_rif_entry_macvlan_del(sw, e, n);
}

int prestera_rif_entry_set_macvlan(const struct prestera_switch *sw,
				   struct prestera_rif_entry *e,
				   bool enable, const char *addr)
{
	struct prestera_rif_macvlan_list_node *n, *tmp;

	list_for_each_entry_safe(n, tmp, &e->macvlan_list, head) {
		if (!memcmp(n->addr, addr, sizeof(n->addr))) {
			if (!enable)
				__prestera_rif_entry_macvlan_del(sw, e, n);

			return 0;
		}
	}

	if (enable)
		return __prestera_rif_entry_macvlan_add(sw, e, addr);

	return 0;
}

struct prestera_rif_entry *
prestera_rif_entry_find(const struct prestera_switch *sw,
			const struct prestera_rif_entry_key *k)
{
	struct prestera_rif_entry *rif_entry;
	struct prestera_rif_entry_key lk; /* lookup key */

	if (__prestera_rif_entry_key_copy(k, &lk))
		return NULL;

	list_for_each_entry(rif_entry, &sw->router->rif_entry_list,
			    router_node) {
		if (!memcmp(k, &rif_entry->key, sizeof(*k)))
			return rif_entry;
	}

	return NULL;
}

void prestera_rif_entry_destroy(struct prestera_switch *sw,
				struct prestera_rif_entry *e)
{
	struct prestera_iface iface;

	list_del(&e->router_node);

	__prestera_rif_entry_macvlan_flush(sw, e);

	memcpy(&iface, &e->key.iface, sizeof(iface));
	iface.vr_id = e->vr->hw_vr_id;
	prestera_hw_rif_delete(sw, e->hw_id, &iface);

	e->vr->ref_cnt--;
	prestera_vr_put(sw, e->vr);
	kfree(e);
}

void prestera_rif_entry_destroy_ht(struct prestera_switch *sw)
{
	struct prestera_rif_entry *e, *tmp;

	list_for_each_entry_safe(e, tmp, &sw->router->rif_entry_list,
				 router_node) {
		prestera_rif_entry_destroy(sw, e);
	}
}

struct prestera_rif_entry *
prestera_rif_entry_create(struct prestera_switch *sw,
			  struct prestera_rif_entry_key *k,
			  u32 tb_id, unsigned char *addr)
{
	int err;
	struct prestera_rif_entry *e;
	struct prestera_iface iface;

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		goto err_kzalloc;

	if (__prestera_rif_entry_key_copy(k, &e->key))
		goto err_key_copy;

	e->vr = prestera_vr_get(sw, tb_id, NULL);
	if (IS_ERR(e->vr))
		goto err_vr_get;

	e->vr->ref_cnt++;
	memcpy(&e->addr, addr, sizeof(e->addr));

	/* HW */
	memcpy(&iface, &e->key.iface, sizeof(iface));
	iface.vr_id = e->vr->hw_vr_id;
	err = prestera_hw_rif_create(sw, &iface, e->addr, &e->hw_id);
	if (err)
		goto err_hw_create;

	INIT_LIST_HEAD(&e->macvlan_list);

	list_add(&e->router_node, &sw->router->rif_entry_list);

	return e;

err_hw_create:
	e->vr->ref_cnt--;
	prestera_vr_put(sw, e->vr);
err_vr_get:
err_key_copy:
	kfree(e);
err_kzalloc:
	return NULL;
}

static void __prestera_nh_neigh_destroy(struct prestera_switch *sw,
					struct prestera_nh_neigh *neigh)
{
	rhashtable_remove_fast(&sw->router->nh_neigh_ht,
			       &neigh->ht_node,
			       __prestera_nh_neigh_ht_params);
	kfree(neigh);
}

static struct prestera_nh_neigh *
__prestera_nh_neigh_create(struct prestera_switch *sw,
			   struct prestera_nh_neigh_key *key)
{
	struct prestera_nh_neigh *neigh;
	int err;

	neigh = kzalloc(sizeof(*neigh), GFP_KERNEL);
	if (!neigh)
		goto err_kzalloc;

	memcpy(&neigh->key, key, sizeof(*key));
	neigh->info.connected = false;
	INIT_LIST_HEAD(&neigh->nexthop_group_list);
	INIT_LIST_HEAD(&neigh->nh_mangle_entry_list);
	err = rhashtable_insert_fast(&sw->router->nh_neigh_ht,
				     &neigh->ht_node,
				     __prestera_nh_neigh_ht_params);
	if (err)
		goto err_rhashtable_insert;

	return neigh;

err_rhashtable_insert:
	kfree(neigh);
err_kzalloc:
	return NULL;
}

struct prestera_nh_neigh *
prestera_nh_neigh_find(struct prestera_switch *sw,
		       struct prestera_nh_neigh_key *key)
{
	struct prestera_nh_neigh *nh_neigh;

	nh_neigh = rhashtable_lookup_fast(&sw->router->nh_neigh_ht,
					  key, __prestera_nh_neigh_ht_params);
	return IS_ERR(nh_neigh) ? NULL : nh_neigh;
}

struct prestera_nh_neigh *
prestera_nh_neigh_get(struct prestera_switch *sw,
		      struct prestera_nh_neigh_key *key)
{
	struct prestera_nh_neigh *neigh;

	neigh = prestera_nh_neigh_find(sw, key);
	if (!neigh)
		return __prestera_nh_neigh_create(sw, key);

	return neigh;
}

void prestera_nh_neigh_put(struct prestera_switch *sw,
			   struct prestera_nh_neigh *neigh)
{
	if (list_empty(&neigh->nexthop_group_list) &&
	    list_empty(&neigh->nh_mangle_entry_list))
		__prestera_nh_neigh_destroy(sw, neigh);
}

/* Updates new prestera_neigh_info */
int prestera_nh_neigh_set(struct prestera_switch *sw,
			  struct prestera_nh_neigh *neigh)
{
	struct prestera_nh_neigh_head *nh_head;
	struct prestera_nexthop_group *nh_grp;
	struct prestera_nh_mangle_entry *nm;
	int err;

	list_for_each_entry(nh_head, &neigh->nexthop_group_list, head) {
		nh_grp = nh_head->this;
		err = prestera_nexthop_group_set(sw, nh_grp);
		if (err)
			return err;
	}

	list_for_each_entry(nm, &neigh->nh_mangle_entry_list, nh_neigh_head) {
		err = prestera_nh_mangle_entry_set(sw, nm);
		if (err)
			return err;
	}

	return 0;
}

bool prestera_nh_neigh_util_hw_state(struct prestera_switch *sw,
				     struct prestera_nh_neigh *nh_neigh)
{
	bool state;
	struct prestera_nh_neigh_head *nh_head, *tmp;
	struct prestera_nh_mangle_entry  *nm, *nm_tmp;

	state = false;
	list_for_each_entry_safe(nh_head, tmp,
				 &nh_neigh->nexthop_group_list, head) {
		state = prestera_nexthop_group_util_hw_state(sw, nh_head->this);
		if (state)
			goto out;
	}
	list_for_each_entry_safe(nm, nm_tmp, &nh_neigh->nh_mangle_entry_list,
				 nh_neigh_head) {
		state = prestera_nh_mangle_entry_util_hw_state(sw, nm);
		if (state)
			goto out;
	}

out:
	return state;
}

static struct prestera_nexthop_group *
__prestera_nexthop_group_create(struct prestera_switch *sw,
				struct prestera_nexthop_group_key *key)
{
	struct prestera_nexthop_group *nh_grp;
	struct prestera_nh_neigh *nh_neigh;
	int nh_cnt, err, gid;

	nh_grp = kzalloc(sizeof(*nh_grp), GFP_KERNEL);
	if (!nh_grp)
		goto err_kzalloc;

	memcpy(&nh_grp->key, key, sizeof(*key));
	for (nh_cnt = 0; nh_cnt < PRESTERA_NHGR_SIZE_MAX; nh_cnt++) {
		if (!prestera_nh_neigh_key_is_valid(&nh_grp->key.neigh[nh_cnt]))
			break;

		nh_neigh = prestera_nh_neigh_get(sw,
						 &nh_grp->key.neigh[nh_cnt]);
		if (!nh_neigh)
			goto err_nh_neigh_get;

		nh_grp->nh_neigh_head[nh_cnt].neigh = nh_neigh;
		nh_grp->nh_neigh_head[nh_cnt].this = nh_grp;
		list_add(&nh_grp->nh_neigh_head[nh_cnt].head,
			 &nh_neigh->nexthop_group_list);
	}

	err = prestera_nh_group_create(sw, nh_cnt, &nh_grp->grp_id);
	if (err)
		goto err_nh_group_create;

	err = prestera_nexthop_group_set(sw, nh_grp);
	if (err)
		goto err_nexthop_group_set;

	err = rhashtable_insert_fast(&sw->router->nexthop_group_ht,
				     &nh_grp->ht_node,
				     __prestera_nexthop_group_ht_params);
	if (err)
		goto err_ht_insert;

	/* reset cache for created group */
	gid = nh_grp->grp_id;
	sw->router->nhgrp_hw_state_cache[gid / 8] &= ~BIT(gid % 8);

	return nh_grp;

err_ht_insert:
err_nexthop_group_set:
	prestera_nh_group_delete(sw, nh_cnt, nh_grp->grp_id);
err_nh_group_create:
err_nh_neigh_get:
	for (nh_cnt--; nh_cnt >= 0; nh_cnt--) {
		list_del(&nh_grp->nh_neigh_head[nh_cnt].head);
		prestera_nh_neigh_put(sw, nh_grp->nh_neigh_head[nh_cnt].neigh);
	}

	kfree(nh_grp);
err_kzalloc:
	return NULL;
}

static void
__prestera_nexthop_group_destroy(struct prestera_switch *sw,
				 struct prestera_nexthop_group *nh_grp)
{
	struct prestera_nh_neigh *nh_neigh;
	int nh_cnt;

	rhashtable_remove_fast(&sw->router->nexthop_group_ht,
			       &nh_grp->ht_node,
			       __prestera_nexthop_group_ht_params);

	for (nh_cnt = 0; nh_cnt < PRESTERA_NHGR_SIZE_MAX; nh_cnt++) {
		nh_neigh = nh_grp->nh_neigh_head[nh_cnt].neigh;
		if (!nh_neigh)
			break;

		list_del(&nh_grp->nh_neigh_head[nh_cnt].head);
		prestera_nh_neigh_put(sw, nh_neigh);
	}

	prestera_nh_group_delete(sw, nh_cnt, nh_grp->grp_id);
	kfree(nh_grp);
}

static struct prestera_nexthop_group *
prestera_nexthop_group_find(struct prestera_switch *sw,
			    struct prestera_nexthop_group_key *key)
{
	struct prestera_nexthop_group *nh_grp;

	nh_grp = rhashtable_lookup_fast(&sw->router->nexthop_group_ht,
					key, __prestera_nexthop_group_ht_params);
	return IS_ERR(nh_grp) ? NULL : nh_grp;
}

static struct prestera_nexthop_group *
prestera_nexthop_group_get(struct prestera_switch *sw,
			   struct prestera_nexthop_group_key *key)
{
	struct prestera_nexthop_group *nh_grp;

	nh_grp = prestera_nexthop_group_find(sw, key);
	if (!nh_grp)
		return __prestera_nexthop_group_create(sw, key);

	return nh_grp;
}

static void prestera_nexthop_group_put(struct prestera_switch *sw,
				       struct prestera_nexthop_group *nh_grp)
{
	if (!nh_grp->ref_cnt)
		__prestera_nexthop_group_destroy(sw, nh_grp);
}

/* Updates with new nh_neigh's info */
static int prestera_nexthop_group_set(struct prestera_switch *sw,
				      struct prestera_nexthop_group *nh_grp)
{
	struct prestera_neigh_info info[PRESTERA_NHGR_SIZE_MAX];
	struct prestera_nh_neigh *neigh;
	int nh_cnt;

	memset(&info[0], 0, sizeof(info));
	for (nh_cnt = 0; nh_cnt < PRESTERA_NHGR_SIZE_MAX; nh_cnt++) {
		neigh = nh_grp->nh_neigh_head[nh_cnt].neigh;
		if (!neigh)
			break;

		memcpy(&info[nh_cnt], &neigh->info, sizeof(neigh->info));
	}

	return prestera_nh_entries_set(sw, nh_cnt, &info[0], nh_grp->grp_id);
}

static bool
prestera_nexthop_group_util_hw_state(struct prestera_switch *sw,
				     struct prestera_nexthop_group *nh_grp)
{
	int err;
	u32 buf_size = sw->size_tbl_router_nexthop / 8 + 1;
	u32 gid = nh_grp->grp_id;
	u8 *cache = sw->router->nhgrp_hw_state_cache;

	/* Antijitter
	 * Prevent situation, when we read state of nh_grp twice in short time,
	 * and state bit is still cleared on second call. So just stuck active
	 * state for PRESTERA_NH_ACTIVE_JIFFER_FILTER, after last occurred.
	 */
	if (!time_before(jiffies, sw->router->nhgrp_hw_cache_kick +
			msecs_to_jiffies(PRESTERA_NH_ACTIVE_JIFFER_FILTER))) {
		err = prestera_nhgrp_blk_get(sw, cache, buf_size);
		if (err) {
			MVSW_LOG_ERROR("Failed to get hw state nh_grp's");
			return false;
		}

		sw->router->nhgrp_hw_cache_kick = jiffies;
	}

	if (cache[gid / 8] & BIT(gid % 8))
		return true;

	return false;
}

/* TODO: Move fibs to another file (hw_match.c?) */
struct prestera_fib_node *
prestera_fib_node_find(struct prestera_switch *sw, struct prestera_fib_key *key)
{
	struct prestera_fib_node *fib_node;

	fib_node = rhashtable_lookup_fast(&sw->router->fib_ht, key,
					  __prestera_fib_ht_params);
	return IS_ERR(fib_node) ? NULL : fib_node;
}

static void __prestera_fib_node_destruct(struct prestera_switch *sw,
					 struct prestera_fib_node *fib_node)
{
	struct prestera_vr *vr;

	vr = fib_node->info.vr;
	if (fib_node->key.addr.v == PRESTERA_IPV4)
		prestera_lpm_del(sw, vr->hw_vr_id, &fib_node->key.addr,
				 fib_node->key.prefix_len);
	else if (fib_node->key.addr.v == PRESTERA_IPV6)
		prestera_lpm6_del(sw, vr->hw_vr_id, &fib_node->key.addr,
				  fib_node->key.prefix_len);

	switch (fib_node->info.type) {
	case PRESTERA_FIB_TYPE_UC_NH:
		fib_node->info.nh_grp->ref_cnt--;
		prestera_nexthop_group_put(sw, fib_node->info.nh_grp);
		break;
	case PRESTERA_FIB_TYPE_TRAP:
		break;
	case PRESTERA_FIB_TYPE_DROP:
		break;
	default:
	      MVSW_LOG_ERROR("Unknown fib_node->info.type = %d",
			     fib_node->info.type);
	}

	vr->ref_cnt--;
	prestera_vr_put(sw, vr);
}

void prestera_fib_node_destroy(struct prestera_switch *sw,
			       struct prestera_fib_node *fib_node)
{
	__prestera_fib_node_destruct(sw, fib_node);
	rhashtable_remove_fast(&sw->router->fib_ht, &fib_node->ht_node,
			       __prestera_fib_ht_params);
	kfree(fib_node);
}

void prestera_fib_node_destroy_ht(struct prestera_switch *sw)
{
	struct prestera_fib_node *node;
	struct rhashtable_iter iter;

	while (1) {
		rhashtable_walk_enter(&sw->router->fib_ht, &iter);
		rhashtable_walk_start(&iter);
		node = rhashtable_walk_next(&iter);
		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);

		if (!node)
			break;
		else if (IS_ERR(node))
			continue;
		else if (node)
			prestera_fib_node_destroy(sw, node);
	}
}

/* nh_grp_key valid only if fib_type == MVSW_PR_FIB_TYPE_UC_NH */
struct prestera_fib_node *
prestera_fib_node_create(struct prestera_switch *sw,
			 struct prestera_fib_key *key,
			 enum prestera_fib_type fib_type,
			 struct prestera_nexthop_group_key *nh_grp_key)
{
	struct prestera_fib_node *fib_node;
	u32 grp_id;
	struct prestera_vr *vr;
	int err;

	fib_node = kzalloc(sizeof(*fib_node), GFP_KERNEL);
	if (!fib_node)
		goto err_kzalloc;

	memcpy(&fib_node->key, key, sizeof(*key));
	fib_node->info.type = fib_type;

	vr = prestera_vr_get(sw, key->tb_id, NULL);
	if (IS_ERR(vr))
		goto err_vr_get;

	fib_node->info.vr = vr;
	vr->ref_cnt++;

	switch (fib_type) {
	case PRESTERA_FIB_TYPE_TRAP:
		grp_id = PRESTERA_NHGR_UNUSED;
		break;
	case PRESTERA_FIB_TYPE_DROP:
		grp_id = PRESTERA_NHGR_DROP;
		break;
	case PRESTERA_FIB_TYPE_UC_NH:
		fib_node->info.nh_grp = prestera_nexthop_group_get(sw,
								   nh_grp_key);
		if (!fib_node->info.nh_grp)
			goto err_nh_grp_get;

		fib_node->info.nh_grp->ref_cnt++;
		grp_id = fib_node->info.nh_grp->grp_id;
		break;
	default:
		MVSW_LOG_ERROR("Unsupported fib_type %d", fib_type);
		goto err_nh_grp_get;
	}

	if (key->addr.v == PRESTERA_IPV4)
		err = prestera_lpm_add(sw, vr->hw_vr_id, &key->addr,
				       key->prefix_len, grp_id);
	else if (key->addr.v == PRESTERA_IPV6)
		err = prestera_lpm6_add(sw, vr->hw_vr_id, &key->addr,
					key->prefix_len, grp_id);
	else
		err = -EOPNOTSUPP;

	if (err)
		goto err_lpm_add;

	err = rhashtable_insert_fast(&sw->router->fib_ht, &fib_node->ht_node,
				     __prestera_fib_ht_params);
	if (err)
		goto err_ht_insert;

	return fib_node;

err_ht_insert:
	if (key->addr.v == PRESTERA_IPV4)
		prestera_lpm_del(sw, vr->hw_vr_id, &key->addr, key->prefix_len);
	else if (key->addr.v == PRESTERA_IPV6)
		prestera_lpm6_del(sw, vr->hw_vr_id,
				  &key->addr, key->prefix_len);
err_lpm_add:
	if (fib_type == PRESTERA_FIB_TYPE_UC_NH) {
		fib_node->info.nh_grp->ref_cnt--;
		prestera_nexthop_group_put(sw, fib_node->info.nh_grp);
	}
err_nh_grp_get:
	vr->ref_cnt--;
	prestera_vr_put(sw, vr);
err_vr_get:
	kfree(fib_node);
err_kzalloc:
	return NULL;
}
