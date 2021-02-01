// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/*
 * Copyright (c) 2019-2020 Marvell International Ltd. All rights reserved.
 *
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/notifier.h>
#include <linux/sort.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/if_bridge.h>
#include <linux/rhashtable.h>
#include <net/netevent.h>
#include <net/neighbour.h>
#include <net/addrconf.h>
#include <net/fib_notifier.h>
#include <net/switchdev.h>
#include <net/arp.h>
#include <net/nexthop.h>

#include "prestera.h"
#include "prestera_hw.h"
#include "prestera_log.h"

#define MVSW_PR_IMPLICITY_RESOLVE_DEAD_NEIGH
#define MVSW_PR_NH_PROBE_INTERVAL 5000 /* ms */
#define MVSW_PR_NH_ACTIVE_JIFFER_FILTER 3000 /* ms */
#define MVSW_PR_NHGR_UNUSED (0)
#define MVSW_PR_NHGR_DROP (0xFFFFFFFF)

static const char mvsw_driver_name[] = "mrvl_switchdev";

struct mvsw_pr_rif {
	struct mvsw_pr_iface iface;
	struct net_device *dev;
	struct list_head router_node;
	unsigned char addr[ETH_ALEN];
	unsigned int mtu;
	bool is_active;
	u16 rif_id;
	struct mvsw_pr_vr *vr;
	struct mvsw_pr_switch *sw;
	unsigned int ref_cnt;
};

struct mvsw_pr_rif_params {
	struct net_device *dev;
	u16 vid;
};

struct mvsw_pr_fib_node {
	struct rhash_head ht_node; /* node of mvsw_pr_vr */
	struct mvsw_pr_fib_key key;
	struct mvsw_pr_fib_info info; /* action related info */
};

struct mvsw_pr_vr {
	u16 hw_vr_id;			/* virtual router ID */
	u32 tb_id;			/* key (kernel fib table id) */
	struct list_head router_node;
	unsigned int ref_cnt;
};

struct mvsw_pr_nexthop_group_key {
	struct mvsw_pr_nh_neigh_key neigh[MVSW_PR_NHGR_SIZE_MAX];
};

struct mvsw_pr_nexthop_group {
	struct mvsw_pr_nexthop_group_key key;
	/* Store intermediate object here.
	 * This prevent overhead kzalloc call.
	 */
	/* nh_neigh is used only to notify nexthop_group */
	struct mvsw_pr_nh_neigh_head {
		struct mvsw_pr_nexthop_group *this;
		struct list_head head;
		/* ptr to neigh is not necessary.
		 * It used to prevent lookup of nh_neigh by key (n) on destroy
		 */
		struct mvsw_pr_nh_neigh *neigh;
	} nh_neigh_head[MVSW_PR_NHGR_SIZE_MAX];
	u32 grp_id; /* hw */
	unsigned long hw_last_connected; /* jiffies */
	struct rhash_head ht_node; /* node of mvsw_pr_vr */
	unsigned int ref_cnt;
};

enum mvsw_pr_mp_hash_policy {
	MVSW_MP_L3_HASH_POLICY,
	MVSW_MP_L4_HASH_POLICY,
	MVSW_MP_HASH_POLICY_MAX,
};

struct mvsw_pr_kern_neigh_cache {
	struct mvsw_pr_nh_neigh_key key;
	bool offloaded;
	struct rhash_head ht_node;
	struct list_head kern_fib_cache_list;
	bool lpm_added; /* Indicate if neigh is reachable by connected route */
	bool in_kernel; /* Valid in kernel */
};

/* Used to track offloaded fib entries */
struct mvsw_pr_kern_fib_cache {
	struct mvsw_pr_fib_key key;
	struct fib_info *fi;
	struct rhash_head ht_node; /* node of mvsw_pr_router */
	struct mvsw_pr_kern_neigh_cache_head {
		struct mvsw_pr_kern_fib_cache *this;
		struct list_head head;
		struct mvsw_pr_kern_neigh_cache *n_cache;
	} kern_neigh_cache_head[MVSW_PR_NHGR_SIZE_MAX];
};

static const struct rhashtable_params __mvsw_pr_kern_neigh_cache_ht_params = {
	.key_offset  = offsetof(struct mvsw_pr_kern_neigh_cache, key),
	.head_offset = offsetof(struct mvsw_pr_kern_neigh_cache, ht_node),
	.key_len     = sizeof(struct mvsw_pr_nh_neigh_key),
	.automatic_shrinking = true,
};

static const struct rhashtable_params __mvsw_pr_kern_fib_cache_ht_params = {
	.key_offset  = offsetof(struct mvsw_pr_kern_fib_cache, key),
	.head_offset = offsetof(struct mvsw_pr_kern_fib_cache, ht_node),
	.key_len     = sizeof(struct mvsw_pr_fib_key),
	.automatic_shrinking = true,
};

static const struct rhashtable_params __mvsw_pr_fib_ht_params = {
	.key_offset  = offsetof(struct mvsw_pr_fib_node, key),
	.head_offset = offsetof(struct mvsw_pr_fib_node, ht_node),
	.key_len     = sizeof(struct mvsw_pr_fib_key),
	.automatic_shrinking = true,
};

static const struct rhashtable_params __mvsw_pr_nh_neigh_ht_params = {
	.key_offset  = offsetof(struct mvsw_pr_nh_neigh, key),
	.key_len     = sizeof(struct mvsw_pr_nh_neigh_key),
	.head_offset = offsetof(struct mvsw_pr_nh_neigh, ht_node),
};

static const struct rhashtable_params __mvsw_pr_nexthop_group_ht_params = {
	.key_offset  = offsetof(struct mvsw_pr_nexthop_group, key),
	.key_len     = sizeof(struct mvsw_pr_nexthop_group_key),
	.head_offset = offsetof(struct mvsw_pr_nexthop_group, ht_node),
};

static struct workqueue_struct *mvsw_r_wq;
static struct workqueue_struct *mvsw_r_owq;

static DEFINE_MUTEX(mvsw_owq_mutex_wip); /* owq function is in progress */
static bool mvsw_owq_flushing;
static void mvsw_owq_lock(void)
{
	while (true) {
		if (!mutex_trylock(&mvsw_owq_mutex_wip))
			goto wip_again;

		if (!rtnl_trylock() && !READ_ONCE(mvsw_owq_flushing))
			goto rtnl_again;

		break;
rtnl_again:
		mutex_unlock(&mvsw_owq_mutex_wip);
wip_again:
		schedule();
	}
}

static void mvsw_owq_unlock(void)
{
	if (!READ_ONCE(mvsw_owq_flushing))
		rtnl_unlock();

	mutex_unlock(&mvsw_owq_mutex_wip);
}

/* Must be called under rtnl_lock */
static void mvsw_owq_flush(void)
{
	/* Sanity check */
	if (rtnl_trylock())
		panic("%s: called without rtnl_lock !", __func__);

	mutex_lock(&mvsw_owq_mutex_wip);
	WRITE_ONCE(mvsw_owq_flushing, true);
	mutex_unlock(&mvsw_owq_mutex_wip);

	flush_workqueue(mvsw_r_owq);

	mutex_lock(&mvsw_owq_mutex_wip);
	WRITE_ONCE(mvsw_owq_flushing, false);
	mutex_unlock(&mvsw_owq_mutex_wip);
}

static const unsigned char mvsw_pr_mac_mask[ETH_ALEN] = {
	0xff, 0xff, 0xff, 0xff, 0xfc, 0x00
};

static struct mvsw_pr_vr *mvsw_pr_vr_get(struct mvsw_pr_switch *sw, u32 tb_id,
					 struct netlink_ext_ack *extack);
static u32 mvsw_pr_fix_tb_id(u32 tb_id);
static void mvsw_pr_vr_put(struct mvsw_pr_switch *sw, struct mvsw_pr_vr *vr);
static void mvsw_pr_vr_util_hw_abort(struct mvsw_pr_switch *sw);
static struct mvsw_pr_rif *mvsw_pr_rif_create(struct mvsw_pr_switch *sw,
					      const struct mvsw_pr_rif_params
					      *params,
					      struct netlink_ext_ack *extack);
static int mvsw_pr_rif_vr_update(struct mvsw_pr_switch *sw,
				 struct mvsw_pr_rif *rif,
				 struct netlink_ext_ack *extack);
static void mvsw_pr_rif_destroy(struct mvsw_pr_rif *rif);
static void mvsw_pr_rif_put(struct mvsw_pr_rif *rif);
static int mvsw_pr_rif_update(struct mvsw_pr_rif *rif, char *mac);
static struct mvsw_pr_rif *mvsw_pr_rif_find(const struct mvsw_pr_switch *sw,
					    const struct net_device *dev);
static u16 mvsw_pr_rif_vr_id(struct mvsw_pr_rif *rif);
static bool
mvsw_pr_nh_neigh_util_hw_state(struct mvsw_pr_switch *sw,
			       struct mvsw_pr_nh_neigh *nh_neigh);
static bool
mvsw_pr_nexthop_group_util_hw_state(struct mvsw_pr_switch *sw,
				    struct mvsw_pr_nexthop_group *nh_grp);
static struct mvsw_pr_nh_neigh *
mvsw_pr_nh_neigh_find(struct mvsw_pr_switch *sw,
		      struct mvsw_pr_nh_neigh_key *key);
static int mvsw_pr_nh_neigh_set(struct mvsw_pr_switch *sw,
				struct mvsw_pr_nh_neigh *neigh);
static int mvsw_pr_nexthop_group_set(struct mvsw_pr_switch *sw,
				     struct mvsw_pr_nexthop_group *nh_grp);
static struct mvsw_pr_fib_node *
mvsw_pr_fib_node_find(struct mvsw_pr_switch *sw, struct mvsw_pr_fib_key *key);
static void mvsw_pr_fib_node_destroy(struct mvsw_pr_switch *sw,
				     struct mvsw_pr_fib_node *fib_node);
static struct mvsw_pr_fib_node *
mvsw_pr_fib_node_uc_nh_create(struct mvsw_pr_switch *sw,
			      struct mvsw_pr_fib_key *key,
			      struct mvsw_pr_nexthop_group_key *nh_grp_key);
static bool mvsw_pr_fi_is_direct(struct fib_info *fi);
static bool mvsw_pr_fi_is_nh(struct fib_info *fi);
static bool
mvsw_pr_fib_node_util_is_neighbour(struct mvsw_pr_fib_node *fib_node);
static void
mvsw_pr_kern_fib_cache_offload_set(struct mvsw_pr_switch *sw,
				   struct mvsw_pr_kern_fib_cache *fib_cache);

static u16 mvsw_pr_nh_dev_to_vid(struct mvsw_pr_switch *sw,
				 struct net_device *dev)
{
	struct macvlan_dev *vlan;
	u16 vid = 0;

	if (is_vlan_dev(dev) &&
	    netif_is_bridge_master(vlan_dev_real_dev(dev))) {
		vid = vlan_dev_vlan_id(dev);
	} else if (netif_is_bridge_master(dev) && br_vlan_enabled(dev)) {
		br_vlan_get_pvid(dev, &vid);
	} else if (netif_is_bridge_master(dev)) {
		vid = mvsw_pr_vlan_dev_vlan_id(sw->bridge, dev);
	} else if (netif_is_macvlan(dev)) {
		vlan = netdev_priv(dev);
		return mvsw_pr_nh_dev_to_vid(sw, vlan->lowerdev);
	}

	return vid;
}

static struct net_device*
mvsw_pr_nh_dev_egress(struct mvsw_pr_switch *sw, struct net_device *dev,
		      u8 *ha)
{
	struct net_device *bridge_dev, *egress_dev = dev;
	u16 vid = mvsw_pr_nh_dev_to_vid(sw, dev);
	struct macvlan_dev *vlan;

	if (is_vlan_dev(dev) &&
	    netif_is_bridge_master(vlan_dev_real_dev(dev))) {
		bridge_dev = vlan_dev_priv(dev)->real_dev;
		egress_dev = br_fdb_find_port(bridge_dev, ha,
					      vid);
	} else if (netif_is_bridge_master(dev) && br_vlan_enabled(dev)) {
		egress_dev = br_fdb_find_port(dev, ha, vid);
	} else if (netif_is_bridge_master(dev)) {
		/* vid in .1d bridge is 0 */
		egress_dev = br_fdb_find_port(dev, ha, 0);
	} else if (netif_is_macvlan(dev)) {
		vlan = netdev_priv(dev);
		return mvsw_pr_nh_dev_egress(sw, vlan->lowerdev, ha);
	}

	return egress_dev;
}

static u16 mvsw_pr_rif_vr_id(struct mvsw_pr_rif *rif)
{
	return rif->vr->hw_vr_id;
}

static int
mvsw_pr_rif_iface_init(struct mvsw_pr_rif *rif)
{
	struct net_device *dev = rif->dev;
	struct mvsw_pr_switch *sw = rif->sw;
	struct mvsw_pr_port *port;
	int if_type = mvsw_pr_dev_if_type(dev);

	switch (if_type) {
	case MVSW_IF_PORT_E:
		port = netdev_priv(dev);
		rif->iface.dev_port.hw_dev_num = port->dev_id;
		rif->iface.dev_port.port_num = port->hw_id;
		break;
	case MVSW_IF_LAG_E:
		prestera_lag_id_find(sw, dev, &rif->iface.lag_id);
		break;
	case MVSW_IF_VID_E:
		break;
	default:
		pr_err("Unsupported rif type");
		return -EINVAL;
	}

	rif->iface.type = if_type;
	rif->iface.vlan_id = mvsw_pr_nh_dev_to_vid(sw, dev);
	rif->iface.vr_id = rif->vr->hw_vr_id;

	return 0;
}

static int
__mvsw_pr_neigh_iface_init(struct mvsw_pr_switch *sw,
			   struct mvsw_pr_iface *iface,
			   struct neighbour *n,
			   struct net_device *dev)
{
	bool is_nud_perm = n->nud_state & NUD_PERMANENT;
	struct net_device *egress_dev;
	struct mvsw_pr_port *port;

	iface->type = mvsw_pr_dev_if_type(dev);

	switch (iface->type) {
	case MVSW_IF_PORT_E:
	case MVSW_IF_VID_E:
		egress_dev = mvsw_pr_nh_dev_egress(sw, dev, n->ha);
		if (!egress_dev && is_nud_perm) {
		/* Permanent neighbours on a bridge are not bounded to any
		 * of the ports which is needed by the hardware, therefore
		 * use any valid lower
		 */
			port = mvsw_pr_port_dev_lower_find(dev);
			egress_dev = port->net_dev;
		}
		if (!egress_dev)
			return -ENOENT;

		if (!mvsw_pr_netdev_check(egress_dev))
			return __mvsw_pr_neigh_iface_init(sw, iface, n,
							  egress_dev);

		port = netdev_priv(egress_dev);
		iface->dev_port.hw_dev_num = port->dev_id;
		iface->dev_port.port_num = port->hw_id;
		break;
	case MVSW_IF_LAG_E:
		prestera_lag_id_find(sw, dev, &iface->lag_id);
		break;
	default:
		MVSW_LOG_ERROR("Unsupported nexthop device");
		return -EINVAL;
	}

	return 0;
}

static int
mvsw_pr_neigh_iface_init(struct mvsw_pr_switch *sw,
			struct mvsw_pr_iface *iface,
			struct neighbour *n)
{
	/* TODO vr_id is obsolete in iface ? */
	iface->vlan_id = mvsw_pr_nh_dev_to_vid(sw, n->dev);
	return __mvsw_pr_neigh_iface_init(sw, iface, n, n->dev);
}

static void mvsw_pr_util_kern_set_neigh_offload(struct neighbour *n,
						bool offloaded)
{
	if (offloaded)
		n->flags |= NTF_OFFLOADED;
	else
		n->flags &= ~NTF_OFFLOADED;
}

static void
__mvsw_pr_util_kern_unset_allneigh_offload_cb(struct neighbour *n,
					      void *cookie)
{
	mvsw_pr_util_kern_set_neigh_offload(n, false);
}

static void mvsw_pr_util_kern_unset_allneigh_offload(void)
{
	/* Walk through every neighbour in kernel */
	neigh_for_each(&arp_tbl,
		       __mvsw_pr_util_kern_unset_allneigh_offload_cb,
		       NULL);
}

static void
mvsw_pr_util_kern_set_nh_offload(struct fib_nh *fib_nh, bool offloaded)
{
		if (offloaded)
			fib_nh->fib_nh_flags |= RTNH_F_OFFLOAD;
		else
			fib_nh->fib_nh_flags &= ~RTNH_F_OFFLOAD;
}

/* must be called with rcu_read_lock() */
static int mvsw_pr_util_kern_get_route(struct fib_result *res,
				       u32 tb_id,
				       struct mvsw_pr_ip_addr *addr)
{
	struct fib_table *tb;
	struct flowi4 fl4;
	int ret;

	/* TODO: walkthrough appropriate tables in kernel
	 * to know if the same prefix exists in several tables
	 */
	tb = fib_new_table(&init_net, tb_id);
	if (!tb)
		return -ENOENT;

	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = addr->u.ipv4;
	ret = fib_table_lookup(tb, &fl4, res, FIB_LOOKUP_NOREF);
	if (ret)
		return ret;

	return 0;
}

static int
mvsw_pr_util_fib_nh2nh_neigh_key(struct mvsw_pr_switch *sw,
				 struct fib_nh *fib_nh,
				 struct mvsw_pr_nh_neigh_key *nh_key)
{
	memset(nh_key, 0, sizeof(*nh_key));
	nh_key->addr.u.ipv4 = fib_nh->fib_nh_gw4;
	nh_key->rif = mvsw_pr_rif_find(sw, fib_nh->fib_nh_dev);
	if (!nh_key->rif)
		return -ENOENT;

	return 0;
}

static struct mvsw_pr_kern_neigh_cache *
mvsw_pr_kern_neigh_cache_find(struct mvsw_pr_switch *sw,
			      struct mvsw_pr_nh_neigh_key *key)
{
	struct mvsw_pr_kern_neigh_cache *n_cache;

	n_cache =
	 rhashtable_lookup_fast(&sw->router->kern_neigh_cache_ht, key,
				__mvsw_pr_kern_neigh_cache_ht_params);
	return IS_ERR(n_cache) ? NULL : n_cache;
}

static void
__mvsw_pr_kern_neigh_cache_destroy(struct mvsw_pr_switch *sw,
				   struct mvsw_pr_kern_neigh_cache *n_cache)
{
	n_cache->key.rif->ref_cnt--;
	mvsw_pr_rif_put(n_cache->key.rif);
	rhashtable_remove_fast(&sw->router->kern_neigh_cache_ht,
			       &n_cache->ht_node,
			       __mvsw_pr_kern_neigh_cache_ht_params);
	kfree(n_cache);
}

static struct mvsw_pr_kern_neigh_cache *
__mvsw_pr_kern_neigh_cache_create(struct mvsw_pr_switch *sw,
				  struct mvsw_pr_nh_neigh_key *key)
{
	struct mvsw_pr_kern_neigh_cache *n_cache;
	int err;

	n_cache = kzalloc(sizeof(*n_cache), GFP_KERNEL);
	if (!n_cache)
		goto err_kzalloc;

	memcpy(&n_cache->key, key, sizeof(*key));
	n_cache->key.rif->ref_cnt++;

	INIT_LIST_HEAD(&n_cache->kern_fib_cache_list);
	err = rhashtable_insert_fast(&sw->router->kern_neigh_cache_ht,
				     &n_cache->ht_node,
				     __mvsw_pr_kern_neigh_cache_ht_params);
	if (err)
		goto err_ht_insert;

	return n_cache;

err_ht_insert:
	n_cache->key.rif->ref_cnt--;
	mvsw_pr_rif_put(n_cache->key.rif);
	kfree(n_cache);
err_kzalloc:
	return NULL;
}

static struct mvsw_pr_kern_neigh_cache *
mvsw_pr_kern_neigh_cache_get(struct mvsw_pr_switch *sw,
			     struct mvsw_pr_nh_neigh_key *key)
{
	struct mvsw_pr_kern_neigh_cache *n_cache;

	n_cache = mvsw_pr_kern_neigh_cache_find(sw, key);
	if (!n_cache)
		n_cache = __mvsw_pr_kern_neigh_cache_create(sw, key);

	return n_cache;
}

static void
mvsw_pr_kern_neigh_cache_put(struct mvsw_pr_switch *sw,
			     struct mvsw_pr_kern_neigh_cache *n_cache)
{
	if (!n_cache->in_kernel && !n_cache->lpm_added &&
	    list_empty(&n_cache->kern_fib_cache_list))
		__mvsw_pr_kern_neigh_cache_destroy(sw, n_cache);
}

static void
mvsw_pr_kern_neigh_cache_offload_set(struct mvsw_pr_switch *sw,
				     struct mvsw_pr_kern_neigh_cache *n_cache)
{
	struct mvsw_pr_kern_neigh_cache_head *n_head;

	list_for_each_entry(n_head, &n_cache->kern_fib_cache_list, head) {
		mvsw_pr_kern_fib_cache_offload_set(sw, n_head->this);
	}
}

static void
mvsw_pr_kern_neigh_cache_lpm_set(struct mvsw_pr_switch *sw,
				 struct mvsw_pr_kern_neigh_cache *n_cache)
{
	struct mvsw_pr_fib_key fib_key;
	struct mvsw_pr_fib_node *fib_node;
	struct mvsw_pr_nexthop_group_key nh_grp_key;

	memset(&fib_key, 0, sizeof(fib_key));
	fib_key.addr = n_cache->key.addr;
	fib_key.prefix_len = 32;
	fib_key.tb_id = n_cache->key.rif->vr->tb_id;
	fib_node = mvsw_pr_fib_node_find(sw, &fib_key);
	if (!n_cache->lpm_added && fib_node) {
		if (mvsw_pr_fib_node_util_is_neighbour(fib_node))
			mvsw_pr_fib_node_destroy(sw, fib_node);
		return;
	}

	if (n_cache->lpm_added && !fib_node) {
		memset(&nh_grp_key, 0, sizeof(nh_grp_key));
		nh_grp_key.neigh[0] = n_cache->key;
		fib_node = mvsw_pr_fib_node_uc_nh_create(sw, &fib_key,
							 &nh_grp_key);
		if (!fib_node)
			MVSW_LOG_ERROR("%s failed ip=%pI4n",
				       "mvsw_pr_fib_node_uc_nh_create",
				       &fib_key.addr.u.ipv4);
		return;
	}
}

static struct mvsw_pr_kern_fib_cache *
mvsw_pr_kern_fib_cache_find(struct mvsw_pr_switch *sw,
			    struct mvsw_pr_fib_key *key)
{
	struct mvsw_pr_kern_fib_cache *fib_cache;

	fib_cache =
	 rhashtable_lookup_fast(&sw->router->kern_fib_cache_ht, key,
				__mvsw_pr_kern_fib_cache_ht_params);
	return IS_ERR(fib_cache) ? NULL : fib_cache;
}

static void
__mvsw_pr_kern_fib_cache_destruct(struct mvsw_pr_switch *sw,
				  struct mvsw_pr_kern_fib_cache *fib_cache)
{
	int i;
	struct mvsw_pr_kern_neigh_cache *n_cache;
	struct fib_nh *fib_nh;

	if (mvsw_pr_fi_is_direct(fib_cache->fi)) {
		fib_nh = fib_info_nh(fib_cache->fi, 0);
		mvsw_pr_util_kern_set_nh_offload(fib_nh, true);
		goto out;
	}

	for (i = 0; i < MVSW_PR_NHGR_SIZE_MAX; i++) {
		n_cache = fib_cache->kern_neigh_cache_head[i].n_cache;
		if (n_cache) {
			list_del(&fib_cache->kern_neigh_cache_head[i].head);
			mvsw_pr_kern_neigh_cache_put(sw, n_cache);
			fib_nh = fib_info_nh(fib_cache->fi, i);
			mvsw_pr_util_kern_set_nh_offload(fib_nh, false);
		}
	}

out:
	fib_info_put(fib_cache->fi);
}

static void
mvsw_pr_kern_fib_cache_offload_set(struct mvsw_pr_switch *sw,
				   struct mvsw_pr_kern_fib_cache *fib_cache)
{
	int i;
	struct mvsw_pr_kern_neigh_cache *n_cache;
	struct fib_nh *fib_nh;
	bool offloaded;

	if (mvsw_pr_fi_is_direct(fib_cache->fi)) {
		fib_nh = fib_info_nh(fib_cache->fi, 0);
		if (mvsw_pr_rif_find(sw, fib_nh->fib_nh_dev))
			mvsw_pr_util_kern_set_nh_offload(fib_nh, true);
		goto out;
	}

	for (i = 0; i < MVSW_PR_NHGR_SIZE_MAX; i++) {
		n_cache = fib_cache->kern_neigh_cache_head[i].n_cache;
		if (!n_cache)
			continue;

		offloaded = n_cache->offloaded;
		fib_nh = fib_info_nh(fib_cache->fi, i);
		mvsw_pr_util_kern_set_nh_offload(fib_nh, offloaded);
	}

out:
	return;
}

static void
mvsw_pr_kern_fib_cache_destroy(struct mvsw_pr_switch *sw,
			       struct mvsw_pr_kern_fib_cache *fib_cache)
{
	__mvsw_pr_kern_fib_cache_destruct(sw, fib_cache);
	rhashtable_remove_fast(&sw->router->kern_fib_cache_ht,
			       &fib_cache->ht_node,
			       __mvsw_pr_kern_fib_cache_ht_params);
	kfree(fib_cache);
}

static void
mvsw_pr_kern_fib_cache_destroy_ht(struct mvsw_pr_switch *sw)
{
	struct mvsw_pr_kern_fib_cache *fib_cache, *tfib_cache;
	struct rhashtable_iter iter;

	tfib_cache = NULL;
	rhashtable_walk_enter(&sw->router->kern_fib_cache_ht, &iter);
	rhashtable_walk_start(&iter);
	while (1) {
		fib_cache = rhashtable_walk_next(&iter);
		if (tfib_cache) {
			rhashtable_remove_fast(&sw->router->kern_fib_cache_ht,
					       &tfib_cache->ht_node,
					    __mvsw_pr_kern_fib_cache_ht_params);
			kfree(tfib_cache);
			tfib_cache = NULL;
		}

		if (!fib_cache)
			break;

		if (IS_ERR(fib_cache))
			continue;

		__mvsw_pr_kern_fib_cache_destruct(sw, fib_cache);
		tfib_cache = fib_cache;
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
}

static struct mvsw_pr_kern_fib_cache *
mvsw_pr_kern_fib_cache_create(struct mvsw_pr_switch *sw,
			      struct mvsw_pr_fib_key *key,
			      struct fib_info *fi)
{
	struct mvsw_pr_kern_fib_cache *fib_cache;
	struct mvsw_pr_kern_neigh_cache *n_cache;
	struct mvsw_pr_nh_neigh_key nh_key;
	struct fib_nh *fib_nh;
	int err, i, nhs;

	fib_cache = kzalloc(sizeof(*fib_cache), GFP_KERNEL);
	if (!fib_cache)
		goto err_kzalloc;

	memcpy(&fib_cache->key, key, sizeof(*key));
	fib_info_hold(fi);
	fib_cache->fi = fi;

	err = rhashtable_insert_fast(&sw->router->kern_fib_cache_ht,
				     &fib_cache->ht_node,
				     __mvsw_pr_kern_fib_cache_ht_params);
	if (err)
		goto err_ht_insert;

	if (!mvsw_pr_fi_is_nh(fi))
		goto out;

	nhs = fib_info_num_path(fi);
	for (i = 0; i < nhs; i++) {
		fib_nh = fib_info_nh(fi, i);
		err = mvsw_pr_util_fib_nh2nh_neigh_key(sw, fib_nh, &nh_key);
		if (err)
			continue;

		n_cache = mvsw_pr_kern_neigh_cache_get(sw, &nh_key);
		if (!n_cache)
			continue;

		fib_cache->kern_neigh_cache_head[i].this = fib_cache;
		fib_cache->kern_neigh_cache_head[i].n_cache = n_cache;
		list_add(&fib_cache->kern_neigh_cache_head[i].head,
			 &n_cache->kern_fib_cache_list);
	}

out:
	mvsw_pr_kern_fib_cache_offload_set(sw, fib_cache);

	return fib_cache;

err_ht_insert:
	fib_info_put(fi);
	kfree(fib_cache);
err_kzalloc:
	return NULL;
}

static int mvsw_pr_util_neigh2nh_neigh_key(struct mvsw_pr_switch *sw,
					   struct neighbour *n,
					   struct mvsw_pr_nh_neigh_key *key)
{
	memset(key, 0, sizeof(*key));
	key->addr.u.ipv4 = *(__be32 *)n->primary_key;
	key->rif = mvsw_pr_rif_find(sw, n->dev);
	if (!key->rif)
		return -ENOENT;

	return 0;
}

static void __mvsw_pr_neigh2nh_neigh_update(struct mvsw_pr_switch *sw,
					    struct neighbour *n)
{
	struct mvsw_pr_nh_neigh_key nh_neigh_key;
	struct mvsw_pr_nh_neigh *nh_neigh;
	struct mvsw_pr_neigh_info new_info;
	struct mvsw_pr_kern_neigh_cache *n_cache;
	bool offloaded;
	int err;

	err = mvsw_pr_util_neigh2nh_neigh_key(sw, n, &nh_neigh_key);
	if (err)
		return;

	nh_neigh = mvsw_pr_nh_neigh_find(sw, &nh_neigh_key);
	if (!nh_neigh)
		return;

	memset(&new_info, 0, sizeof(new_info));
	read_lock_bh(&n->lock);
	if (n->nud_state & NUD_VALID && !n->dead) {
		memcpy(&new_info.ha[0], &n->ha[0], ETH_ALEN);
		err = mvsw_pr_neigh_iface_init(sw, &new_info.iface, n);
		if (err) {
			MVSW_LOG_ERROR("Cannot initialize iface for %pI4n %pM",
				       n->primary_key, &n->ha[0]);
			new_info.connected = false;
		} else {
			new_info.connected = true;
		}
	} else {
		new_info.connected = false;
	}
	read_unlock_bh(&n->lock);

	offloaded = new_info.connected;
	/* Do hw update only if something changed to prevent nh flap */
	if (memcmp(&new_info, &nh_neigh->info, sizeof(new_info))) {
		memcpy(&nh_neigh->info, &new_info, sizeof(new_info));
		err = mvsw_pr_nh_neigh_set(sw, nh_neigh);
		if (err) {
			offloaded = false;
			MVSW_LOG_ERROR("%s failed with err=%d ip=%pI4n mac=%pM",
				       "mvsw_pr_nh_neigh_set", err,
				       &nh_neigh->key.addr.u.ipv4,
				       &nh_neigh->info.ha[0]);
		}
	}

	mvsw_pr_util_kern_set_neigh_offload(n, offloaded);
	n_cache = mvsw_pr_kern_neigh_cache_find(sw, &nh_neigh_key);
	if (!n_cache) {
		MVSW_LOG_ERROR("Cannot get neigh cache for %pI4n %pM",
			       n->primary_key, &n->ha[0]);
	} else {
		n_cache->offloaded = offloaded;
		mvsw_pr_kern_neigh_cache_offload_set(sw, n_cache);
	}
}

static void __mvsw_pr_neigh2nh_neigh_update_all(struct mvsw_pr_switch *sw)
{
	struct mvsw_pr_nh_neigh *nh_neigh;
	struct rhashtable_iter iter;
	struct neighbour *n;
	struct mvsw_pr_nh_neigh_key *nkey;

	rhashtable_walk_enter(&sw->router->nh_neigh_ht, &iter);
	rhashtable_walk_start(&iter);
	while ((nh_neigh = rhashtable_walk_next(&iter))) {
		if (IS_ERR(nh_neigh))
			continue;

		nkey = &nh_neigh->key;
		n = neigh_lookup(&arp_tbl, &nkey->addr.u.ipv4, nkey->rif->dev);
		if (n) {
			__mvsw_pr_neigh2nh_neigh_update(sw, n);
			neigh_release(n);
		}
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
}

/* I dont think that optimiztaion of this
 * function withone neighbour will make sense...
 * Just select direction nh_neigh -> kernel or vice versa
 */
static void
__mvsw_pr_neigh_hwstate_update_all(struct mvsw_pr_switch *sw)
{
	struct mvsw_pr_nh_neigh *nh_neigh;
	struct rhashtable_iter iter;
	struct neighbour *n;
	struct mvsw_pr_nh_neigh_key *nkey;
	bool n_resolved, hw_active;

	rhashtable_walk_enter(&sw->router->nh_neigh_ht, &iter);
	rhashtable_walk_start(&iter);
	while ((nh_neigh = rhashtable_walk_next(&iter))) {
		if (IS_ERR(nh_neigh))
			continue;

		hw_active = mvsw_pr_nh_neigh_util_hw_state(sw, nh_neigh);
		nkey = &nh_neigh->key;
		n = neigh_lookup(&arp_tbl, &nkey->addr.u.ipv4, nkey->rif->dev);
		if (n) {
			read_lock_bh(&n->lock);
			if (n->dead || !(n->nud_state & NUD_VALID))
				n_resolved = false;
			else
				n_resolved = true;
			read_unlock_bh(&n->lock);
		} else {
			n_resolved = false;
		}

#ifdef MVSW_PR_IMPLICITY_RESOLVE_DEAD_NEIGH
		if (!hw_active && n_resolved)
			goto next_nh_neigh;
#else /* MVSW_PR_IMPLICITY_RESOLVE_DEAD_NEIGH */
		if (!hw_active)
			goto next_nh_neigh;
#endif /* MVSW_PR_IMPLICITY_RESOLVE_DEAD_NEIGH */

		if (!n) {
			MVSW_LOG_INFO("Push active neighbour %pI4n to kernel",
				      &nkey->addr.u.ipv4);
			n = neigh_create(&arp_tbl, &nkey->addr.u.ipv4,
					 nkey->rif->dev);
			if (IS_ERR(n)) {
				n = NULL;
				MVSW_LOG_ERROR("Cannot create neighbour %pI4n",
					       &nkey->addr.u.ipv4);

				goto next_nh_neigh;
			}
		}

		neigh_event_send(n, NULL);

next_nh_neigh:
		if (n)
			neigh_release(n);
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
}

static void
__mvsw_pr_sync_neigh_cache_kernel(struct mvsw_pr_switch *sw,
				  struct mvsw_pr_kern_neigh_cache *n_cache)
{
	struct neighbour *n;
	struct fib_result res;
	struct fib_nh *fib_nh;
	struct mvsw_pr_nh_neigh_key *key;

	key = &n_cache->key;

	n_cache->in_kernel = false;
	n_cache->lpm_added = false;
	n = neigh_lookup(&arp_tbl, &key->addr.u.ipv4, key->rif->dev);
	if (n) {
		read_lock_bh(&n->lock);
		if (!n->dead && (n->nud_state & NUD_VALID))
			n_cache->in_kernel = true;
		read_unlock_bh(&n->lock);
	}

	if (n_cache->in_kernel) {
		if (!mvsw_pr_util_kern_get_route(&res, key->rif->vr->tb_id,
						 &key->addr))
			if (res.type == RTN_UNICAST &&
			    mvsw_pr_fi_is_direct(res.fi)) {
				fib_nh = fib_info_nh(res.fi, 0);
				if (n->dev == fib_nh->fib_nh_dev)
					n_cache->lpm_added = true;
			}
	}

	if (n)
		neigh_release(n);

	mvsw_pr_kern_neigh_cache_lpm_set(sw, n_cache);
}

static void __mvsw_pr_sync_neigh_cache_kernel_all(struct mvsw_pr_switch *sw)
{
	struct mvsw_pr_kern_neigh_cache *n_cache, *tn_cache;
	struct rhashtable_iter iter;

	tn_cache = NULL;
	rhashtable_walk_enter(&sw->router->kern_neigh_cache_ht, &iter);
	rhashtable_walk_start(&iter);
	while (1) {
		n_cache = rhashtable_walk_next(&iter);
		if (tn_cache) {
			mvsw_pr_kern_neigh_cache_put(sw, tn_cache);
			tn_cache = NULL;
		}

		if (!n_cache)
			break;

		if (IS_ERR(n_cache))
			continue;

		__mvsw_pr_sync_neigh_cache_kernel(sw, n_cache);
		tn_cache = n_cache;
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
}

/* Propagate kernel event to hw */
static void mvsw_pr_neigh_arbiter_n_evt(struct mvsw_pr_switch *sw,
					struct neighbour *n)
{
	struct mvsw_pr_kern_neigh_cache *n_cache;
	struct mvsw_pr_nh_neigh_key n_key;
	int err;

	err = mvsw_pr_util_neigh2nh_neigh_key(sw, n, &n_key);
	if (err)
		return;

	n_cache = mvsw_pr_kern_neigh_cache_get(sw, &n_key);
	if (!n_cache)
		return;

	__mvsw_pr_sync_neigh_cache_kernel(sw, n_cache);
	mvsw_pr_kern_neigh_cache_put(sw, n_cache);

	__mvsw_pr_neigh2nh_neigh_update(sw, n);
}

/* Propagate hw state to kernel */
static void mvsw_pr_neigh_arbiter_hw_evt(struct mvsw_pr_switch *sw)
{
	__mvsw_pr_neigh_hwstate_update_all(sw);
}

/* Propagate fib changes to hw neighs */
static void
mvsw_pr_neigh_arbiter_fib_evt(struct mvsw_pr_switch *sw,
			      bool replace, /* replace or del */
			      struct mvsw_pr_fib_key *fib_key,
			      struct fib_info *fi)
{
	struct mvsw_pr_kern_fib_cache *fib_cache;

	fib_cache = mvsw_pr_kern_fib_cache_find(sw, fib_key);
		if (fib_cache)
			mvsw_pr_kern_fib_cache_destroy(sw, fib_cache);

	/* TODO: add util function IS_NH / IS_DIR */
	if (replace) {
		fib_cache = mvsw_pr_kern_fib_cache_create(sw, fib_key, fi);
		if (!fib_cache)
			MVSW_LOG_ERROR("%s failed for %pI4n",
				       "mvsw_pr_kern_fib_cache_create",
				       &fib_key->addr.u.ipv4);
	}

	__mvsw_pr_sync_neigh_cache_kernel_all(sw);
	__mvsw_pr_neigh2nh_neigh_update_all(sw);
}

struct mvsw_pr_netevent_work {
	struct work_struct work;
	struct mvsw_pr_switch *sw;
	struct neighbour *n;
};

static void mvsw_pr_router_neigh_event_work(struct work_struct *work)
{
	struct mvsw_pr_netevent_work *net_work =
		container_of(work, struct mvsw_pr_netevent_work, work);
	struct mvsw_pr_switch *sw = net_work->sw;
	struct neighbour *n = net_work->n;

	/* neigh - its not hw related object. It stored only in kernel. So... */
	mvsw_owq_lock();

	if (sw->router->aborted)
		goto out;

	mvsw_pr_neigh_arbiter_n_evt(sw, n);

out:
	neigh_release(n);
	mvsw_owq_unlock();
	kfree(net_work);
}

static int mvsw_pr_router_netevent_event(struct notifier_block *nb,
					 unsigned long event, void *ptr)
{
	struct mvsw_pr_netevent_work *net_work;
	struct mvsw_pr_router *router;
	struct mvsw_pr_rif *rif;
	struct neighbour *n = ptr;

	router = container_of(nb, struct mvsw_pr_router, netevent_nb);

	switch (event) {
	case NETEVENT_NEIGH_UPDATE:
		if (n->tbl != &arp_tbl)
			return NOTIFY_DONE;

		rif = mvsw_pr_rif_find(router->sw, n->dev);
		if (!rif)
			return NOTIFY_DONE;

		net_work = kzalloc(sizeof(*net_work), GFP_ATOMIC);
		if (WARN_ON(!net_work))
			return NOTIFY_BAD;

		neigh_clone(n);
		net_work->n = n;
		net_work->sw = router->sw;
		INIT_WORK(&net_work->work, mvsw_pr_router_neigh_event_work);
		queue_work(mvsw_r_owq, &net_work->work);
	}

	return NOTIFY_DONE;
}

static void
mvsw_pr_router_neighs_update_interval_init(struct mvsw_pr_router *router)
{
	router->neighs_update.interval = MVSW_PR_NH_PROBE_INTERVAL;
}

static void mvsw_pr_router_update_neighs_work(struct work_struct *work)
{
	struct mvsw_pr_router *router;

	router = container_of(work, struct mvsw_pr_router,
			      neighs_update.dw.work);
	rtnl_lock();

	if (router->aborted)
		goto out;

	mvsw_pr_neigh_arbiter_hw_evt(router->sw);

out:
	rtnl_unlock();
	mvsw_pr_router_neighs_update_interval_init(router);
	queue_delayed_work(mvsw_r_wq, &router->neighs_update.dw,
			   msecs_to_jiffies(router->neighs_update.interval));
}

static int mvsw_pr_neigh_init(struct mvsw_pr_switch *sw)
{
	int err;

	err = rhashtable_init(&sw->router->nh_neigh_ht,
			      &__mvsw_pr_nh_neigh_ht_params);
	if (err)
		return err;

	mvsw_pr_router_neighs_update_interval_init(sw->router);

	INIT_DELAYED_WORK(&sw->router->neighs_update.dw,
			  mvsw_pr_router_update_neighs_work);
	queue_delayed_work(mvsw_r_wq, &sw->router->neighs_update.dw, 0);
	return 0;
}

static void mvsw_pr_neigh_fini(struct mvsw_pr_switch *sw)
{
	cancel_delayed_work_sync(&sw->router->neighs_update.dw);
	rhashtable_destroy(&sw->router->nh_neigh_ht);
}

static struct mvsw_pr_rif*
mvsw_pr_rif_find(const struct mvsw_pr_switch *sw,
		 const struct net_device *dev)
{
	struct mvsw_pr_rif *rif;

	list_for_each_entry(rif, &sw->router->rif_list, router_node) {
		if (rif->dev == dev)
			return rif;
	}

	return NULL;
}

bool mvsw_pr_rif_exists(const struct mvsw_pr_switch *sw,
			const struct net_device *dev)
{
	return !!mvsw_pr_rif_find(sw, dev);
}

static int
mvsw_pr_port_vlan_router_join(struct mvsw_pr_port_vlan *mvsw_pr_port_vlan,
			      struct net_device *dev,
			      struct netlink_ext_ack *extack)
{
	struct mvsw_pr_port *mvsw_pr_port = mvsw_pr_port_vlan->mvsw_pr_port;
	struct mvsw_pr_switch *sw = mvsw_pr_port->sw;

	struct mvsw_pr_rif_params params = {
		.dev = dev,
	};
	struct mvsw_pr_rif *rif;

	MVSW_LOG_ERROR("NOT IMPLEMENTED!!!");

	rif = mvsw_pr_rif_find(sw, dev);
	if (!rif)
		rif = mvsw_pr_rif_create(sw, &params, extack);

	if (IS_ERR(rif))
		return PTR_ERR(rif);

	rif->is_active = true;

	/* TODO:
	 * - vid learning set (false)
	 * - stp state set (FORWARDING)
	 */

	return 0;
}

static void
mvsw_pr_port_vlan_router_leave(struct mvsw_pr_port_vlan *mvsw_pr_port_vlan,
			       struct net_device *dev)

{
	struct mvsw_pr_port *mvsw_pr_port = mvsw_pr_port_vlan->mvsw_pr_port;
	struct mvsw_pr_switch *sw = mvsw_pr_port->sw;
	struct mvsw_pr_rif *rif;

	rif = mvsw_pr_rif_find(sw, dev);

	if (rif)
		rif->is_active = false;
	/* TODO:
	 * - stp state set (BLOCKING)
	 * - vid learning set (true)
	 */
}

static int
mvsw_pr_port_router_join(struct mvsw_pr_port *mvsw_pr_port,
			 struct net_device *dev,
			 struct netlink_ext_ack *extack)
{
	struct mvsw_pr_switch *sw = mvsw_pr_port->sw;

	struct mvsw_pr_rif_params params = {
		.dev = dev,
	};
	struct mvsw_pr_rif *rif;

	rif = mvsw_pr_rif_find(sw, dev);
	if (!rif)
		rif = mvsw_pr_rif_create(sw, &params, extack);

	if (IS_ERR(rif))
		return PTR_ERR(rif);

	rif->is_active = true;

	/* TODO:
	 * - vid learning set (false)
	 * - stp state set (FORWARDING)
	 */

	return 0;
}

void mvsw_pr_port_router_leave(struct mvsw_pr_port *mvsw_pr_port)
{
	struct mvsw_pr_rif *rif;

	/* TODO:
	 * - stp state set (BLOCKING)
	 * - vid learning set (true)
	 */

	rif = mvsw_pr_rif_find(mvsw_pr_port->sw, mvsw_pr_port->net_dev);
	if (rif) {
		rif->is_active = false;
		mvsw_pr_rif_put(rif);
	}
}

static int mvsw_pr_rif_fdb_op(struct mvsw_pr_rif *rif, const char *mac,
			      bool adding)
{
	if (adding)
		mvsw_pr_macvlan_add(rif->sw, mvsw_pr_rif_vr_id(rif), mac,
				    rif->iface.vlan_id);
	else
		mvsw_pr_macvlan_del(rif->sw, mvsw_pr_rif_vr_id(rif), mac,
				    rif->iface.vlan_id);

	return 0;
}

static int mvsw_pr_rif_macvlan_add(struct mvsw_pr_switch *sw,
				   const struct net_device *macvlan_dev,
				   struct netlink_ext_ack *extack)
{
	struct macvlan_dev *vlan = netdev_priv(macvlan_dev);
	struct mvsw_pr_rif *rif;
	int err;

	rif = mvsw_pr_rif_find(sw, vlan->lowerdev);
	if (!rif) {
		NL_SET_ERR_MSG_MOD(extack,
				   "macvlan is only supported on top of RIF");
		return -EOPNOTSUPP;
	}

	err = mvsw_pr_rif_fdb_op(rif, macvlan_dev->dev_addr, true);
	if (err)
		return err;

	return err;
}

static void __mvsw_pr_rif_macvlan_del(struct mvsw_pr_switch *sw,
				      const struct net_device *macvlan_dev)
{
	struct macvlan_dev *vlan = netdev_priv(macvlan_dev);
	struct mvsw_pr_rif *rif;

	rif = mvsw_pr_rif_find(sw, vlan->lowerdev);
	if (!rif)
		return;

	mvsw_pr_rif_fdb_op(rif, macvlan_dev->dev_addr,  false);
}

static void mvsw_pr_rif_macvlan_del(struct mvsw_pr_switch *sw,
				    const struct net_device *macvlan_dev)
{
	__mvsw_pr_rif_macvlan_del(sw, macvlan_dev);
}

static int mvsw_pr_inetaddr_macvlan_event(struct mvsw_pr_switch *sw,
					  struct net_device *macvlan_dev,
					  unsigned long event,
					  struct netlink_ext_ack *extack)
{
	switch (event) {
	case NETDEV_UP:
		return mvsw_pr_rif_macvlan_add(sw, macvlan_dev, extack);
	case NETDEV_DOWN:
		mvsw_pr_rif_macvlan_del(sw, macvlan_dev);
		break;
	}

	return 0;
}

static int mvsw_pr_router_port_check_rif_addr(struct mvsw_pr_switch *sw,
					      struct net_device *dev,
					      const unsigned char *dev_addr,
					      struct netlink_ext_ack *extack)
{
	if (netif_is_macvlan(dev) || netif_is_l3_master(dev))
		return 0;

	if (!ether_addr_equal_masked(sw->base_mac, dev_addr,
				     mvsw_pr_mac_mask)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "RIF MAC must have the same prefix");
		return -EINVAL;
	}

	return 0;
}

static int mvsw_pr_inetaddr_port_event(struct net_device *port_dev,
				       unsigned long event,
				       struct netlink_ext_ack *extack)
{
	struct mvsw_pr_port *mvsw_pr_port = netdev_priv(port_dev);

	MVSW_LOG_ERROR("dev=%s", port_dev->name);

	switch (event) {
	case NETDEV_UP:
		if (netif_is_bridge_port(port_dev) ||
		    netif_is_lag_port(port_dev) || netif_is_ovs_port(port_dev))
			return 0;
		return mvsw_pr_port_router_join(mvsw_pr_port, port_dev, extack);
	case NETDEV_DOWN:
		mvsw_pr_port_router_leave(mvsw_pr_port);
		break;
	}

	return 0;
}

static int mvsw_pr_inetaddr_bridge_event(struct mvsw_pr_switch *sw,
					 struct net_device *dev,
					 unsigned long event,
					 struct netlink_ext_ack *extack)
{
	struct mvsw_pr_rif_params params = {
		.dev = dev,
	};
	struct mvsw_pr_rif *rif;

	switch (event) {
	case NETDEV_UP:
		rif = mvsw_pr_rif_find(sw, dev);
		if (!rif)
			rif = mvsw_pr_rif_create(sw, &params, extack);

		if (IS_ERR(rif))
			return PTR_ERR(rif);
		rif->is_active = true;
		break;
	case NETDEV_DOWN:
		rif = mvsw_pr_rif_find(sw, dev);
		rif->is_active = false;
		mvsw_pr_rif_put(rif);
		break;
	}

	return 0;
}

static int mvsw_pr_inetaddr_port_vlan_event(struct net_device *l3_dev,
					    struct net_device *port_dev,
					    unsigned long event, u16 vid,
					    struct netlink_ext_ack *extack)
{
	struct mvsw_pr_port *mvsw_pr_port = netdev_priv(port_dev);
	struct mvsw_pr_port_vlan *mvsw_pr_port_vlan;

	mvsw_pr_port_vlan = mvsw_pr_port_vlan_find_by_vid(mvsw_pr_port, vid);
	if (WARN_ON(!mvsw_pr_port_vlan))
		return -EINVAL;

	switch (event) {
	case NETDEV_UP:
		return mvsw_pr_port_vlan_router_join(mvsw_pr_port_vlan,
						     l3_dev, extack);
	case NETDEV_DOWN:
		mvsw_pr_port_vlan_router_leave(mvsw_pr_port_vlan, l3_dev);
		break;
	}

	return 0;
}

static int mvsw_pr_inetaddr_vlan_event(struct mvsw_pr_switch *sw,
				       struct net_device *vlan_dev,
				       unsigned long event,
				       struct netlink_ext_ack *extack)
{
	struct net_device *real_dev = vlan_dev_real_dev(vlan_dev);
	u16 vid = vlan_dev_vlan_id(vlan_dev);

	MVSW_LOG_ERROR("vlan_dev=%s, real_dev=%s", vlan_dev->name,
		       real_dev->name);
	if (netif_is_bridge_port(vlan_dev))
		return 0;

	if (mvsw_pr_netdev_check(real_dev))
		return mvsw_pr_inetaddr_port_vlan_event(vlan_dev, real_dev,
							event, vid, extack);
	else if (netif_is_bridge_master(real_dev) && br_vlan_enabled(real_dev))
		return mvsw_pr_inetaddr_bridge_event(sw, vlan_dev, event,
						     extack);

	return 0;
}

static int mvsw_pr_inetaddr_lag_event(struct mvsw_pr_switch *sw,
				      struct net_device *lag_dev,
				      unsigned long event,
				      struct netlink_ext_ack *extack)
{
	struct mvsw_pr_rif_params params = {
		.dev = lag_dev,
	};
	struct mvsw_pr_rif *rif;

	MVSW_LOG_ERROR("lag_dev=%s", lag_dev->name);

	switch (event) {
	case NETDEV_UP:
		rif = mvsw_pr_rif_find(sw, lag_dev);
		if (!rif)
			rif = mvsw_pr_rif_create(sw, &params, extack);

		if (IS_ERR(rif))
			return PTR_ERR(rif);
		rif->is_active = true;
		break;
	case NETDEV_DOWN:
		rif = mvsw_pr_rif_find(sw, lag_dev);
		rif->is_active = false;
		mvsw_pr_rif_put(rif);
		break;
	}

	return 0;
}

static int __mvsw_pr_inetaddr_event(struct mvsw_pr_switch *sw,
				    struct net_device *dev,
				    unsigned long event,
				    struct netlink_ext_ack *extack)
{
	if (mvsw_pr_netdev_check(dev))
		return mvsw_pr_inetaddr_port_event(dev, event, extack);
	else if (is_vlan_dev(dev))
		return mvsw_pr_inetaddr_vlan_event(sw, dev, event, extack);
	else if (netif_is_bridge_master(dev))
		return mvsw_pr_inetaddr_bridge_event(sw, dev, event, extack);
	else if (netif_is_lag_master(dev))
		return mvsw_pr_inetaddr_lag_event(sw, dev, event, extack);
	else if (netif_is_macvlan(dev))
		return mvsw_pr_inetaddr_macvlan_event(sw, dev, event, extack);
	else
		return 0;
}

static bool
mvsw_pr_rif_should_config(struct mvsw_pr_rif *rif, struct net_device *dev,
			  unsigned long event)
{
	bool addr_list_empty = true;
	struct in_device *idev;

	switch (event) {
	case NETDEV_UP:
		return !rif;
	case NETDEV_DOWN:
		idev = __in_dev_get_rtnl(dev);
		if (idev && idev->ifa_list)
			addr_list_empty = false;

		if (netif_is_macvlan(dev) && addr_list_empty)
			return true;

		if (rif && addr_list_empty)
			return true;

		return false;
	}

	return false;
}

static int mvsw_pr_inetaddr_event(struct notifier_block *nb,
				  unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net_device *dev = ifa->ifa_dev->dev;
	struct mvsw_pr_router *router;
	struct mvsw_pr_switch *sw;
	struct mvsw_pr_rif *rif;
	int err = 0;

	/* Wait until previously created works finished (e.g. neigh events) */
	mvsw_owq_flush();
	/* NETDEV_UP event is handled by mvsw_pr_inetaddr_valid_event */
	if (event == NETDEV_UP)
		goto out;

	MVSW_LOG_ERROR("dev=%s", dev->name);
	router = container_of(nb, struct mvsw_pr_router, inetaddr_nb);
	sw = router->sw;

	if (netif_is_macvlan(dev))
		goto mac_vlan;

	rif = mvsw_pr_rif_find(sw, dev);
	if (!rif)
		goto out;

	if (!mvsw_pr_rif_should_config(rif, dev, event))
		goto out;
mac_vlan:
	err = __mvsw_pr_inetaddr_event(sw, dev, event, NULL);
out:
	return notifier_from_errno(err);
}

int mvsw_pr_inetaddr_valid_event(struct notifier_block *unused,
				 unsigned long event, void *ptr)
{
	struct in_validator_info *ivi = (struct in_validator_info *)ptr;
	struct net_device *dev = ivi->ivi_dev->dev;
	struct mvsw_pr_switch *sw;
	struct mvsw_pr_rif *rif;
	int err = 0;

	sw = mvsw_pr_switch_get(dev);
	if (!sw)
		goto out;

	/* Wait until previously created works finished (e.g. neigh events) */
	mvsw_owq_flush();

	if (ipv4_is_multicast(ivi->ivi_addr))
		return notifier_from_errno(-EINVAL);

	rif = mvsw_pr_rif_find(sw, dev);
	if (!mvsw_pr_rif_should_config(rif, dev, event))
		goto out;

	err = mvsw_pr_router_port_check_rif_addr(sw, dev, dev->dev_addr,
						 ivi->extack);
	if (err)
		goto out;

	err = __mvsw_pr_inetaddr_event(sw, dev, event, ivi->extack);
out:
	return notifier_from_errno(err);
}

static bool __mvsw_pr_fi_is_direct(struct fib_info *fi)
{
	struct fib_nh *fib_nh;

	if (fib_info_num_path(fi) == 1) {
		fib_nh = fib_info_nh(fi, 0);
		if (fib_nh->fib_nh_scope == RT_SCOPE_HOST)
			return true;
	}

	return false;
}

static bool mvsw_pr_fi_is_direct(struct fib_info *fi)
{
	if (fi->fib_type != RTN_UNICAST)
		return false;

	return __mvsw_pr_fi_is_direct(fi);
}

static bool mvsw_pr_fi_is_nh(struct fib_info *fi)
{
	if (fi->fib_type != RTN_UNICAST)
		return false;

	return !__mvsw_pr_fi_is_direct(fi);
}

static void __mvsw_pr_nh_neigh_destroy(struct mvsw_pr_switch *sw,
				       struct mvsw_pr_nh_neigh *neigh)
{
	neigh->key.rif->ref_cnt--;
	mvsw_pr_rif_put(neigh->key.rif);
	rhashtable_remove_fast(&sw->router->nh_neigh_ht,
			       &neigh->ht_node,
			       __mvsw_pr_nh_neigh_ht_params);
	kfree(neigh);
}

static struct mvsw_pr_nh_neigh *
__mvsw_pr_nh_neigh_create(struct mvsw_pr_switch *sw,
			  struct mvsw_pr_nh_neigh_key *key)
{
	struct mvsw_pr_nh_neigh *neigh;
	int err;

	neigh = kzalloc(sizeof(*neigh), GFP_KERNEL);
	if (!neigh)
		goto err_kzalloc;

	memcpy(&neigh->key, key, sizeof(*key));
	neigh->key.rif->ref_cnt++;
	neigh->info.connected = false;
	INIT_LIST_HEAD(&neigh->nexthop_group_list);
	err = rhashtable_insert_fast(&sw->router->nh_neigh_ht,
				     &neigh->ht_node,
				     __mvsw_pr_nh_neigh_ht_params);
	if (err)
		goto err_rhashtable_insert;

	return neigh;

err_rhashtable_insert:
	kfree(neigh);
err_kzalloc:
	return NULL;
}

static struct mvsw_pr_nh_neigh *
mvsw_pr_nh_neigh_find(struct mvsw_pr_switch *sw,
		      struct mvsw_pr_nh_neigh_key *key)
{
	struct mvsw_pr_nh_neigh *nh_neigh;

	nh_neigh = rhashtable_lookup_fast(&sw->router->nh_neigh_ht,
					  key, __mvsw_pr_nh_neigh_ht_params);
	return IS_ERR(nh_neigh) ? NULL : nh_neigh;
}

static struct mvsw_pr_nh_neigh *
mvsw_pr_nh_neigh_get(struct mvsw_pr_switch *sw,
		     struct mvsw_pr_nh_neigh_key *key)
{
	struct mvsw_pr_nh_neigh *neigh;

	neigh = mvsw_pr_nh_neigh_find(sw, key);
	if (!neigh)
		return __mvsw_pr_nh_neigh_create(sw, key);

	return neigh;
}

static void mvsw_pr_nh_neigh_put(struct mvsw_pr_switch *sw,
				 struct mvsw_pr_nh_neigh *neigh)
{
	if (list_empty(&neigh->nexthop_group_list))
		__mvsw_pr_nh_neigh_destroy(sw, neigh);
}

/* Updates new mvsw_pr_neigh_info */
static int mvsw_pr_nh_neigh_set(struct mvsw_pr_switch *sw,
				struct mvsw_pr_nh_neigh *neigh)
{
	struct mvsw_pr_nh_neigh_head *nh_head;
	struct mvsw_pr_nexthop_group *nh_grp;
	int err;

	list_for_each_entry(nh_head, &neigh->nexthop_group_list, head) {
		nh_grp = nh_head->this;
		err = mvsw_pr_nexthop_group_set(sw, nh_grp);
		if (err)
			return err;
	}

	return 0;
}

static bool __mvsw_pr_nh_neigh_key_is_valid(struct mvsw_pr_nh_neigh_key *key)
{
	return memchr_inv(key, 0, sizeof(*key)) ? true : false;
}

static bool
mvsw_pr_nh_neigh_util_hw_state(struct mvsw_pr_switch *sw,
			       struct mvsw_pr_nh_neigh *nh_neigh)
{
	bool state;
	struct mvsw_pr_nh_neigh_head *nh_head, *tmp;

	state = false;
	list_for_each_entry_safe(nh_head, tmp,
				 &nh_neigh->nexthop_group_list, head) {
		state = mvsw_pr_nexthop_group_util_hw_state(sw, nh_head->this);
		if (state)
			break;
	}

	return state;
}

static size_t
__mvsw_pr_nexthop_group_key_size(struct mvsw_pr_nexthop_group_key *key)
{
	size_t nh_cnt;

	for (nh_cnt = 0; nh_cnt < MVSW_PR_NHGR_SIZE_MAX; nh_cnt++) {
		if (!__mvsw_pr_nh_neigh_key_is_valid(&key->neigh[nh_cnt]))
			break;
	}

	return nh_cnt;
}

static struct mvsw_pr_nexthop_group *
__mvsw_pr_nexthop_group_create(struct mvsw_pr_switch *sw,
			       struct mvsw_pr_nexthop_group_key *key)
{
	struct mvsw_pr_nexthop_group *nh_grp;
	struct mvsw_pr_nh_neigh *nh_neigh;
	int nh_cnt, err;

	nh_grp = kzalloc(sizeof(*nh_grp), GFP_KERNEL);
	if (!nh_grp)
		goto err_kzalloc;

	memcpy(&nh_grp->key, key, sizeof(*key));
	for (nh_cnt = 0; nh_cnt < MVSW_PR_NHGR_SIZE_MAX; nh_cnt++) {
		if (!__mvsw_pr_nh_neigh_key_is_valid(&nh_grp->key.neigh[nh_cnt])
		   )
			break;

		nh_neigh = mvsw_pr_nh_neigh_get(sw, &nh_grp->key.neigh[nh_cnt]);
		if (!nh_neigh)
			goto err_nh_neigh_get;

		nh_grp->nh_neigh_head[nh_cnt].neigh = nh_neigh;
		nh_grp->nh_neigh_head[nh_cnt].this = nh_grp;
		list_add(&nh_grp->nh_neigh_head[nh_cnt].head,
			 &nh_neigh->nexthop_group_list);
	}

	err = mvsw_pr_nh_group_create(sw, nh_cnt, &nh_grp->grp_id);
	if (err)
		goto err_nh_group_create;

	err = mvsw_pr_nexthop_group_set(sw, nh_grp);
	if (err)
		goto err_nexthop_group_set;

	err = rhashtable_insert_fast(&sw->router->nexthop_group_ht,
				     &nh_grp->ht_node,
				     __mvsw_pr_nexthop_group_ht_params);
	if (err)
		goto err_ht_insert;

	return nh_grp;

err_ht_insert:
err_nexthop_group_set:
	mvsw_pr_nh_group_delete(sw, nh_cnt, nh_grp->grp_id);
err_nh_group_create:
err_nh_neigh_get:
	for (nh_cnt--; nh_cnt >= 0; nh_cnt--) {
		list_del(&nh_grp->nh_neigh_head[nh_cnt].head);
		mvsw_pr_nh_neigh_put(sw, nh_grp->nh_neigh_head[nh_cnt].neigh);
	}

	kfree(nh_grp);
err_kzalloc:
	return NULL;
}

static void
__mvsw_pr_nexthop_group_destroy(struct mvsw_pr_switch *sw,
				struct mvsw_pr_nexthop_group *nh_grp)
{
	struct mvsw_pr_nh_neigh *nh_neigh;
	int nh_cnt;

	rhashtable_remove_fast(&sw->router->nexthop_group_ht,
			       &nh_grp->ht_node,
			       __mvsw_pr_nexthop_group_ht_params);

	for (nh_cnt = 0; nh_cnt < MVSW_PR_NHGR_SIZE_MAX; nh_cnt++) {
		nh_neigh = nh_grp->nh_neigh_head[nh_cnt].neigh;
		if (!nh_neigh)
			break;

		list_del(&nh_grp->nh_neigh_head[nh_cnt].head);
		mvsw_pr_nh_neigh_put(sw, nh_neigh);
	}

	mvsw_pr_nh_group_delete(sw, nh_cnt, nh_grp->grp_id);
	kfree(nh_grp);
}

static struct mvsw_pr_nexthop_group *
mvsw_pr_nexthop_group_find(struct mvsw_pr_switch *sw,
			   struct mvsw_pr_nexthop_group_key *key)
{
	struct mvsw_pr_nexthop_group *nh_grp;

	nh_grp = rhashtable_lookup_fast(&sw->router->nexthop_group_ht,
					key, __mvsw_pr_nexthop_group_ht_params);
	return IS_ERR(nh_grp) ? NULL : nh_grp;
}

static struct mvsw_pr_nexthop_group *
mvsw_pr_nexthop_group_get(struct mvsw_pr_switch *sw,
			  struct mvsw_pr_nexthop_group_key *key)
{
	struct mvsw_pr_nexthop_group *nh_grp;

	nh_grp = mvsw_pr_nexthop_group_find(sw, key);
	if (!nh_grp)
		return __mvsw_pr_nexthop_group_create(sw, key);

	return nh_grp;
}

static void mvsw_pr_nexthop_group_put(struct mvsw_pr_switch *sw,
				      struct mvsw_pr_nexthop_group *nh_grp)
{
	if (!nh_grp->ref_cnt)
		__mvsw_pr_nexthop_group_destroy(sw, nh_grp);
}

/* Updates with new nh_neigh's info */
static int mvsw_pr_nexthop_group_set(struct mvsw_pr_switch *sw,
				     struct mvsw_pr_nexthop_group *nh_grp)
{
	struct mvsw_pr_neigh_info info[MVSW_PR_NHGR_SIZE_MAX];
	struct mvsw_pr_nh_neigh *neigh;
	int nh_cnt;

	memset(&info[0], 0, sizeof(info));
	for (nh_cnt = 0; nh_cnt < MVSW_PR_NHGR_SIZE_MAX; nh_cnt++) {
		neigh = nh_grp->nh_neigh_head[nh_cnt].neigh;
		if (!neigh)
			break;

		memcpy(&info[nh_cnt], &neigh->info, sizeof(neigh->info));
	}

	return mvsw_pr_nh_entries_set(sw, nh_cnt, &info[0], nh_grp->grp_id);
}

static bool
mvsw_pr_nexthop_group_util_hw_state(struct mvsw_pr_switch *sw,
				    struct mvsw_pr_nexthop_group *nh_grp)
{
	int err, nh_cnt;
	struct mvsw_pr_neigh_info info[MVSW_PR_NHGR_SIZE_MAX];
	size_t grp_size;

	/* Antijitter
	 * Prevent situation, when we read state of nh_grp twice in short time,
	 * and state bit is still cleared on second call. So just stuck active
	 * state for MVSW_PR_NH_ACTIVE_JIFFER_FILTER, after last occurred.
	 */
	if (time_before(jiffies, nh_grp->hw_last_connected +
			msecs_to_jiffies(MVSW_PR_NH_ACTIVE_JIFFER_FILTER)))
		return true;

	grp_size =  __mvsw_pr_nexthop_group_key_size(&nh_grp->key);
	err = mvsw_pr_nh_entries_get(sw, grp_size, &info[0], nh_grp->grp_id);
	if (err) {
		MVSW_LOG_ERROR("Failed to get hw state of nh_grp %d",
			       nh_grp->grp_id);
		return false;
	}

	for (nh_cnt = 0; nh_cnt < grp_size; nh_cnt++)
		if (info[nh_cnt].connected) {
			nh_grp->hw_last_connected = jiffies;
			return true;
		}

	return false;
}

static struct mvsw_pr_fib_node *
mvsw_pr_fib_node_find(struct mvsw_pr_switch *sw, struct mvsw_pr_fib_key *key)
{
	struct mvsw_pr_fib_node *fib_node;

	fib_node = rhashtable_lookup_fast(&sw->router->fib_ht, key,
					  __mvsw_pr_fib_ht_params);
	return IS_ERR(fib_node) ? NULL : fib_node;
}

static void __mvsw_pr_fib_node_destruct(struct mvsw_pr_switch *sw,
					struct mvsw_pr_fib_node *fib_node)
{
	struct mvsw_pr_vr *vr;

	vr = fib_node->info.vr;
	mvsw_pr_lpm_del(sw, vr->hw_vr_id, &fib_node->key.addr,
			fib_node->key.prefix_len);
	switch (fib_node->info.type) {
	case MVSW_PR_FIB_TYPE_UC_NH:
		fib_node->info.nh_grp->ref_cnt--;
		mvsw_pr_nexthop_group_put(sw, fib_node->info.nh_grp);
		break;
	case MVSW_PR_FIB_TYPE_TRAP:
		break;
	case MVSW_PR_FIB_TYPE_DROP:
		break;
	default:
	      MVSW_LOG_ERROR("Unknown fib_node->info.type = %d",
			     fib_node->info.type);
	}

	vr->ref_cnt--;
	mvsw_pr_vr_put(sw, vr);
}

static void mvsw_pr_fib_node_destroy(struct mvsw_pr_switch *sw,
				     struct mvsw_pr_fib_node *fib_node)
{
	__mvsw_pr_fib_node_destruct(sw, fib_node);
	rhashtable_remove_fast(&sw->router->fib_ht, &fib_node->ht_node,
			       __mvsw_pr_fib_ht_params);
	kfree(fib_node);
}

static void mvsw_pr_fib_node_destroy_ht(struct mvsw_pr_switch *sw)
{
	struct mvsw_pr_fib_node *node, *tnode;
	struct rhashtable_iter iter;

	tnode = NULL;
	rhashtable_walk_enter(&sw->router->fib_ht, &iter);
	rhashtable_walk_start(&iter);
	while (1) {
		node = rhashtable_walk_next(&iter);
		if (tnode) {
			rhashtable_remove_fast(&sw->router->fib_ht,
					       &tnode->ht_node,
					       __mvsw_pr_fib_ht_params);
			kfree(tnode);
			tnode = NULL;
		}

		if (!node)
			break;

		if (IS_ERR(node))
			continue;

		__mvsw_pr_fib_node_destruct(sw, node);
		tnode = node;
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
}

static struct mvsw_pr_fib_node *
mvsw_pr_fib_node_uc_nh_create(struct mvsw_pr_switch *sw,
			      struct mvsw_pr_fib_key *key,
			      struct mvsw_pr_nexthop_group_key *nh_grp_key)
{
	struct mvsw_pr_fib_node *fib_node;
	struct mvsw_pr_nexthop_group *nh_grp;
	struct mvsw_pr_vr *vr;
	int err;

	fib_node = kzalloc(sizeof(*fib_node), GFP_KERNEL);
	if (!fib_node)
		goto err_kzalloc;

	memcpy(&fib_node->key, key, sizeof(*key));
	fib_node->info.type = MVSW_PR_FIB_TYPE_UC_NH;

	vr = mvsw_pr_vr_get(sw, key->tb_id, NULL);
	if (!vr)
		goto err_vr_get;

	fib_node->info.vr = vr;
	vr->ref_cnt++;

	nh_grp = mvsw_pr_nexthop_group_get(sw, nh_grp_key);
	if (!nh_grp)
		goto err_nh_grp_get;

	fib_node->info.nh_grp = nh_grp;
	nh_grp->ref_cnt++;

	err = mvsw_pr_lpm_add(sw, vr->hw_vr_id, &key->addr,
			      key->prefix_len, nh_grp->grp_id);
	if (err)
		goto err_lpm_add;

	err = rhashtable_insert_fast(&sw->router->fib_ht, &fib_node->ht_node,
				     __mvsw_pr_fib_ht_params);
	if (err)
		goto err_ht_insert;

	return fib_node;

err_ht_insert:
	mvsw_pr_lpm_del(sw, vr->hw_vr_id, &key->addr, key->prefix_len);
err_lpm_add:
	nh_grp->ref_cnt--;
	mvsw_pr_nexthop_group_put(sw, nh_grp);
err_nh_grp_get:
	vr->ref_cnt--;
	mvsw_pr_vr_put(sw, vr);
err_vr_get:
	kfree(fib_node);
err_kzalloc:
	return NULL;
}

/* Decided, that uc_nh route with key==nh is obviously neighbour route */
static bool
mvsw_pr_fib_node_util_is_neighbour(struct mvsw_pr_fib_node *fib_node)
{
	if (fib_node->info.type != MVSW_PR_FIB_TYPE_UC_NH)
		return false;

	if (fib_node->info.nh_grp->nh_neigh_head[1].neigh)
		return false;

	if (!fib_node->info.nh_grp->nh_neigh_head[0].neigh)
		return false;

	if (memcmp(&fib_node->info.nh_grp->nh_neigh_head[0].neigh->key.addr,
		   &fib_node->key.addr, sizeof(struct mvsw_pr_ip_addr)))
		return false;

	return true;
}

static struct mvsw_pr_fib_node *
mvsw_pr_fib_node_trap_create(struct mvsw_pr_switch *sw,
			     struct mvsw_pr_fib_key *key)
{
	struct mvsw_pr_fib_node *fib_node;
	struct mvsw_pr_vr *vr;
	int err;

	fib_node = kzalloc(sizeof(*fib_node), GFP_KERNEL);
	if (!fib_node)
		goto err_kzalloc;

	vr = mvsw_pr_vr_get(sw, key->tb_id, NULL);
	if (!vr)
		goto err_vr_get;

	fib_node->info.vr = vr;
	vr->ref_cnt++;

	memcpy(&fib_node->key, key, sizeof(*key));
	fib_node->info.type = MVSW_PR_FIB_TYPE_TRAP;
	err = mvsw_pr_lpm_add(sw, vr->hw_vr_id, &key->addr,
			      key->prefix_len, MVSW_PR_NHGR_UNUSED);
	if (err)
		goto err_lpm_add;

	err = rhashtable_insert_fast(&sw->router->fib_ht, &fib_node->ht_node,
				     __mvsw_pr_fib_ht_params);
	if (err)
		goto err_ht_insert;

	return fib_node;

err_ht_insert:
	mvsw_pr_lpm_del(sw, vr->hw_vr_id, &key->addr, key->prefix_len);
err_lpm_add:
	vr->ref_cnt--;
	mvsw_pr_vr_put(sw, vr);
err_vr_get:
	kfree(fib_node);
err_kzalloc:
	return NULL;
}

static struct mvsw_pr_fib_node *
mvsw_pr_fib_node_drop_create(struct mvsw_pr_switch *sw,
			     struct mvsw_pr_fib_key *key)
{
	struct mvsw_pr_fib_node *fib_node;
	struct mvsw_pr_vr *vr;
	int err;

	fib_node = kzalloc(sizeof(*fib_node), GFP_KERNEL);
	if (!fib_node)
		goto err_kzalloc;

	vr = mvsw_pr_vr_get(sw, key->tb_id, NULL);
	if (!vr)
		goto err_vr_get;

	fib_node->info.vr = vr;
	vr->ref_cnt++;

	memcpy(&fib_node->key, key, sizeof(*key));
	fib_node->info.type = MVSW_PR_FIB_TYPE_DROP;
	err = mvsw_pr_lpm_add(sw, vr->hw_vr_id,
			      &key->addr, key->prefix_len, MVSW_PR_NHGR_DROP);
	if (err)
		goto err_lpm_add;

	err = rhashtable_insert_fast(&sw->router->fib_ht, &fib_node->ht_node,
				     __mvsw_pr_fib_ht_params);
	if (err)
		goto err_ht_insert;

	return fib_node;

err_ht_insert:
	mvsw_pr_lpm_del(sw, vr->hw_vr_id,
			&key->addr, key->prefix_len);
err_lpm_add:
	vr->ref_cnt--;
	mvsw_pr_vr_put(sw, vr);
err_vr_get:
	kfree(fib_node);
err_kzalloc:
	return NULL;
}

static void mvsw_pr_fib_nh_del2nh_neigh_set(struct mvsw_pr_switch *sw,
					    struct fib_nh *fib_nh)
{
	struct mvsw_pr_nh_neigh_key nh_neigh_key;
	struct mvsw_pr_nh_neigh *nh_neigh;

	memset(&nh_neigh_key, 0, sizeof(nh_neigh_key));
	nh_neigh_key.addr.u.ipv4 = fib_nh->fib_nh_gw4;
	nh_neigh_key.rif = mvsw_pr_rif_find(sw, fib_nh->fib_nh_dev);
	if (!nh_neigh_key.rif)
		return;

	nh_neigh = mvsw_pr_nh_neigh_find(sw, &nh_neigh_key);
	if (!nh_neigh)
		return;

	nh_neigh->info.connected = false;
	mvsw_pr_nh_neigh_set(sw, nh_neigh);
}

static void __mvsw_pr_fen_info2fib_key(struct fib_entry_notifier_info *fen_info,
				       struct mvsw_pr_fib_key *key)
{
	memset(key, 0, sizeof(*key));
	key->addr.u.ipv4 = cpu_to_be32(fen_info->dst);
	key->prefix_len = fen_info->dst_len;
	key->tb_id = mvsw_pr_fix_tb_id(fen_info->tb_id);
}

static int
mvsw_pr_fi2nh_gr_key(struct mvsw_pr_switch *sw, struct fib_info *fi,
		     size_t limit, struct mvsw_pr_nexthop_group_key *grp_key)
{
	int i, nhs, err;
	struct fib_nh *fib_nh;

	nhs = fib_info_num_path(fi);
	if (nhs > limit)
		return 0;

	memset(grp_key, 0, sizeof(*grp_key));
	for (i = 0; i < nhs; i++) {
		fib_nh = fib_info_nh(fi, i);
		err = mvsw_pr_util_fib_nh2nh_neigh_key(sw,
						       fib_nh,
						       &grp_key->neigh[i]);
		if (err)
			return 0;
	}

	return nhs;
}

static int
mvsw_pr_router_fib_replace(struct mvsw_pr_switch *sw,
			   struct fib_entry_notifier_info *fen_info)
{
	struct mvsw_pr_fib_node *fib_node;
	struct mvsw_pr_fib_key fib_key;
	struct mvsw_pr_nexthop_group_key nh_grp_key;
	int nh_cnt;

	__mvsw_pr_fen_info2fib_key(fen_info, &fib_key);

	fib_node = mvsw_pr_fib_node_find(sw, &fib_key);
	if (fib_node) {
		MVSW_LOG_INFO("fib_node found. destroy.");
		mvsw_pr_fib_node_destroy(sw, fib_node);
	}

	/* TODO: fib lookup here to check if another route with the same key
	 * is occurred in another kernel's table
	 */
	switch (fen_info->fi->fib_type) {
	case RTN_UNICAST:
		if (mvsw_pr_fi_is_nh(fen_info->fi))
			nh_cnt = mvsw_pr_fi2nh_gr_key(sw, fen_info->fi,
						      MVSW_PR_NHGR_SIZE_MAX,
						      &nh_grp_key);
		else
			nh_cnt = 0;

		if (nh_cnt) {
			fib_node = mvsw_pr_fib_node_uc_nh_create(sw, &fib_key,
								 &nh_grp_key);
		} else {
			fib_node = mvsw_pr_fib_node_trap_create(sw, &fib_key);
		}

		if (!fib_node)
			goto err_fib_create;

		break;
	/* Unsupported. Leave it for kernel: */
	case RTN_BROADCAST:
	case RTN_MULTICAST:
	/* Routes we must trap by design: */
	case RTN_LOCAL:
	case RTN_UNREACHABLE:
	case RTN_PROHIBIT:
		fib_node = mvsw_pr_fib_node_trap_create(sw, &fib_key);
		if (!fib_node)
			goto err_fib_create;
		break;
	case RTN_BLACKHOLE:
		fib_node = mvsw_pr_fib_node_drop_create(sw, &fib_key);
		if (!fib_node)
			goto err_fib_create;

		break;
	default:
		goto err_type;
	}

	mvsw_pr_neigh_arbiter_fib_evt(sw, true, &fib_key, fen_info->fi);

	return 0;

err_fib_create:
	MVSW_LOG_ERROR("fib_create failed");
	goto err_out;
err_type:
	MVSW_LOG_ERROR("Invalid fen_info->fi->fib_type %d",
		       fen_info->fi->fib_type);
	goto err_out;
err_out:
	MVSW_LOG_ERROR("Error when processing %pI4h/%d", &fen_info->dst,
		       fen_info->dst_len);
	return -EINVAL;
}

static void mvsw_pr_router_fib_del(struct mvsw_pr_switch *sw,
				   struct fib_entry_notifier_info *fen_info)
{
	struct mvsw_pr_fib_node *fib_node;
	struct mvsw_pr_fib_key fib_key;

	/* TODO: fib lookup here to check if another route with the same key
	 * is occurred in another kernel's table
	 */
	__mvsw_pr_fen_info2fib_key(fen_info, &fib_key);

	fib_node = mvsw_pr_fib_node_find(sw, &fib_key);
	if (fib_node) {
		mvsw_pr_fib_node_destroy(sw, fib_node);
	} else {
		MVSW_LOG_ERROR("Cant find fib_node");
		goto err_out;
	}

	mvsw_pr_neigh_arbiter_fib_evt(sw, false, &fib_key, fen_info->fi);

	return;

err_out:
	MVSW_LOG_ERROR("Error when processing %pI4h/%d", &fen_info->dst,
		       fen_info->dst_len);
}

static void mvsw_pr_router_fib_abort(struct mvsw_pr_switch *sw)
{
	mvsw_pr_vr_util_hw_abort(sw);
	mvsw_pr_fib_node_destroy_ht(sw);
	mvsw_pr_kern_fib_cache_destroy_ht(sw);
	mvsw_pr_util_kern_unset_allneigh_offload();
}

struct mvsw_pr_fib_event_work {
	struct work_struct work;
	struct mvsw_pr_switch *sw;
	union {
		struct fib_entry_notifier_info fen_info;
		struct fib_nh_notifier_info fnh_info;
	};
	unsigned long event;
};

static void mvsw_pr_router_fib4_event_work(struct work_struct *work)
{
	struct mvsw_pr_fib_event_work *fib_work =
			container_of(work, struct mvsw_pr_fib_event_work, work);
	struct mvsw_pr_switch *sw = fib_work->sw;
	int err;

	mvsw_owq_lock();

	if (sw->router->aborted)
		goto out;

	switch (fib_work->event) {
	case FIB_EVENT_ENTRY_REPLACE:
		err = mvsw_pr_router_fib_replace(sw,
						 &fib_work->fen_info);
		if (err)
			goto abort_out;
		break;
	case FIB_EVENT_ENTRY_DEL:
		mvsw_pr_router_fib_del(sw, &fib_work->fen_info);
		break;
	}

	goto out;

abort_out:
	sw->router->aborted = true;
	mvsw_pr_router_fib_abort(sw);
	dev_err(sw->dev->dev, "Abort. HW routing offloading disabled");
out:
	fib_info_put(fib_work->fen_info.fi);
	mvsw_owq_unlock();
	kfree(fib_work);
}

static void mvsw_pr_router_nh_update_event_work(struct work_struct *work)
{
	struct mvsw_pr_fib_event_work *fib_work =
			container_of(work, struct mvsw_pr_fib_event_work, work);
	struct mvsw_pr_switch *sw = fib_work->sw;
	struct fib_nh *fib_nh = fib_work->fnh_info.fib_nh;

	mvsw_owq_lock();

	if (sw->router->aborted)
		goto out;

	/* For now provided only deletion */
	if (fib_work->event == FIB_EVENT_NH_DEL)
		mvsw_pr_fib_nh_del2nh_neigh_set(sw, fib_nh);

out:
	fib_info_put(fib_nh->nh_parent);
	mvsw_owq_unlock();
	kfree(fib_work);
	return;
}

/* Called with rcu_read_lock() */
static int mvsw_pr_router_fib_event(struct notifier_block *nb,
				    unsigned long event, void *ptr)
{
	struct fib_entry_notifier_info *fen_info;
	struct fib_nh_notifier_info *fnh_info;
	struct fib_notifier_info *info = ptr;
	struct mvsw_pr_fib_event_work *fib_work;
	struct mvsw_pr_router *router;
	struct fib_info *fi;

	if (info->family != AF_INET)
		return NOTIFY_DONE;

	router = container_of(nb, struct mvsw_pr_router, fib_nb);

	switch (event) {
	case FIB_EVENT_ENTRY_REPLACE:
	case FIB_EVENT_ENTRY_DEL:
		fen_info = container_of(info, struct fib_entry_notifier_info,
					info);
		if (!fen_info->fi)
			return NOTIFY_DONE;
		else
			fi = fen_info->fi;

		/* Sanity */
		if (event == FIB_EVENT_ENTRY_REPLACE) {
			if (fi->nh)
				return notifier_from_errno(-EINVAL);

			if (fi->fib_nh_is_v6)
				return notifier_from_errno(-EINVAL);

			if (fib_info_num_path(fi) > MVSW_PR_NHGR_SIZE_MAX) {
				NL_SET_ERR_MSG_MOD(info->extack,
						   "Exceeded number of nexthops per route"
						   );
				return notifier_from_errno(-EINVAL);
			}
		}

		fib_work = kzalloc(sizeof(*fib_work), GFP_ATOMIC);
		if (WARN_ON(!fib_work))
			return NOTIFY_BAD;

		fib_info_hold(fi);
		fib_work->fen_info = *fen_info;
		fib_work->event = event;
		fib_work->sw = router->sw;
		INIT_WORK(&fib_work->work, mvsw_pr_router_fib4_event_work);
		queue_work(mvsw_r_owq, &fib_work->work);
		break;
	case FIB_EVENT_NH_DEL:
		/* Set down nh as fast as possible */
		fnh_info = container_of(info, struct fib_nh_notifier_info,
					info);
		if (!fnh_info->fib_nh->nh_parent)
			return NOTIFY_DONE;

		fi = fnh_info->fib_nh->nh_parent;

		fib_work = kzalloc(sizeof(*fib_work), GFP_ATOMIC);
		if (WARN_ON(!fib_work))
			return NOTIFY_BAD;

		fib_info_hold(fi);
		fib_work->fnh_info = *fnh_info;
		fib_work->event = event;
		fib_work->sw = router->sw;
		INIT_WORK(&fib_work->work, mvsw_pr_router_nh_update_event_work);
		queue_work(mvsw_r_owq, &fib_work->work);
		break;
	default:
		return NOTIFY_DONE;
	}

	return NOTIFY_DONE;
}

static void mvsw_pr_router_fib_dump_flush(struct notifier_block *nb)
{
	struct mvsw_pr_router *router;

	/* Flush pending FIB notifications and then flush the device's
	 * table before requesting another dump. The FIB notification
	 * block is unregistered, so no need to take RTNL.
	 * No neighbours are expected to be present since FIBs  are not
	 * registered yet
	 */
	router = container_of(nb, struct mvsw_pr_router, fib_nb);
	flush_workqueue(mvsw_r_owq);
	flush_workqueue(mvsw_r_wq);
	mvsw_pr_fib_node_destroy_ht(router->sw);
}

static int
mvsw_pr_router_port_change(struct mvsw_pr_rif *rif)
{
	struct net_device *dev = rif->dev;
	int err;

	err = mvsw_pr_rif_update(rif, dev->dev_addr);
	if (err)
		return err;

	ether_addr_copy(rif->addr, dev->dev_addr);
	rif->mtu = dev->mtu;

	netdev_dbg(dev, "Updated RIF=%d\n", rif->rif_id);

	return 0;
}

static int
mvsw_pr_router_port_pre_change(struct mvsw_pr_rif *rif,
			       struct netdev_notifier_pre_changeaddr_info *info)
{
	struct netlink_ext_ack *extack;

	extack = netdev_notifier_info_to_extack(&info->info);
	return mvsw_pr_router_port_check_rif_addr(rif->sw, rif->dev,
						  info->dev_addr, extack);
}

int mvsw_pr_netdevice_router_port_event(struct net_device *dev,
					unsigned long event, void *ptr)
{
	struct mvsw_pr_switch *sw;
	struct mvsw_pr_rif *rif;

	sw = mvsw_pr_switch_get(dev);
	if (!sw)
		return 0;

	rif = mvsw_pr_rif_find(sw, dev);
	if (!rif)
		return 0;

	switch (event) {
	case NETDEV_CHANGEADDR:
		return mvsw_pr_router_port_change(rif);
	case NETDEV_PRE_CHANGEADDR:
		return mvsw_pr_router_port_pre_change(rif, ptr);
	}

	return 0;
}

static int mvsw_pr_port_vrf_join(struct mvsw_pr_switch *sw,
				 struct net_device *dev,
				 struct netlink_ext_ack *extack)
{
	struct mvsw_pr_rif *rif;

	/* If netdev is already associated with a RIF, then we need to
	 * destroy it and create a new one with the new virtual router ID.
	 */
	rif = mvsw_pr_rif_find(sw, dev);
	if (rif)
		__mvsw_pr_inetaddr_event(sw, dev, NETDEV_DOWN, extack);

	__mvsw_pr_inetaddr_event(sw, dev, NETDEV_UP, extack);
	rif = mvsw_pr_rif_find(sw, dev);
	return mvsw_pr_rif_vr_update(sw, rif, extack);
}

static void mvsw_pr_port_vrf_leave(struct mvsw_pr_switch *sw,
				   struct net_device *dev,
				   struct netlink_ext_ack *extack)
{
	struct mvsw_pr_rif *rif;
	struct in_device *idev;

	rif = mvsw_pr_rif_find(sw, dev);
	if (!rif)
		return;

	__mvsw_pr_inetaddr_event(sw, dev, NETDEV_DOWN, NULL);

	rif = mvsw_pr_rif_find(sw, dev);
	if (rif)
		mvsw_pr_rif_vr_update(sw, rif, extack);

	idev = __in_dev_get_rtnl(dev);
	/* Restore rif in the default vrf: do so only if IF address's present*/
	if (idev && idev->ifa_list)
		__mvsw_pr_inetaddr_event(sw, dev, NETDEV_UP, NULL);
}

int mvsw_pr_netdevice_vrf_event(struct net_device *dev, unsigned long event,
				struct netdev_notifier_changeupper_info *info)
{
	struct mvsw_pr_switch *sw = mvsw_pr_switch_get(dev);
	struct netlink_ext_ack *extack = NULL;
	int err = 0;

	if (!sw || netif_is_macvlan(dev))
		return 0;

	switch (event) {
	case NETDEV_PRECHANGEUPPER:
		return 0;
	case NETDEV_CHANGEUPPER:
		extack = netdev_notifier_info_to_extack(&info->info);
		if (info->linking)
			err = mvsw_pr_port_vrf_join(sw, dev, extack);
		else
			mvsw_pr_port_vrf_leave(sw, dev, extack);
		break;
	}

	return err;
}

static int __mvsw_pr_rif_macvlan_flush(struct net_device *dev,
				       struct netdev_nested_priv *priv)
{
	struct mvsw_pr_rif *rif = priv->data;

	if (!netif_is_macvlan(dev))
		return 0;

	return mvsw_pr_rif_fdb_op(rif, dev->dev_addr, false);
}

static int mvsw_pr_rif_macvlan_flush(struct mvsw_pr_rif *rif)
{
	struct netdev_nested_priv priv = {
		.data = (void *)rif,
	};

	if (!netif_is_macvlan_port(rif->dev))
		return 0;

	netdev_warn(rif->dev,
		    "Router interface is deleted. Upper macvlans will not work\n");
	return netdev_walk_all_upper_dev_rcu(rif->dev,
					     __mvsw_pr_rif_macvlan_flush, &priv);
}

#ifdef CONFIG_IP_ROUTE_MULTIPATH
static int mvsw_pr_mp_hash_init(struct mvsw_pr_switch *sw)
{
	u8 hash_policy;

	hash_policy = init_net.ipv4.sysctl_fib_multipath_hash_policy;
	return  mvsw_pr_mp4_hash_set(sw, hash_policy);
}
#else
static int mvsw_pr_mp_hash_init(struct mvsw_pr_switch *sw)
{
	return 0;
}
#endif

static struct notifier_block mvsw_pr_inetaddr_valid_nb __read_mostly = {
	.notifier_call = mvsw_pr_inetaddr_valid_event,
};

int mvsw_pr_router_init(struct mvsw_pr_switch *sw)
{
	struct mvsw_pr_router *router;
	int err;

	router = kzalloc(sizeof(*sw->router), GFP_KERNEL);
	if (!router)
		return -ENOMEM;
	sw->router = router;
	router->sw = sw;

	err = mvsw_pr_mp_hash_init(sw);
	if (err)
		goto err_mp_hash_init;

	err = rhashtable_init(&router->nexthop_group_ht,
			      &__mvsw_pr_nexthop_group_ht_params);
	if (err)
		goto err_nexthop_grp_ht_init;

	err = rhashtable_init(&router->fib_ht,
			      &__mvsw_pr_fib_ht_params);
	if (err)
		goto err_fib_ht_init;

	err = rhashtable_init(&router->kern_fib_cache_ht,
			      &__mvsw_pr_kern_fib_cache_ht_params);
	if (err)
		goto err_kern_fib_cache_ht_init;

	err = rhashtable_init(&router->kern_neigh_cache_ht,
			      &__mvsw_pr_kern_neigh_cache_ht_params);
	if (err)
		goto err_kern_neigh_cache_ht_init;

	INIT_LIST_HEAD(&sw->router->rif_list);
	INIT_LIST_HEAD(&sw->router->vr_list);

	mvsw_r_wq = alloc_workqueue(mvsw_driver_name, 0, 0);
	if (!mvsw_r_wq) {
		err = -ENOMEM;
		goto err_alloc_workqueue;
	}

	mvsw_r_owq = alloc_ordered_workqueue("%s_ordered", 0, "mvsw_prestera");
	if (!mvsw_r_owq) {
		err = -ENOMEM;
		goto err_alloc_oworkqueue;
	}

	err = register_inetaddr_validator_notifier(&mvsw_pr_inetaddr_valid_nb);
	if (err)
		goto err_register_inetaddr_validator_notifier;

	router->inetaddr_nb.notifier_call = mvsw_pr_inetaddr_event;
	err = register_inetaddr_notifier(&router->inetaddr_nb);
	if (err)
		goto err_register_inetaddr_notifier;

	err = mvsw_pr_neigh_init(sw);
	if (err)
		goto err_neigh_init;

	sw->router->netevent_nb.notifier_call = mvsw_pr_router_netevent_event;
	err = register_netevent_notifier(&sw->router->netevent_nb);
	if (err)
		goto err_register_netevent_notifier;

	sw->router->fib_nb.notifier_call = mvsw_pr_router_fib_event;
	err = register_fib_notifier(&init_net, &sw->router->fib_nb,
				    mvsw_pr_router_fib_dump_flush, NULL);
	if (err)
		goto err_register_fib_notifier;

	return 0;

err_register_fib_notifier:
	unregister_netevent_notifier(&sw->router->netevent_nb);
err_register_netevent_notifier:
	mvsw_pr_neigh_fini(sw);
err_neigh_init:
	unregister_inetaddr_notifier(&router->inetaddr_nb);
err_register_inetaddr_notifier:
	unregister_inetaddr_validator_notifier(&mvsw_pr_inetaddr_valid_nb);
err_register_inetaddr_validator_notifier:
	destroy_workqueue(mvsw_r_owq);
err_alloc_oworkqueue:
	destroy_workqueue(mvsw_r_wq);
err_alloc_workqueue:
	rhashtable_destroy(&router->kern_neigh_cache_ht);
err_kern_neigh_cache_ht_init:
	rhashtable_destroy(&router->kern_fib_cache_ht);
err_kern_fib_cache_ht_init:
	rhashtable_destroy(&router->fib_ht);
err_fib_ht_init:
	rhashtable_destroy(&router->nexthop_group_ht);
err_nexthop_grp_ht_init:
err_mp_hash_init:
	kfree(sw->router);
	return err;
}

static void mvsw_pr_rifs_fini(struct mvsw_pr_switch *sw)
{
	struct mvsw_pr_rif *rif, *tmp;

	list_for_each_entry_safe(rif, tmp, &sw->router->rif_list, router_node) {
		rif->is_active = false;
		mvsw_pr_rif_destroy(rif);
	}
}

void mvsw_pr_router_fini(struct mvsw_pr_switch *sw)
{
	unregister_fib_notifier(&init_net, &sw->router->fib_nb);
	unregister_netevent_notifier(&sw->router->netevent_nb);
	mvsw_pr_neigh_fini(sw);
	/* TODO: check if vrs necessary ? */
	mvsw_pr_rifs_fini(sw);
	unregister_inetaddr_notifier(&sw->router->inetaddr_nb);
	unregister_inetaddr_validator_notifier(&mvsw_pr_inetaddr_valid_nb);

	rhashtable_destroy(&sw->router->fib_ht);
	rhashtable_destroy(&sw->router->nexthop_group_ht);

	flush_workqueue(mvsw_r_wq);
	flush_workqueue(mvsw_r_owq);
	destroy_workqueue(mvsw_r_wq);
	destroy_workqueue(mvsw_r_owq);

	WARN_ON(!list_empty(&sw->router->rif_list));

	kfree(sw->router);
	sw->router = NULL;
}

static u32 mvsw_pr_fix_tb_id(u32 tb_id)
{
	if (tb_id == RT_TABLE_UNSPEC ||
	    tb_id == RT_TABLE_LOCAL ||
	    tb_id == RT_TABLE_DEFAULT)
		return tb_id = RT_TABLE_MAIN;

	return tb_id;
}

static struct mvsw_pr_vr *__mvsw_pr_vr_find(struct mvsw_pr_switch *sw,
					    u32 tb_id)
{
	struct mvsw_pr_vr *vr;

	list_for_each_entry(vr, &sw->router->vr_list, router_node) {
		if (vr->tb_id == tb_id)
			return vr;
	}

	return NULL;
}

static struct mvsw_pr_vr *__mvsw_pr_vr_create(struct mvsw_pr_switch *sw,
					      u32 tb_id,
					      struct netlink_ext_ack *extack)
{
	struct mvsw_pr_vr *vr;
	u16 hw_vr_id;
	int err;

	err = mvsw_pr_hw_vr_create(sw, &hw_vr_id);
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
	mvsw_pr_hw_vr_delete(sw, hw_vr_id);
	kfree(vr);
	return ERR_PTR(err);
}

static void __mvsw_pr_vr_destroy(struct mvsw_pr_switch *sw,
				 struct mvsw_pr_vr *vr)
{
	mvsw_pr_hw_vr_delete(sw, vr->hw_vr_id);
	list_del(&vr->router_node);
	kfree(vr);
}

static struct mvsw_pr_vr *mvsw_pr_vr_get(struct mvsw_pr_switch *sw, u32 tb_id,
					 struct netlink_ext_ack *extack)
{
	struct mvsw_pr_vr *vr;

	vr = __mvsw_pr_vr_find(sw, tb_id);
	if (!vr)
		vr = __mvsw_pr_vr_create(sw, tb_id, extack);
	if (IS_ERR(vr))
		return ERR_CAST(vr);

	return vr;
}

static void mvsw_pr_vr_put(struct mvsw_pr_switch *sw, struct mvsw_pr_vr *vr)
{
	if (!vr->ref_cnt)
		__mvsw_pr_vr_destroy(sw, vr);
}

static void mvsw_pr_vr_util_hw_abort(struct mvsw_pr_switch *sw)
{
	struct mvsw_pr_vr *vr, *vr_tmp;

	list_for_each_entry_safe(vr, vr_tmp,
				 &sw->router->vr_list, router_node)
		mvsw_pr_hw_vr_abort(sw, vr->hw_vr_id);
}

static struct mvsw_pr_rif*
mvsw_pr_rif_alloc(struct mvsw_pr_switch *sw,
		  struct mvsw_pr_vr *vr,
		  const struct mvsw_pr_rif_params *params)
{
	struct mvsw_pr_rif *rif;
	int err;

	rif = kzalloc(sizeof(*rif), GFP_KERNEL);
	if (!rif) {
		err = -ENOMEM;
		goto err_rif_alloc;
	}

	rif->sw = sw;
	rif->vr = vr;
	rif->dev = params->dev;
	err = mvsw_pr_rif_iface_init(rif);
	if (err)
		goto err_rif_iface_init;

	ether_addr_copy(rif->addr, params->dev->dev_addr);
	rif->mtu = params->dev->mtu;

	return rif;

err_rif_iface_init:
	kfree(rif);
err_rif_alloc:
	return ERR_PTR(err);
}

static int mvsw_pr_rif_offload(struct mvsw_pr_rif *rif)
{
	return mvsw_pr_hw_rif_create(rif->sw, &rif->iface, rif->addr,
				     &rif->rif_id);
}

static struct mvsw_pr_rif *mvsw_pr_rif_create(struct mvsw_pr_switch *sw,
					      const struct mvsw_pr_rif_params
					      *params,
					      struct netlink_ext_ack *extack)
{
	u32 tb_id = mvsw_pr_fix_tb_id(l3mdev_fib_table(params->dev));
	struct mvsw_pr_rif *rif;
	struct mvsw_pr_vr *vr;
	int err;

	vr = mvsw_pr_vr_get(sw, tb_id, extack);
	if (IS_ERR(vr))
		return ERR_CAST(vr);

	rif = mvsw_pr_rif_alloc(sw, vr, params);
	if (IS_ERR(rif)) {
		mvsw_pr_vr_put(sw, vr);
		return rif;
	}

	err = mvsw_pr_rif_offload(rif);
	if (err)  {
		NL_SET_ERR_MSG_MOD(extack,
				   "Exceeded number of supported rifs");
		goto err_rif_offload;
	}

	vr->ref_cnt++;
	dev_hold(rif->dev);
	list_add(&rif->router_node, &sw->router->rif_list);

	return rif;

err_rif_offload:
	kfree(rif);
	return ERR_PTR(err);
}

static int mvsw_pr_rif_delete(struct mvsw_pr_rif *rif)
{
	return mvsw_pr_hw_rif_delete(rif->sw, rif->rif_id, &rif->iface);
}

static void mvsw_pr_rif_destroy(struct mvsw_pr_rif *rif)
{
	mvsw_pr_rif_macvlan_flush(rif);
	if (!rif->is_active) {
		mvsw_pr_rif_delete(rif);
		list_del(&rif->router_node);
		dev_put(rif->dev);
		rif->vr->ref_cnt--;
		mvsw_pr_vr_put(rif->sw, rif->vr);
		kfree(rif);
	}
}

static void mvsw_pr_rif_put(struct mvsw_pr_rif *rif)
{
	if (!rif->ref_cnt)
		mvsw_pr_rif_destroy(rif);
}

void mvsw_pr_rif_enable(struct mvsw_pr_switch *sw,
			struct net_device *dev, bool enable)
{
	struct mvsw_pr_rif *rif;

	rif = mvsw_pr_rif_find(sw, dev);
	if (!rif)
		return;

	if (enable)
		mvsw_pr_rif_offload(rif);
	else
		mvsw_pr_rif_delete(rif);
}

static int mvsw_pr_rif_update(struct mvsw_pr_rif *rif, char *mac)
{
	return mvsw_pr_hw_rif_set(rif->sw, &rif->rif_id, &rif->iface, mac);
}

static int mvsw_pr_rif_vr_update(struct mvsw_pr_switch *sw,
				 struct mvsw_pr_rif *rif,
				 struct netlink_ext_ack *extack)
{
	u32 tb_id = mvsw_pr_fix_tb_id(l3mdev_fib_table(rif->dev));
	struct mvsw_pr_vr *vr;

	rif->vr->ref_cnt--;
	mvsw_pr_rif_delete(rif);
	mvsw_pr_vr_put(sw, rif->vr);
	vr = mvsw_pr_vr_get(sw, tb_id, extack);
	if (IS_ERR(vr))
		return PTR_ERR(vr);
	rif->vr = vr;
	mvsw_pr_rif_iface_init(rif);
	mvsw_pr_rif_offload(rif);
	rif->vr->ref_cnt++;

	return 0;
}

void mvsw_pr_router_lag_member_leave(const struct mvsw_pr_port *port,
				     const struct net_device *dev)
{
	struct mvsw_pr_rif *rif;
	u16 vr_id;

	rif = mvsw_pr_rif_find(port->sw, dev);
	if (!rif)
		return;

	vr_id = mvsw_pr_rif_vr_id(rif);
	prestera_lag_member_rif_leave(port, port->lag_id, vr_id);
}

void prestera_lag_router_leave(struct mvsw_pr_switch *sw,
			       struct net_device *lag_dev)
{
	struct mvsw_pr_rif *rif;

	rif = mvsw_pr_rif_find(sw, lag_dev);
	if (rif) {
		rif->is_active = false;
		mvsw_pr_rif_put(rif);
	}
}

static int mvsw_pr_bridge_device_rif_put(struct net_device *bridge_dev,
					struct netdev_nested_priv *priv)
{
	struct mvsw_pr_rif *rif;
	struct mvsw_pr_switch *sw = priv->data;

	rif = mvsw_pr_rif_find(sw, bridge_dev);
	if (rif) {
		rif->is_active = false;
		mvsw_pr_rif_put(rif);
	}

	return 0;
}

void mvsw_pr_bridge_device_rifs_destroy(struct mvsw_pr_switch *sw,
					struct net_device *bridge_dev)
{
	struct netdev_nested_priv priv = {
		.data = (void *)sw,
	};
	mvsw_pr_bridge_device_rif_put(bridge_dev, &priv);
	netdev_walk_all_upper_dev_rcu(bridge_dev,
				      mvsw_pr_bridge_device_rif_put,
				      &priv);
}
