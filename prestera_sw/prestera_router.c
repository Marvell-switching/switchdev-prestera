// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/notifier.h>
#include <linux/sort.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/if_bridge.h>
#include <net/netevent.h>
#include <net/neighbour.h>
#include <net/addrconf.h>
#include <net/fib_notifier.h>
#include <net/switchdev.h>
#include <net/arp.h>
#include <net/nexthop.h>
#include <linux/rhashtable.h>

#include "prestera.h"
#include "prestera_ct.h"
#include "prestera_acl.h"
#include "prestera_hw.h"
#include "prestera_log.h"

#define MVSW_PR_IMPLICITY_RESOLVE_DEAD_NEIGH
#define MVSW_PR_NH_PROBE_INTERVAL 5000 /* ms */
#define MVSW_PR_NHGR_UNUSED (0)
#define MVSW_PR_NHGR_DROP (0xFFFFFFFF)

static const char mvsw_driver_name[] = "mrvl_switchdev";

struct prestera_rif {
	struct prestera_iface iface;
	struct net_device *dev;
	struct list_head router_node;
	unsigned char addr[ETH_ALEN];
	unsigned int mtu;
	bool is_active;
	u16 rif_id;
	struct mvsw_pr_vr *vr;
	struct prestera_switch *sw;
	unsigned int ref_cnt;
};

struct mvsw_pr_rif_params {
	struct net_device *dev;
	u16 vid;
};

struct mvsw_pr_fib_node {
	struct rhash_head ht_node; /* node of mvsw_pr_vr */
	struct prestera_fib_key key;
	struct prestera_fib_info info; /* action related info */
};

struct mvsw_pr_vr {
	u16 hw_vr_id;			/* virtual router ID */
	u32 tb_id;			/* key (kernel fib table id) */
	struct list_head router_node;
	unsigned int ref_cnt;
};

struct mvsw_pr_nexthop_group {
	struct prestera_nexthop_group_key key;
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
		struct prestera_nh_neigh *neigh;
	} nh_neigh_head[PRESTERA_NHGR_SIZE_MAX];
	u32 grp_id; /* hw */
	struct rhash_head ht_node; /* node of mvsw_pr_vr */
	unsigned int ref_cnt;
};

enum mvsw_pr_mp_hash_policy {
	MVSW_MP_L3_HASH_POLICY,
	MVSW_MP_L4_HASH_POLICY,
	MVSW_MP_HASH_POLICY_MAX,
};

struct prestera_kern_neigh_cache {
	struct prestera_nh_neigh_key key;
	struct rhash_head ht_node;
	struct list_head kern_fib_cache_list;
	/* Lock cache if neigh is present in kernel */
	bool in_kernel;
	/* Hold prepared nh_neigh info if is in_kernel */
	struct prestera_neigh_info nh_neigh_info;
	/* Indicate if neighbour is reachable by direct route */
	bool reachable;
};

struct mvsw_pr_kern_fib_cache_key {
	struct prestera_ip_addr addr;
	u32 prefix_len;
	u32 kern_tb_id; /* tb_id from kernel (not fixed) */
};

/* Subscribing on neighbours in kernel */
struct mvsw_pr_kern_fib_cache {
	struct mvsw_pr_kern_fib_cache_key key;
	struct {
		struct prestera_fib_key fib_key;
		enum mvsw_pr_fib_type fib_type;
		struct prestera_nexthop_group_key nh_grp_key;
	} lpm_info; /* hold prepared lpm info */
	/* Indicate if route is not overlapped by another table */
	bool reachable;
	bool allow_oflag;
	struct rhash_head ht_node; /* node of mvsw_pr_router */
	struct mvsw_pr_kern_neigh_cache_head {
		struct mvsw_pr_kern_fib_cache *this;
		struct list_head head;
		struct prestera_kern_neigh_cache *n_cache;
	} kern_neigh_cache_head[PRESTERA_NHGR_SIZE_MAX];
	struct fib_info *fi;
};

static const struct rhashtable_params __mvsw_pr_kern_neigh_cache_ht_params = {
	.key_offset  = offsetof(struct prestera_kern_neigh_cache, key),
	.head_offset = offsetof(struct prestera_kern_neigh_cache, ht_node),
	.key_len     = sizeof(struct prestera_nh_neigh_key),
	.automatic_shrinking = true,
};

static const struct rhashtable_params __mvsw_pr_kern_fib_cache_ht_params = {
	.key_offset  = offsetof(struct mvsw_pr_kern_fib_cache, key),
	.head_offset = offsetof(struct mvsw_pr_kern_fib_cache, ht_node),
	.key_len     = sizeof(struct mvsw_pr_kern_fib_cache_key),
	.automatic_shrinking = true,
};

static const struct rhashtable_params __mvsw_pr_fib_ht_params = {
	.key_offset  = offsetof(struct mvsw_pr_fib_node, key),
	.head_offset = offsetof(struct mvsw_pr_fib_node, ht_node),
	.key_len     = sizeof(struct prestera_fib_key),
	.automatic_shrinking = true,
};

static const struct rhashtable_params __mvsw_pr_nh_neigh_ht_params = {
	.key_offset  = offsetof(struct prestera_nh_neigh, key),
	.key_len     = sizeof(struct prestera_nh_neigh_key),
	.head_offset = offsetof(struct prestera_nh_neigh, ht_node),
};

static const struct rhashtable_params __mvsw_pr_nexthop_group_ht_params = {
	.key_offset  = offsetof(struct mvsw_pr_nexthop_group, key),
	.key_len     = sizeof(struct prestera_nexthop_group_key),
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

static struct mvsw_pr_vr *mvsw_pr_vr_get(struct prestera_switch *sw, u32 tb_id,
					 struct netlink_ext_ack *extack);
static u32 mvsw_pr_fix_tb_id(u32 tb_id);
static void mvsw_pr_vr_put(struct prestera_switch *sw, struct mvsw_pr_vr *vr);
static void mvsw_pr_vr_util_hw_abort(struct prestera_switch *sw);
static struct prestera_rif *mvsw_pr_rif_create(struct prestera_switch *sw,
					       const struct mvsw_pr_rif_params
					       *params,
					       struct netlink_ext_ack *extack);
static int mvsw_pr_rif_vr_update(struct prestera_switch *sw,
				 struct prestera_rif *rif,
				 struct netlink_ext_ack *extack);
static void mvsw_pr_rif_destroy(struct prestera_rif *rif);
static void mvsw_pr_rif_put(struct prestera_rif *rif);
static int mvsw_pr_rif_update(struct prestera_rif *rif, char *mac);
static struct prestera_rif *mvsw_pr_rif_find(const struct prestera_switch *sw,
					     const struct net_device *dev);
static u16 mvsw_pr_rif_vr_id(struct prestera_rif *rif);
static bool
mvsw_pr_nh_neigh_util_hw_state(struct prestera_switch *sw,
			       struct prestera_nh_neigh *nh_neigh);
static bool
mvsw_pr_nexthop_group_util_hw_state(struct prestera_switch *sw,
				    struct mvsw_pr_nexthop_group *nh_grp);
static int mvsw_pr_nh_neigh_set(struct prestera_switch *sw,
				struct prestera_nh_neigh *neigh);
static int mvsw_pr_nexthop_group_set(struct prestera_switch *sw,
				     struct mvsw_pr_nexthop_group *nh_grp);
static struct mvsw_pr_fib_node *
mvsw_pr_fib_node_find(struct prestera_switch *sw, struct prestera_fib_key *key);
static void mvsw_pr_fib_node_destroy(struct prestera_switch *sw,
				     struct mvsw_pr_fib_node *fib_node);
static struct mvsw_pr_fib_node *
mvsw_pr_fib_node_create(struct prestera_switch *sw,
			struct prestera_fib_key *key,
			enum mvsw_pr_fib_type fib_type,
			struct prestera_nexthop_group_key *nh_grp_key);
static bool mvsw_pr_fi_is_direct(struct fib_info *fi);
static bool mvsw_pr_fi_is_hw_direct(struct prestera_switch *sw,
				    struct fib_info *fi);
static bool mvsw_pr_fi_is_nh(struct fib_info *fi);
static bool mvsw_pr_nh_neigh_key_is_valid(struct prestera_nh_neigh_key *key);
static bool
mvsw_pr_fib_node_util_is_neighbour(struct mvsw_pr_fib_node *fib_node);
static int
mvsw_pr_util_fi2nh_gr_key(struct prestera_switch *sw, struct fib_info *fi,
			  size_t limit,
			  struct prestera_nexthop_group_key *grp_key);

static u16 mvsw_pr_nh_dev_to_vid(struct prestera_switch *sw,
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
		vid = prestera_vlan_dev_vlan_id(sw->bridge, dev);
	} else if (netif_is_macvlan(dev)) {
		vlan = netdev_priv(dev);
		return mvsw_pr_nh_dev_to_vid(sw, vlan->lowerdev);
	}

	return vid;
}

static struct net_device*
mvsw_pr_nh_dev_egress(struct prestera_switch *sw, struct net_device *dev,
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

static u16 mvsw_pr_rif_vr_id(struct prestera_rif *rif)
{
	return rif->vr->hw_vr_id;
}

static int
mvsw_pr_rif_iface_init(struct prestera_rif *rif)
{
	struct net_device *dev = rif->dev;
	struct prestera_switch *sw = rif->sw;
	struct prestera_port *port;
	int if_type = prestera_dev_if_type(dev);

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
__mvsw_pr_neigh_iface_init(struct prestera_switch *sw,
			   struct prestera_iface *iface,
			   struct neighbour *n,
			   struct net_device *dev)
{
	bool is_nud_perm = n->nud_state & NUD_PERMANENT;
	struct net_device *egress_dev;
	struct prestera_port *port;

	iface->type = prestera_dev_if_type(dev);

	switch (iface->type) {
	case MVSW_IF_PORT_E:
	case MVSW_IF_VID_E:
		egress_dev = mvsw_pr_nh_dev_egress(sw, dev, n->ha);
		if (!egress_dev && is_nud_perm) {
		/* Permanent neighbours on a bridge are not bounded to any
		 * of the ports which is needed by the hardware, therefore
		 * use any valid lower
		 */
			port = prestera_port_dev_lower_find(dev);
			egress_dev = port->net_dev;
		}
		if (!egress_dev)
			return -ENOENT;

		if (!prestera_netdev_check(egress_dev))
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
mvsw_pr_neigh_iface_init(struct prestera_switch *sw,
			 struct prestera_iface *iface,
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
				       struct prestera_ip_addr *addr)
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

int prestera_util_kern_dip2nh_grp_key(struct prestera_switch *sw,
				      u32 tb_id, struct prestera_ip_addr *addr,
				      struct prestera_nexthop_group_key *res)
{
	int err;
	struct fib_result fib_res;
	struct fib_nh *fib_nh;

	err = mvsw_pr_util_kern_get_route(&fib_res, tb_id, addr);
	if (err)
		return 0;

	if (mvsw_pr_fi_is_direct(fib_res.fi)) {
		fib_nh = fib_info_nh(fib_res.fi, 0);
		memset(res, 0, sizeof(*res));
		res->neigh[0].addr = *addr;
		res->neigh[0].rif = mvsw_pr_rif_find(sw, fib_nh->fib_nh_dev);
		if (!res->neigh[0].rif || !res->neigh[0].rif->is_active)
			return 0;

		return 1;
	}

	return mvsw_pr_util_fi2nh_gr_key(sw, fib_res.fi,
					 PRESTERA_NHGR_SIZE_MAX, res);
}

/* Check if neigh route is reachable */
static bool
mvsw_pr_util_kern_n_is_reachable(u32 tb_id,
				 struct prestera_ip_addr *addr,
				 struct net_device *dev)
{
	bool reachable;
	struct fib_nh *fib_nh;
	struct fib_result res;

	reachable = false;

	if (!mvsw_pr_util_kern_get_route(&res, tb_id, addr))
		if (res.type == RTN_UNICAST &&
		    mvsw_pr_fi_is_direct(res.fi)) {
			fib_nh = fib_info_nh(res.fi, 0);
			if (dev == fib_nh->fib_nh_dev)
				reachable = true;
		}

	return reachable;
}

static bool
mvsw_pr_util_fi_is_point2dev(struct fib_info *fi,
			     const struct net_device *dev)
{
	int nhs, i;
	struct fib_nh *fib_nh;

	nhs = fib_info_num_path(fi);
	for (i = 0; i < nhs; i++) {
		fib_nh = fib_info_nh(fi, i);
		if (fib_nh->fib_nh_dev == dev)
			return true;
	}

	return false;
}

static int
mvsw_pr_util_fib_nh2nh_neigh_key(struct prestera_switch *sw,
				 struct fib_nh *fib_nh,
				 struct prestera_nh_neigh_key *nh_key)
{
	memset(nh_key, 0, sizeof(*nh_key));
	nh_key->addr.u.ipv4 = fib_nh->fib_nh_gw4;
	nh_key->rif = mvsw_pr_rif_find(sw, fib_nh->fib_nh_dev);
	if (!nh_key->rif || !nh_key->rif->is_active)
		return -ENOENT;

	return 0;
}

static int
mvsw_pr_util_fi2nh_gr_key(struct prestera_switch *sw, struct fib_info *fi,
			  size_t limit,
			  struct prestera_nexthop_group_key *grp_key)
{
	int i, nhs, err;
	struct fib_nh *fib_nh;

	if (!mvsw_pr_fi_is_nh(fi))
		return 0;

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

static void
mvsw_pr_util_fen_info2fib_cache_key(struct fib_entry_notifier_info *fen_info,
				    struct mvsw_pr_kern_fib_cache_key *key)
{
	memset(key, 0, sizeof(*key));
	key->addr.u.ipv4 = cpu_to_be32(fen_info->dst);
	key->prefix_len = fen_info->dst_len;
	key->kern_tb_id = fen_info->tb_id;
}

static void
mvsw_pr_util_fib_cache_key2fib_key(struct mvsw_pr_kern_fib_cache_key *ckey,
				   struct prestera_fib_key *fkey)
{
	memset(fkey, 0, sizeof(*fkey));
	fkey->addr = ckey->addr;
	fkey->prefix_len = ckey->prefix_len;
	fkey->tb_id = mvsw_pr_fix_tb_id(ckey->kern_tb_id);
}

static bool
mvsw_pr_util_is_fib_nh_equal2nh_neigh_key(struct prestera_switch *sw,
					  struct fib_nh *fib_nh,
					  struct prestera_nh_neigh_key *nk)
{
	int err;
	struct prestera_nh_neigh_key tk;

	err = mvsw_pr_util_fib_nh2nh_neigh_key(sw, fib_nh, &tk);
	if (err)
		return false;

	if (memcmp(&tk, nk, sizeof(tk)))
		return false;

	return true;
}

static int mvsw_pr_util_neigh2nh_neigh_key(struct prestera_switch *sw,
					   struct neighbour *n,
					   struct prestera_nh_neigh_key *key)
{
	memset(key, 0, sizeof(*key));
	key->addr.u.ipv4 = *(__be32 *)n->primary_key;
	key->rif = mvsw_pr_rif_find(sw, n->dev);
	if (!key->rif)
		return -ENOENT;

	return 0;
}

static struct prestera_kern_neigh_cache *
mvsw_pr_kern_neigh_cache_find(struct prestera_switch *sw,
			      struct prestera_nh_neigh_key *key)
{
	struct prestera_kern_neigh_cache *n_cache;

	n_cache =
	 rhashtable_lookup_fast(&sw->router->kern_neigh_cache_ht, key,
				__mvsw_pr_kern_neigh_cache_ht_params);
	return IS_ERR(n_cache) ? NULL : n_cache;
}

static void
__mvsw_pr_kern_neigh_cache_destroy(struct prestera_switch *sw,
				   struct prestera_kern_neigh_cache *n_cache)
{
	n_cache->key.rif->ref_cnt--;
	mvsw_pr_rif_put(n_cache->key.rif);
	rhashtable_remove_fast(&sw->router->kern_neigh_cache_ht,
			       &n_cache->ht_node,
			       __mvsw_pr_kern_neigh_cache_ht_params);
	kfree(n_cache);
}

static struct prestera_kern_neigh_cache *
__mvsw_pr_kern_neigh_cache_create(struct prestera_switch *sw,
				  struct prestera_nh_neigh_key *key)
{
	struct prestera_kern_neigh_cache *n_cache;
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

static struct prestera_kern_neigh_cache *
mvsw_pr_kern_neigh_cache_get(struct prestera_switch *sw,
			     struct prestera_nh_neigh_key *key)
{
	struct prestera_kern_neigh_cache *n_cache;

	n_cache = mvsw_pr_kern_neigh_cache_find(sw, key);
	if (!n_cache)
		n_cache = __mvsw_pr_kern_neigh_cache_create(sw, key);

	return n_cache;
}

static struct prestera_kern_neigh_cache *
mvsw_pr_kern_neigh_cache_put(struct prestera_switch *sw,
			     struct prestera_kern_neigh_cache *n_cache)
{
	if (!n_cache->in_kernel &&
	    list_empty(&n_cache->kern_fib_cache_list)) {
		__mvsw_pr_kern_neigh_cache_destroy(sw, n_cache);
		return NULL;
	}

	return n_cache;
}

static struct mvsw_pr_kern_fib_cache *
mvsw_pr_kern_fib_cache_find(struct prestera_switch *sw,
			    struct mvsw_pr_kern_fib_cache_key *key)
{
	struct mvsw_pr_kern_fib_cache *fib_cache;

	fib_cache =
	 rhashtable_lookup_fast(&sw->router->kern_fib_cache_ht, key,
				__mvsw_pr_kern_fib_cache_ht_params);
	return IS_ERR(fib_cache) ? NULL : fib_cache;
}

static void
mvsw_pr_kern_fib_cache_destroy(struct prestera_switch *sw,
			       struct mvsw_pr_kern_fib_cache *fib_cache)
{
	int i;
	struct prestera_kern_neigh_cache *n_cache;

	for (i = 0; i < PRESTERA_NHGR_SIZE_MAX; i++) {
		n_cache = fib_cache->kern_neigh_cache_head[i].n_cache;
		if (n_cache) {
			list_del(&fib_cache->kern_neigh_cache_head[i].head);
			mvsw_pr_kern_neigh_cache_put(sw, n_cache);
		}
	}

	fib_info_put(fib_cache->fi);
	rhashtable_remove_fast(&sw->router->kern_fib_cache_ht,
			       &fib_cache->ht_node,
			       __mvsw_pr_kern_fib_cache_ht_params);
	kfree(fib_cache);
}

/* Pass also grp_key, because we may implement logic to     *
 * differ fib_nh's and created nh_neighs.                   *
 * Operations on fi (offload, etc) must be wrapped in utils *
 */
static struct mvsw_pr_kern_fib_cache *
__mvsw_pr_kern_fib_cache_create(struct prestera_switch *sw,
				struct mvsw_pr_kern_fib_cache_key *key,
				struct prestera_nexthop_group_key *grp_key,
				struct fib_info *fi)
{
	struct mvsw_pr_kern_fib_cache *fib_cache;
	struct prestera_kern_neigh_cache *n_cache;
	int err, i;

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

	if (!grp_key)
		goto out;

	for (i = 0; i < PRESTERA_NHGR_SIZE_MAX; i++) {
		if (!mvsw_pr_nh_neigh_key_is_valid(&grp_key->neigh[i]))
			break;

		n_cache = mvsw_pr_kern_neigh_cache_get(sw, &grp_key->neigh[i]);
		if (!n_cache)
			continue;

		fib_cache->kern_neigh_cache_head[i].this = fib_cache;
		fib_cache->kern_neigh_cache_head[i].n_cache = n_cache;
		list_add(&fib_cache->kern_neigh_cache_head[i].head,
			 &n_cache->kern_fib_cache_list);
	}

out:
	return fib_cache;

err_ht_insert:
	fib_info_put(fi);
	kfree(fib_cache);
err_kzalloc:
	return NULL;
}

static struct mvsw_pr_kern_fib_cache *
mvsw_pr_kern_fib_cache_create(struct prestera_switch *sw,
			      struct mvsw_pr_kern_fib_cache_key *fc_key,
			      struct fib_info *fi)
{
	struct mvsw_pr_kern_fib_cache *fc;
	struct prestera_nexthop_group_key grp_key;
	int nh_cnt;

	switch (fi->fib_type) {
	case RTN_UNICAST:
		nh_cnt = mvsw_pr_util_fi2nh_gr_key(sw, fi,
						   PRESTERA_NHGR_SIZE_MAX,
						   &grp_key);
		fc = __mvsw_pr_kern_fib_cache_create(sw, fc_key,
						     nh_cnt ? &grp_key : NULL,
						     fi);
		if (!fc)
			return NULL;

		fc->lpm_info.fib_type = nh_cnt ?
					MVSW_PR_FIB_TYPE_UC_NH :
					MVSW_PR_FIB_TYPE_TRAP;
		fc->lpm_info.nh_grp_key = grp_key;
		fc->allow_oflag = !!(nh_cnt || mvsw_pr_fi_is_hw_direct(sw, fi));
		break;
	/* Unsupported. Leave it for kernel: */
	case RTN_BROADCAST:
	case RTN_MULTICAST:
	/* Routes we must trap by design: */
	case RTN_LOCAL:
	case RTN_UNREACHABLE:
	case RTN_PROHIBIT:
		fc = __mvsw_pr_kern_fib_cache_create(sw, fc_key, NULL, fi);
		if (!fc)
			return NULL;

		fc->lpm_info.fib_type = MVSW_PR_FIB_TYPE_TRAP;
		break;
	case RTN_BLACKHOLE:
		fc = __mvsw_pr_kern_fib_cache_create(sw, fc_key, NULL, fi);
		if (!fc)
			return NULL;

		fc->lpm_info.fib_type = MVSW_PR_FIB_TYPE_DROP;
		break;
	default:
		MVSW_LOG_ERROR("Unsupported fib_type");
		return NULL;
	}

	mvsw_pr_util_fib_cache_key2fib_key(fc_key,
					   &fc->lpm_info.fib_key);

	return fc;
}

static void
__mvsw_pr_k_arb_fib_offload_set(struct prestera_switch *sw,
				struct mvsw_pr_kern_fib_cache *fibc,
				struct prestera_kern_neigh_cache *nc,
				bool offloaded)
{
	int i, nhs;
	struct fib_nh *fib_nh;

	nhs = fib_info_num_path(fibc->fi);
	for (i = 0; i < nhs; i++) {
		fib_nh = fib_info_nh(fibc->fi, i);
		if (!nc) {
			mvsw_pr_util_kern_set_nh_offload(fib_nh, offloaded);
			continue;
		}

		if (mvsw_pr_util_is_fib_nh_equal2nh_neigh_key(sw,
							      fib_nh,
							      &nc->key)) {
			mvsw_pr_util_kern_set_nh_offload(fib_nh, offloaded);
			break;
		}
	}
}

static void
__mvsw_pr_k_arb_n_offload_set(struct prestera_switch *sw,
			      struct prestera_kern_neigh_cache *nc,
			      bool offloaded)
{
	struct neighbour *n;

	n = neigh_lookup(&arp_tbl, &nc->key.addr.u.ipv4, nc->key.rif->dev);

	if (!n)
		return;

	mvsw_pr_util_kern_set_neigh_offload(n, offloaded);
	neigh_release(n);
}

static void
__mvsw_pr_k_arb_n_lpm_set(struct prestera_switch *sw,
			  struct prestera_kern_neigh_cache *n_cache,
			  bool enabled)
{
	struct prestera_fib_key fib_key;
	struct mvsw_pr_fib_node *fib_node;
	struct prestera_nexthop_group_key nh_grp_key;

	memset(&fib_key, 0, sizeof(fib_key));
	fib_key.addr = n_cache->key.addr;
	fib_key.prefix_len = 32;
	fib_key.tb_id = n_cache->key.rif->vr->tb_id;
	fib_node = mvsw_pr_fib_node_find(sw, &fib_key);
	if (!enabled && fib_node) {
		if (mvsw_pr_fib_node_util_is_neighbour(fib_node))
			mvsw_pr_fib_node_destroy(sw, fib_node);
		return;
	}

	if (enabled && !fib_node) {
		memset(&nh_grp_key, 0, sizeof(nh_grp_key));
		nh_grp_key.neigh[0] = n_cache->key;
		fib_node = mvsw_pr_fib_node_create(sw, &fib_key,
						   MVSW_PR_FIB_TYPE_UC_NH,
						   &nh_grp_key);
		if (!fib_node)
			MVSW_LOG_ERROR("%s failed ip=%pI4n",
				       "mvsw_pr_fib_node_create",
				       &fib_key.addr.u.ipv4);
		return;
	}
}

static void
__mvsw_pr_k_arb_nc_kern_fib_fetch(struct prestera_switch *sw,
				  struct prestera_kern_neigh_cache *nc)
{
	if (mvsw_pr_util_kern_n_is_reachable(nc->key.rif->vr->tb_id,
					     &nc->key.addr,
					     nc->key.rif->dev))
		nc->reachable = true;
	else
		nc->reachable = false;
}

/* Kernel neighbour -> neigh_cache info */
static void
__mvsw_pr_k_arb_nc_kern_n_fetch(struct prestera_switch *sw,
				struct prestera_kern_neigh_cache *nc)
{
	struct neighbour *n;
	int err;

	memset(&nc->nh_neigh_info, 0, sizeof(nc->nh_neigh_info));
	n = neigh_lookup(&arp_tbl, &nc->key.addr.u.ipv4, nc->key.rif->dev);
	if (!n)
		goto out;

	read_lock_bh(&n->lock);
	if (n->nud_state & NUD_VALID && !n->dead) {
		err = mvsw_pr_neigh_iface_init(sw, &nc->nh_neigh_info.iface, n);
		if (err) {
			MVSW_LOG_ERROR("Cannot initialize iface for %pI4n %pM",
				       n->primary_key, &n->ha[0]);
			goto n_read_out;
		}

		memcpy(&nc->nh_neigh_info.ha[0], &n->ha[0], ETH_ALEN);
		nc->nh_neigh_info.connected = true;
	}
n_read_out:
	read_unlock_bh(&n->lock);
out:
	nc->in_kernel = nc->nh_neigh_info.connected;
	if (n)
		neigh_release(n);
}

/* neigh_cache info -> lpm update */
static void
__mvsw_pr_k_arb_nc_apply(struct prestera_switch *sw,
			 struct prestera_kern_neigh_cache *nc)
{
	struct prestera_nh_neigh *nh_neigh;
	struct mvsw_pr_kern_neigh_cache_head *nhead;
	struct prestera_acl_nat_port *nat_port;
	struct prestera_port *port;
	u32 port_hw_id, port_dev_id;
	int err;

	__mvsw_pr_k_arb_n_lpm_set(sw, nc,
				  nc->reachable && nc->in_kernel);
	__mvsw_pr_k_arb_n_offload_set(sw, nc,
				      nc->reachable && nc->in_kernel);

	/* update NAT port on neighbour change */
	port_hw_id = nc->key.rif->iface.dev_port.port_num;
	port_dev_id = nc->key.rif->iface.dev_port.hw_dev_num;
	nat_port = prestera_acl_nat_port_get(sw->acl, port_hw_id,
					     port_dev_id);
	if (!nat_port)
		goto skip_nat_port_update;

	port = prestera_acl_nat_port_to_port(nat_port);
	prestera_acl_nat_port_put(nat_port);

	err = prestera_hw_nat_port_neigh_update(port,
						nc->nh_neigh_info.ha);
	if (err)
		/* do not fail others, just print an error */
		MVSW_LOG_ERROR("Update NAT neigh fail [%pI4n, %pM]",
			       &nc->key.addr.u.ipv4,
			       nc->nh_neigh_info.ha);

skip_nat_port_update:
	nh_neigh = prestera_nh_neigh_find(sw, &nc->key);
	if (!nh_neigh)
		goto out;

	/* Do hw update only if something changed to prevent nh flap */
	if (memcmp(&nc->nh_neigh_info, &nh_neigh->info,
		   sizeof(nh_neigh->info))) {
		memcpy(&nh_neigh->info, &nc->nh_neigh_info,
		       sizeof(nh_neigh->info));
		err = mvsw_pr_nh_neigh_set(sw, nh_neigh);
		if (err) {
			MVSW_LOG_ERROR("%s failed with err=%d ip=%pI4n mac=%pM",
				       "mvsw_pr_nh_neigh_set", err,
				       &nh_neigh->key.addr.u.ipv4,
				       &nh_neigh->info.ha[0]);
			goto out;
		}
	}

out:
	list_for_each_entry(nhead, &nc->kern_fib_cache_list, head) {
		__mvsw_pr_k_arb_fib_offload_set(sw, nhead->this, nc,
						nc->in_kernel &&
						nhead->this->reachable &&
						nhead->this->allow_oflag);
	}
}

static void __mvsw_pr_k_arb_hw_state_upd(struct prestera_switch *sw,
					 struct prestera_kern_neigh_cache *nc)
{
	bool hw_active;
	struct prestera_nh_neigh *nh_neigh;
	struct neighbour *n;

	nh_neigh = prestera_nh_neigh_find(sw, &nc->key);
	if (!nh_neigh) {
		MVSW_LOG_ERROR("Cannot find nh_neigh for cached %pI4n",
			       &nc->key.addr.u.ipv4);
		return;
	}

	hw_active = mvsw_pr_nh_neigh_util_hw_state(sw, nh_neigh);

#ifdef MVSW_PR_IMPLICITY_RESOLVE_DEAD_NEIGH
	if (!hw_active && nc->in_kernel)
		goto out;
#else /* MVSW_PR_IMPLICITY_RESOLVE_DEAD_NEIGH */
	if (!hw_active)
		goto out;
#endif /* MVSW_PR_IMPLICITY_RESOLVE_DEAD_NEIGH */

	n = neigh_lookup(&arp_tbl, &nc->key.addr.u.ipv4, nc->key.rif->dev);
	if (!n) {
		n = neigh_create(&arp_tbl, &nc->key.addr.u.ipv4,
				 nc->key.rif->dev);
		if (IS_ERR(n)) {
			n = NULL;
			MVSW_LOG_ERROR("Cannot create neighbour %pI4n",
				       &nc->key.addr.u.ipv4);
		}
	}

	if (n) {
		neigh_event_send(n, NULL);
		neigh_release(n);
	}

out:
	return;
}

static int __mvsw_pr_k_arb_f_lpm_set(struct prestera_switch *sw,
				     struct mvsw_pr_kern_fib_cache *fc,
				     bool enabled)
{
	struct mvsw_pr_fib_node *fib_node;

	fib_node = mvsw_pr_fib_node_find(sw, &fc->lpm_info.fib_key);
	if (fib_node)
		mvsw_pr_fib_node_destroy(sw, fib_node);

	if (!enabled)
		return 0;

	fib_node = mvsw_pr_fib_node_create(sw, &fc->lpm_info.fib_key,
					   fc->lpm_info.fib_type,
					   &fc->lpm_info.nh_grp_key);

	if (!fib_node) {
		MVSW_LOG_ERROR("fib_node=NULL %pI4n/%d kern_tb_id = %d",
			       &fc->key.addr.u.ipv4, fc->key.prefix_len,
			       fc->key.kern_tb_id);
		return -ENOENT;
	}

	return 0;
}

static int __mvsw_pr_k_arb_fc_apply(struct prestera_switch *sw,
				    struct mvsw_pr_kern_fib_cache *fc)
{
	int err;

	/* 1. Update lpm */
	err = __mvsw_pr_k_arb_f_lpm_set(sw, fc, fc->reachable);
	if (err)
		return err;

	/* UC_NH offload flag is managed by neighbours cache */
	if (fc->lpm_info.fib_type != MVSW_PR_FIB_TYPE_UC_NH || !fc->reachable)
		__mvsw_pr_k_arb_fib_offload_set(sw, fc, NULL, fc->reachable &&
						fc->allow_oflag);

	return 0;
}

static struct mvsw_pr_kern_fib_cache *
__mvsw_pr_k_arb_util_fib_overlaps(struct prestera_switch *sw,
				  struct mvsw_pr_kern_fib_cache *fc)
{
	struct mvsw_pr_kern_fib_cache *rfc;
	struct mvsw_pr_kern_fib_cache_key fc_key;

	/* TODO: parse kernel rules */
	rfc = NULL;
	if (fc->key.kern_tb_id == RT_TABLE_LOCAL) {
		memcpy(&fc_key, &fc->key, sizeof(fc_key));
		fc_key.kern_tb_id = RT_TABLE_MAIN;
		rfc = mvsw_pr_kern_fib_cache_find(sw, &fc_key);
	}

	return rfc;
}

static struct mvsw_pr_kern_fib_cache *
__mvsw_pr_k_arb_util_fib_overlapped(struct prestera_switch *sw,
				    struct mvsw_pr_kern_fib_cache *fc)
{
	struct mvsw_pr_kern_fib_cache *rfc;
	struct mvsw_pr_kern_fib_cache_key fc_key;

	/* TODO: parse kernel rules */
	rfc = NULL;
	if (fc->key.kern_tb_id == RT_TABLE_MAIN) {
		memcpy(&fc_key, &fc->key, sizeof(fc_key));
		fc_key.kern_tb_id = RT_TABLE_LOCAL;
		rfc = mvsw_pr_kern_fib_cache_find(sw, &fc_key);
	}

	return rfc;
}

static void __mvsw_pr_k_arb_abort_neigh(struct prestera_switch *sw)
{
	struct prestera_kern_neigh_cache *n_cache;
	struct rhashtable_iter iter;

	while (1) {
		rhashtable_walk_enter(&sw->router->kern_neigh_cache_ht, &iter);
		rhashtable_walk_start(&iter);

		n_cache = rhashtable_walk_next(&iter);

		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);

		if (!n_cache) {
			break;
		} else if (IS_ERR(n_cache)) {
			continue;
		} else if (n_cache) {
			__mvsw_pr_k_arb_n_offload_set(sw, n_cache, false);
			n_cache->in_kernel = false;
			/* No need to destroy lpm.
			 * It will be aborted by destroy_ht
			 */
			__mvsw_pr_kern_neigh_cache_destroy(sw, n_cache);
		}
	}
}

static void __mvsw_pr_k_arb_abort_fib(struct prestera_switch *sw)
{
	struct mvsw_pr_kern_fib_cache *fib_cache;
	struct rhashtable_iter iter;

	while (1) {
		rhashtable_walk_enter(&sw->router->kern_fib_cache_ht, &iter);
		rhashtable_walk_start(&iter);

		fib_cache = rhashtable_walk_next(&iter);

		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);

		if (!fib_cache) {
			break;
		} else if (IS_ERR(fib_cache)) {
			continue;
		} else if (fib_cache) {
			__mvsw_pr_k_arb_fib_offload_set(sw, fib_cache, NULL,
							false);
			/* No need to destroy lpm.
			 * It will be aborted by destroy_ht
			 */
			mvsw_pr_kern_fib_cache_destroy(sw, fib_cache);
		}
	}
}

static void mvsw_pr_k_arb_abort(struct prestera_switch *sw)
{
	__mvsw_pr_k_arb_abort_fib(sw);
	__mvsw_pr_k_arb_abort_neigh(sw);
}

/* Make necesssary things  with neighbour, if FDB upupdated
 * Known useacase for this function:
 *  if FDB entry (which tied on neigh) updated - we need to reaply it in HW
 */
void prestera_k_arb_fdb_evt(struct prestera_switch *sw, struct net_device *dev)
{
	struct net_device *upper_dev;
	struct list_head *list_iter;
	struct prestera_rif *rif;
	struct prestera_kern_neigh_cache *n_cache;
	struct rhashtable_iter iter;

	rif = mvsw_pr_rif_find(sw, dev);
	if (rif) {
		/* TODO: seems to be a lot of places, where such iteration used.
		 * Maybe, make sense to write macros.
		 */
		rhashtable_walk_enter(&sw->router->kern_neigh_cache_ht, &iter);
		rhashtable_walk_start(&iter);
		while (1) {
			n_cache = rhashtable_walk_next(&iter);

			if (!n_cache)
				break;

			if (IS_ERR(n_cache))
				continue;

			if (n_cache->key.rif != rif)
				continue;

			rhashtable_walk_stop(&iter);
			__mvsw_pr_k_arb_nc_kern_fib_fetch(sw, n_cache);
			__mvsw_pr_k_arb_nc_apply(sw, n_cache);
			rhashtable_walk_start(&iter);
		}
		rhashtable_walk_stop(&iter);
		rhashtable_walk_exit(&iter);
	}

	netdev_for_each_upper_dev_rcu(dev, upper_dev, list_iter)
		prestera_k_arb_fdb_evt(sw, upper_dev);
}

/* Propagate kernel event to hw */
static void mvsw_pr_k_arb_n_evt(struct prestera_switch *sw,
				struct neighbour *n)
{
	struct prestera_kern_neigh_cache *n_cache;
	struct prestera_nh_neigh_key n_key;
	int err;

	err = mvsw_pr_util_neigh2nh_neigh_key(sw, n, &n_key);
	if (err)
		return;

	n_cache = mvsw_pr_kern_neigh_cache_find(sw, &n_key);
	if (!n_cache) {
		n_cache = mvsw_pr_kern_neigh_cache_get(sw, &n_key);
		if (!n_cache)
			return;
		__mvsw_pr_k_arb_nc_kern_fib_fetch(sw, n_cache);
	}

	__mvsw_pr_k_arb_nc_kern_n_fetch(sw, n_cache);
	__mvsw_pr_k_arb_nc_apply(sw, n_cache);

	mvsw_pr_kern_neigh_cache_put(sw, n_cache);
}

/* Propagate hw state to kernel */
static void mvsw_pr_k_arb_hw_evt(struct prestera_switch *sw)
{
	struct prestera_kern_neigh_cache *n_cache;
	struct rhashtable_iter iter;

	rhashtable_walk_enter(&sw->router->kern_neigh_cache_ht, &iter);
	rhashtable_walk_start(&iter);
	while (1) {
		n_cache = rhashtable_walk_next(&iter);

		if (!n_cache)
			break;

		if (IS_ERR(n_cache))
			continue;

		rhashtable_walk_stop(&iter);
		__mvsw_pr_k_arb_hw_state_upd(sw, n_cache);
		rhashtable_walk_start(&iter);
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
}

static void __mvsw_pr_k_arb_fib_evt2nc(struct prestera_switch *sw)
{
	struct prestera_kern_neigh_cache *n_cache;
	struct rhashtable_iter iter;

	rhashtable_walk_enter(&sw->router->kern_neigh_cache_ht, &iter);
	rhashtable_walk_start(&iter);
	while (1) {
		n_cache = rhashtable_walk_next(&iter);

		if (!n_cache)
			break;

		if (IS_ERR(n_cache))
			continue;

		rhashtable_walk_stop(&iter);
		__mvsw_pr_k_arb_nc_kern_fib_fetch(sw, n_cache);
		__mvsw_pr_k_arb_nc_apply(sw, n_cache);
		rhashtable_walk_start(&iter);
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
}

/* Propagate fib changes to hw neighs */
static int
mvsw_pr_k_arb_fib_evt(struct prestera_switch *sw,
		      bool replace, /* replace or del */
		      struct fib_entry_notifier_info *fen_info)
{
	struct mvsw_pr_kern_fib_cache_key fc_key;
	struct mvsw_pr_kern_fib_cache *fib_cache;
	struct mvsw_pr_kern_fib_cache *tfib_cache, *bfib_cache;
	int err;

	mvsw_pr_util_fen_info2fib_cache_key(fen_info, &fc_key);
	fib_cache = mvsw_pr_kern_fib_cache_find(sw, &fc_key);
	if (fib_cache) {
		fib_cache->reachable = false;
		err = __mvsw_pr_k_arb_fc_apply(sw, fib_cache);
		if (err)
			MVSW_LOG_ERROR("Applying destroyed fib_cache failed");

		bfib_cache = __mvsw_pr_k_arb_util_fib_overlaps(sw, fib_cache);
		tfib_cache = __mvsw_pr_k_arb_util_fib_overlapped(sw, fib_cache);
		if (!tfib_cache && bfib_cache) {
			bfib_cache->reachable = true;
			err = __mvsw_pr_k_arb_fc_apply(sw, bfib_cache);
			if (err) {
				MVSW_LOG_ERROR("Applying fib_cache btm failed");
				return -ENOENT;
			}
		}

		mvsw_pr_kern_fib_cache_destroy(sw, fib_cache);
	}

	if (replace) {
		fib_cache = mvsw_pr_kern_fib_cache_create(sw, &fc_key,
							  fen_info->fi);
		if (!fib_cache) {
			MVSW_LOG_ERROR("fib_cache == NULL");
			return -ENOENT;
		}

		bfib_cache = __mvsw_pr_k_arb_util_fib_overlaps(sw, fib_cache);
		tfib_cache = __mvsw_pr_k_arb_util_fib_overlapped(sw, fib_cache);
		if (!tfib_cache)
			fib_cache->reachable = true;

		if (bfib_cache) {
			bfib_cache->reachable = false;
			err = __mvsw_pr_k_arb_fc_apply(sw, bfib_cache);
			if (err)
				MVSW_LOG_ERROR("Applying fib_cache btm failed");
		}

		err = __mvsw_pr_k_arb_fc_apply(sw, fib_cache);
		if (err) {
			MVSW_LOG_ERROR("Applying fib_cache failed");
			return -ENOENT;
		}
	}

	/* Update all neighs to resolve overlapped and apply related */
	__mvsw_pr_k_arb_fib_evt2nc(sw);

	return 0;
}

static void mvsw_pr_k_arb_nh_evt(struct prestera_switch *sw,
				 bool replace,
				 struct fib_nh *fib_nh)
{
	struct prestera_kern_neigh_cache *nc;
	struct prestera_nh_neigh_key nkey;
	int err;

	err = mvsw_pr_util_fib_nh2nh_neigh_key(sw, fib_nh, &nkey);
	if (err)
		return;

	nc = mvsw_pr_kern_neigh_cache_find(sw, &nkey);
	if (!nc)
		return;

	/* NOTE: we also get from kernel n_evt after this one
	 * mvsw_pr_k_arb_nh_evt is used only to speedup nh update after
	 * linkdown on ECMP routes
	 */
	nc->nh_neigh_info.connected = false;
	__mvsw_pr_k_arb_nc_apply(sw, nc);
}

static struct mvsw_pr_kern_fib_cache *
__mvsw_pr_k_arb_fc_rebuild(struct prestera_switch *sw,
			   struct mvsw_pr_kern_fib_cache *fc)
{
	struct fib_info *fi;
	struct mvsw_pr_kern_fib_cache_key key;
	struct mvsw_pr_kern_fib_cache *new_fc;
	bool reachable;

	memcpy(&key, &fc->key, sizeof(key));
	fi = fc->fi;
	fib_info_hold(fi);
	reachable = fc->reachable;

	fc->reachable = false;
	__mvsw_pr_k_arb_fc_apply(sw, fc);
	mvsw_pr_kern_fib_cache_destroy(sw, fc);

	new_fc = mvsw_pr_kern_fib_cache_create(sw, &key, fi);
	fib_info_put(fi);
	if (!new_fc)
		return NULL;

	new_fc->reachable = reachable;
	__mvsw_pr_k_arb_fc_apply(sw, new_fc);

	return new_fc;
}

static void mvsw_pr_k_arb_rif_evt(struct prestera_switch *sw,
				  struct prestera_rif *rif)
{
	struct mvsw_pr_kern_fib_cache *fc, *tfc, *nfc;
	struct prestera_kern_neigh_cache *nc, *tnc;
	struct rhashtable_iter iter;

	/* Walk every fc, which related to rif and set to trap */
	tfc = NULL;
	rhashtable_walk_enter(&sw->router->kern_fib_cache_ht, &iter);
	rhashtable_walk_start(&iter);
	while (1) {
		fc = rhashtable_walk_next(&iter);
		if (tfc && mvsw_pr_util_fi_is_point2dev(tfc->fi, rif->dev)) {
			rhashtable_walk_stop(&iter);
			nfc = __mvsw_pr_k_arb_fc_rebuild(sw, tfc);
			rhashtable_walk_start(&iter);
			/* TODO: way to crash ? */
			if (WARN_ON(!nfc))
				MVSW_LOG_ERROR("Rebuild failed %pI4n/%d",
					       &tfc->key.addr.u.ipv4,
					       tfc->key.prefix_len);
		}

		if (!fc)
			break;

		tfc = NULL;
		if (IS_ERR(fc))
			continue;

		tfc = fc;
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	/* Destroy every nc, which related to rif */
	tnc = NULL;
	rhashtable_walk_enter(&sw->router->kern_neigh_cache_ht, &iter);
	rhashtable_walk_start(&iter);
	while (1) {
		nc = rhashtable_walk_next(&iter);
		if (tnc && tnc->key.rif == rif) {
			tnc->in_kernel = false;
			rhashtable_walk_stop(&iter);
			__mvsw_pr_k_arb_nc_apply(sw, tnc);
			WARN_ON(mvsw_pr_kern_neigh_cache_put(sw, tnc));
			rhashtable_walk_start(&iter);
		}

		if (!nc)
			break;

		tnc = NULL;
		if (IS_ERR(nc))
			continue;

		tnc = nc;
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
}

struct mvsw_pr_netevent_work {
	struct work_struct work;
	struct prestera_switch *sw;
	struct neighbour *n;
};

static void mvsw_pr_router_neigh_event_work(struct work_struct *work)
{
	struct mvsw_pr_netevent_work *net_work =
		container_of(work, struct mvsw_pr_netevent_work, work);
	struct prestera_switch *sw = net_work->sw;
	struct neighbour *n = net_work->n;

	/* neigh - its not hw related object. It stored only in kernel. So... */
	mvsw_owq_lock();

	if (sw->router->aborted)
		goto out;

	mvsw_pr_k_arb_n_evt(sw, n);

out:
	neigh_release(n);
	mvsw_owq_unlock();
	kfree(net_work);
}

static int mvsw_pr_router_netevent_event(struct notifier_block *nb,
					 unsigned long event, void *ptr)
{
	struct mvsw_pr_netevent_work *net_work;
	struct prestera_router *router;
	struct prestera_rif *rif;
	struct neighbour *n = ptr;

	router = container_of(nb, struct prestera_router, netevent_nb);

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
mvsw_pr_router_neighs_update_interval_init(struct prestera_router *router)
{
	router->neighs_update.interval = MVSW_PR_NH_PROBE_INTERVAL;
}

static void mvsw_pr_router_update_neighs_work(struct work_struct *work)
{
	struct prestera_router *router;

	router = container_of(work, struct prestera_router,
			      neighs_update.dw.work);
	rtnl_lock();

	if (router->aborted)
		goto out;

	mvsw_pr_k_arb_hw_evt(router->sw);

out:
	rtnl_unlock();
	mvsw_pr_router_neighs_update_interval_init(router);
	queue_delayed_work(mvsw_r_wq, &router->neighs_update.dw,
			   msecs_to_jiffies(router->neighs_update.interval));
}

static int mvsw_pr_neigh_init(struct prestera_switch *sw)
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

static void mvsw_pr_neigh_fini(struct prestera_switch *sw)
{
	cancel_delayed_work_sync(&sw->router->neighs_update.dw);
	rhashtable_destroy(&sw->router->nh_neigh_ht);
}

static struct prestera_rif*
mvsw_pr_rif_find(const struct prestera_switch *sw,
		 const struct net_device *dev)
{
	struct prestera_rif *rif;

	list_for_each_entry(rif, &sw->router->rif_list, router_node) {
		if (rif->dev == dev)
			return rif;
	}

	return NULL;
}

bool prestera_rif_exists(const struct prestera_switch *sw,
			 const struct net_device *dev)
{
	return !!mvsw_pr_rif_find(sw, dev);
}

static int
mvsw_pr_port_vlan_router_join(struct prestera_port_vlan *mvsw_pr_port_vlan,
			      struct net_device *dev,
			      struct netlink_ext_ack *extack)
{
	struct prestera_port *port = mvsw_pr_port_vlan->mvsw_pr_port;
	struct prestera_switch *sw = port->sw;

	struct mvsw_pr_rif_params params = {
		.dev = dev,
	};
	struct prestera_rif *rif;

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
mvsw_pr_port_vlan_router_leave(struct prestera_port_vlan *mvsw_pr_port_vlan,
			       struct net_device *dev)

{
	struct prestera_port *port = mvsw_pr_port_vlan->mvsw_pr_port;
	struct prestera_switch *sw = port->sw;
	struct prestera_rif *rif;

	rif = mvsw_pr_rif_find(sw, dev);

	if (rif)
		rif->is_active = false;
	/* TODO:
	 * - stp state set (BLOCKING)
	 * - vid learning set (true)
	 */
}

static int
mvsw_pr_port_router_join(struct prestera_port *port,
			 struct net_device *dev,
			 struct netlink_ext_ack *extack)
{
	struct prestera_switch *sw = port->sw;

	struct mvsw_pr_rif_params params = {
		.dev = dev,
	};
	struct prestera_rif *rif;

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

void prestera_port_router_leave(struct prestera_port *port)
{
	struct prestera_rif *rif;

	/* TODO:
	 * - stp state set (BLOCKING)
	 * - vid learning set (true)
	 */

	rif = mvsw_pr_rif_find(port->sw, port->net_dev);
	if (rif) {
		rif->is_active = false;
		mvsw_pr_rif_put(rif);
	}
}

static int mvsw_pr_rif_fdb_op(struct prestera_rif *rif, const char *mac,
			      bool adding)
{
	if (adding)
		prestera_macvlan_add(rif->sw, mvsw_pr_rif_vr_id(rif), mac,
				     rif->iface.vlan_id);
	else
		prestera_macvlan_del(rif->sw, mvsw_pr_rif_vr_id(rif), mac,
				     rif->iface.vlan_id);

	return 0;
}

static int mvsw_pr_rif_macvlan_add(struct prestera_switch *sw,
				   const struct net_device *macvlan_dev,
				   struct netlink_ext_ack *extack)
{
	struct macvlan_dev *vlan = netdev_priv(macvlan_dev);
	struct prestera_rif *rif;
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

static void __mvsw_pr_rif_macvlan_del(struct prestera_switch *sw,
				      const struct net_device *macvlan_dev)
{
	struct macvlan_dev *vlan = netdev_priv(macvlan_dev);
	struct prestera_rif *rif;

	rif = mvsw_pr_rif_find(sw, vlan->lowerdev);
	if (!rif)
		return;

	mvsw_pr_rif_fdb_op(rif, macvlan_dev->dev_addr,  false);
}

static void mvsw_pr_rif_macvlan_del(struct prestera_switch *sw,
				    const struct net_device *macvlan_dev)
{
	__mvsw_pr_rif_macvlan_del(sw, macvlan_dev);
}

static int mvsw_pr_inetaddr_macvlan_event(struct prestera_switch *sw,
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

static int mvsw_pr_router_port_check_rif_addr(struct prestera_switch *sw,
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
	struct prestera_port *port = netdev_priv(port_dev);

	MVSW_LOG_ERROR("dev=%s", port_dev->name);

	switch (event) {
	case NETDEV_UP:
		if (netif_is_bridge_port(port_dev) ||
		    netif_is_lag_port(port_dev) || netif_is_ovs_port(port_dev))
			return 0;
		return mvsw_pr_port_router_join(port, port_dev, extack);
	case NETDEV_DOWN:
		prestera_port_router_leave(port);
		break;
	}

	return 0;
}

static int mvsw_pr_inetaddr_bridge_event(struct prestera_switch *sw,
					 struct net_device *dev,
					 unsigned long event,
					 struct netlink_ext_ack *extack)
{
	struct mvsw_pr_rif_params params = {
		.dev = dev,
	};
	struct prestera_rif *rif;

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
	struct prestera_port *port = netdev_priv(port_dev);
	struct prestera_port_vlan *mvsw_pr_port_vlan;

	mvsw_pr_port_vlan = prestera_port_vlan_find_by_vid(port, vid);
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

static int mvsw_pr_inetaddr_vlan_event(struct prestera_switch *sw,
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

	if (prestera_netdev_check(real_dev))
		return mvsw_pr_inetaddr_port_vlan_event(vlan_dev, real_dev,
							event, vid, extack);
	else if (netif_is_bridge_master(real_dev) && br_vlan_enabled(real_dev))
		return mvsw_pr_inetaddr_bridge_event(sw, vlan_dev, event,
						     extack);

	return 0;
}

static int mvsw_pr_inetaddr_lag_event(struct prestera_switch *sw,
				      struct net_device *lag_dev,
				      unsigned long event,
				      struct netlink_ext_ack *extack)
{
	struct mvsw_pr_rif_params params = {
		.dev = lag_dev,
	};
	struct prestera_rif *rif;

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

static int __mvsw_pr_inetaddr_event(struct prestera_switch *sw,
				    struct net_device *dev,
				    unsigned long event,
				    struct netlink_ext_ack *extack)
{
	if (prestera_netdev_check(dev))
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
mvsw_pr_rif_should_config(struct prestera_rif *rif, struct net_device *dev,
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
	struct prestera_router *router;
	struct prestera_switch *sw;
	struct prestera_rif *rif;
	int err = 0;

	/* Wait until previously created works finished (e.g. neigh events) */
	mvsw_owq_flush();
	/* NETDEV_UP event is handled by mvsw_pr_inetaddr_valid_event */
	if (event == NETDEV_UP)
		goto out;

	MVSW_LOG_ERROR("dev=%s", dev->name);
	router = container_of(nb, struct prestera_router, inetaddr_nb);
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

int prestera_inetaddr_valid_event(struct notifier_block *unused,
				  unsigned long event, void *ptr)
{
	struct in_validator_info *ivi = (struct in_validator_info *)ptr;
	struct net_device *dev = ivi->ivi_dev->dev;
	struct prestera_switch *sw;
	struct prestera_rif *rif;
	int err = 0;

	sw = prestera_switch_get(dev);
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

static bool mvsw_pr_fi_is_hw_direct(struct prestera_switch *sw,
				    struct fib_info *fi)
{
	struct fib_nh *fib_nh;
	struct prestera_rif *rif;

	if (!mvsw_pr_fi_is_direct(fi))
		return false;

	fib_nh = fib_info_nh(fi, 0);
	rif = mvsw_pr_rif_find(sw, fib_nh->fib_nh_dev);
	if (!rif || !rif->is_active)
		return false;

	return true;
}

static bool mvsw_pr_fi_is_nh(struct fib_info *fi)
{
	if (fi->fib_type != RTN_UNICAST)
		return false;

	return !__mvsw_pr_fi_is_direct(fi);
}

static void __mvsw_pr_nh_neigh_destroy(struct prestera_switch *sw,
				       struct prestera_nh_neigh *neigh)
{
	neigh->key.rif->ref_cnt--;
	mvsw_pr_rif_put(neigh->key.rif);
	rhashtable_remove_fast(&sw->router->nh_neigh_ht,
			       &neigh->ht_node,
			       __mvsw_pr_nh_neigh_ht_params);
	kfree(neigh);
}

static struct prestera_nh_neigh *
__mvsw_pr_nh_neigh_create(struct prestera_switch *sw,
			  struct prestera_nh_neigh_key *key)
{
	struct prestera_nh_neigh *neigh;
	int err;

	neigh = kzalloc(sizeof(*neigh), GFP_KERNEL);
	if (!neigh)
		goto err_kzalloc;

	memcpy(&neigh->key, key, sizeof(*key));
	neigh->key.rif->ref_cnt++;
	neigh->info.connected = false;
	INIT_LIST_HEAD(&neigh->nexthop_group_list);
	INIT_LIST_HEAD(&neigh->nh_mangle_entry_list);
	err = rhashtable_insert_fast(&sw->router->nh_neigh_ht,
				     &neigh->ht_node,
				     __mvsw_pr_nh_neigh_ht_params);
	if (err)
		goto err_rhashtable_insert;

	return neigh;

err_rhashtable_insert:
	neigh->key.rif->ref_cnt--;
	mvsw_pr_rif_put(neigh->key.rif);
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
					  key, __mvsw_pr_nh_neigh_ht_params);
	return IS_ERR(nh_neigh) ? NULL : nh_neigh;
}

struct prestera_nh_neigh *
prestera_nh_neigh_get(struct prestera_switch *sw,
		      struct prestera_nh_neigh_key *key)
{
	struct prestera_nh_neigh *neigh;

	neigh = prestera_nh_neigh_find(sw, key);
	if (!neigh)
		return __mvsw_pr_nh_neigh_create(sw, key);

	return neigh;
}

void prestera_nh_neigh_put(struct prestera_switch *sw,
			   struct prestera_nh_neigh *neigh)
{
	if (list_empty(&neigh->nexthop_group_list) &&
	    list_empty(&neigh->nh_mangle_entry_list))
		__mvsw_pr_nh_neigh_destroy(sw, neigh);
}

/* Updates new mvsw_pr_neigh_info */
static int mvsw_pr_nh_neigh_set(struct prestera_switch *sw,
				struct prestera_nh_neigh *neigh)
{
	struct mvsw_pr_nh_neigh_head *nh_head;
	struct mvsw_pr_nexthop_group *nh_grp;
	struct prestera_nh_mangle_entry *nm;
	int err;

	list_for_each_entry(nh_head, &neigh->nexthop_group_list, head) {
		nh_grp = nh_head->this;
		err = mvsw_pr_nexthop_group_set(sw, nh_grp);
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

static bool mvsw_pr_nh_neigh_key_is_valid(struct prestera_nh_neigh_key *key)
{
	return memchr_inv(key, 0, sizeof(*key)) ? true : false;
}

static bool
mvsw_pr_nh_neigh_util_hw_state(struct prestera_switch *sw,
			       struct prestera_nh_neigh *nh_neigh)
{
	bool state;
	struct mvsw_pr_nh_neigh_head *nh_head, *tmp;
	struct prestera_nh_mangle_entry  *nm, *nm_tmp;

	state = false;
	list_for_each_entry_safe(nh_head, tmp,
				 &nh_neigh->nexthop_group_list, head) {
		state = mvsw_pr_nexthop_group_util_hw_state(sw, nh_head->this);
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

static struct mvsw_pr_nexthop_group *
__mvsw_pr_nexthop_group_create(struct prestera_switch *sw,
			       struct prestera_nexthop_group_key *key)
{
	struct mvsw_pr_nexthop_group *nh_grp;
	struct prestera_nh_neigh *nh_neigh;
	int nh_cnt, err, gid;

	nh_grp = kzalloc(sizeof(*nh_grp), GFP_KERNEL);
	if (!nh_grp)
		goto err_kzalloc;

	memcpy(&nh_grp->key, key, sizeof(*key));
	for (nh_cnt = 0; nh_cnt < PRESTERA_NHGR_SIZE_MAX; nh_cnt++) {
		if (!mvsw_pr_nh_neigh_key_is_valid(&nh_grp->key.neigh[nh_cnt])
		   )
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

	err = mvsw_pr_nexthop_group_set(sw, nh_grp);
	if (err)
		goto err_nexthop_group_set;

	err = rhashtable_insert_fast(&sw->router->nexthop_group_ht,
				     &nh_grp->ht_node,
				     __mvsw_pr_nexthop_group_ht_params);
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
__mvsw_pr_nexthop_group_destroy(struct prestera_switch *sw,
				struct mvsw_pr_nexthop_group *nh_grp)
{
	struct prestera_nh_neigh *nh_neigh;
	int nh_cnt;

	rhashtable_remove_fast(&sw->router->nexthop_group_ht,
			       &nh_grp->ht_node,
			       __mvsw_pr_nexthop_group_ht_params);

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

static struct mvsw_pr_nexthop_group *
mvsw_pr_nexthop_group_find(struct prestera_switch *sw,
			   struct prestera_nexthop_group_key *key)
{
	struct mvsw_pr_nexthop_group *nh_grp;

	nh_grp = rhashtable_lookup_fast(&sw->router->nexthop_group_ht,
					key, __mvsw_pr_nexthop_group_ht_params);
	return IS_ERR(nh_grp) ? NULL : nh_grp;
}

static struct mvsw_pr_nexthop_group *
mvsw_pr_nexthop_group_get(struct prestera_switch *sw,
			  struct prestera_nexthop_group_key *key)
{
	struct mvsw_pr_nexthop_group *nh_grp;

	nh_grp = mvsw_pr_nexthop_group_find(sw, key);
	if (!nh_grp)
		return __mvsw_pr_nexthop_group_create(sw, key);

	return nh_grp;
}

static void mvsw_pr_nexthop_group_put(struct prestera_switch *sw,
				      struct mvsw_pr_nexthop_group *nh_grp)
{
	if (!nh_grp->ref_cnt)
		__mvsw_pr_nexthop_group_destroy(sw, nh_grp);
}

/* Updates with new nh_neigh's info */
static int mvsw_pr_nexthop_group_set(struct prestera_switch *sw,
				     struct mvsw_pr_nexthop_group *nh_grp)
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
mvsw_pr_nexthop_group_util_hw_state(struct prestera_switch *sw,
				    struct mvsw_pr_nexthop_group *nh_grp)
{
	int err;
	u32 buf_size = sw->size_tbl_router_nexthop / 8 + 1;
	u32 gid = nh_grp->grp_id;
	u8 *cache = sw->router->nhgrp_hw_state_cache;

	/* Antijitter
	 * Prevent situation, when we read state of nh_grp twice in short time,
	 * and state bit is still cleared on second call. So just stuck active
	 * state for MVSW_PR_NH_ACTIVE_JIFFER_FILTER, after last occurred.
	 */
	if (!time_before(jiffies, sw->router->nhgrp_hw_cache_kick +
			msecs_to_jiffies(MVSW_PR_NH_ACTIVE_JIFFER_FILTER))) {
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

static struct mvsw_pr_fib_node *
mvsw_pr_fib_node_find(struct prestera_switch *sw, struct prestera_fib_key *key)
{
	struct mvsw_pr_fib_node *fib_node;

	fib_node = rhashtable_lookup_fast(&sw->router->fib_ht, key,
					  __mvsw_pr_fib_ht_params);
	return IS_ERR(fib_node) ? NULL : fib_node;
}

static void __mvsw_pr_fib_node_destruct(struct prestera_switch *sw,
					struct mvsw_pr_fib_node *fib_node)
{
	struct mvsw_pr_vr *vr;

	vr = fib_node->info.vr;
	prestera_lpm_del(sw, vr->hw_vr_id, &fib_node->key.addr,
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

static void mvsw_pr_fib_node_destroy(struct prestera_switch *sw,
				     struct mvsw_pr_fib_node *fib_node)
{
	__mvsw_pr_fib_node_destruct(sw, fib_node);
	rhashtable_remove_fast(&sw->router->fib_ht, &fib_node->ht_node,
			       __mvsw_pr_fib_ht_params);
	kfree(fib_node);
}

static void mvsw_pr_fib_node_destroy_ht(struct prestera_switch *sw)
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

		rhashtable_walk_stop(&iter);
		__mvsw_pr_fib_node_destruct(sw, node);
		rhashtable_walk_start(&iter);
		tnode = node;
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
}

/* nh_grp_key valid only if fib_type == MVSW_PR_FIB_TYPE_UC_NH */
static struct mvsw_pr_fib_node *
mvsw_pr_fib_node_create(struct prestera_switch *sw,
			struct prestera_fib_key *key,
			enum mvsw_pr_fib_type fib_type,
			struct prestera_nexthop_group_key *nh_grp_key)
{
	struct mvsw_pr_fib_node *fib_node;
	u32 grp_id;
	struct mvsw_pr_vr *vr;
	int err;

	fib_node = kzalloc(sizeof(*fib_node), GFP_KERNEL);
	if (!fib_node)
		goto err_kzalloc;

	memcpy(&fib_node->key, key, sizeof(*key));
	fib_node->info.type = fib_type;

	vr = mvsw_pr_vr_get(sw, key->tb_id, NULL);
	if (IS_ERR(vr))
		goto err_vr_get;

	fib_node->info.vr = vr;
	vr->ref_cnt++;

	switch (fib_type) {
	case MVSW_PR_FIB_TYPE_TRAP:
		grp_id = MVSW_PR_NHGR_UNUSED;
		break;
	case MVSW_PR_FIB_TYPE_DROP:
		grp_id = MVSW_PR_NHGR_DROP;
		break;
	case MVSW_PR_FIB_TYPE_UC_NH:
		fib_node->info.nh_grp = mvsw_pr_nexthop_group_get(sw,
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


	err = prestera_lpm_add(sw, vr->hw_vr_id, &key->addr,
			       key->prefix_len, grp_id);
	if (err)
		goto err_lpm_add;

	err = rhashtable_insert_fast(&sw->router->fib_ht, &fib_node->ht_node,
				     __mvsw_pr_fib_ht_params);
	if (err)
		goto err_ht_insert;

	return fib_node;

err_ht_insert:
	prestera_lpm_del(sw, vr->hw_vr_id, &key->addr, key->prefix_len);
err_lpm_add:
	if (fib_type == MVSW_PR_FIB_TYPE_UC_NH) {
		fib_node->info.nh_grp->ref_cnt--;
		mvsw_pr_nexthop_group_put(sw, fib_node->info.nh_grp);
	}
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
		   &fib_node->key.addr, sizeof(struct prestera_ip_addr)))
		return false;

	return true;
}

static void mvsw_pr_router_fib_abort(struct prestera_switch *sw)
{
	mvsw_pr_vr_util_hw_abort(sw);
	mvsw_pr_fib_node_destroy_ht(sw);
	mvsw_pr_k_arb_abort(sw);
}

struct mvsw_pr_fib_event_work {
	struct work_struct work;
	struct prestera_switch *sw;
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
	struct prestera_switch *sw = fib_work->sw;
	int err;

	mvsw_owq_lock();

	if (sw->router->aborted)
		goto out;

	switch (fib_work->event) {
	case FIB_EVENT_ENTRY_REPLACE:
		err = mvsw_pr_k_arb_fib_evt(sw, true, &fib_work->fen_info);
		if (err)
			goto abort_out;

		break;
	case FIB_EVENT_ENTRY_DEL:
		err = mvsw_pr_k_arb_fib_evt(sw, false, &fib_work->fen_info);
		if (err)
			MVSW_LOG_ERROR("Cant delete %pI4n/%d",
				       &fib_work->fen_info.dst,
				       fib_work->fen_info.dst_len);

		break;
	}

	goto out;

abort_out:
	dev_err(sw->dev->dev, "Error when processing %pI4h/%d",
		&fib_work->fen_info.dst,
		fib_work->fen_info.dst_len);
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
	struct prestera_switch *sw = fib_work->sw;
	struct fib_nh *fib_nh = fib_work->fnh_info.fib_nh;

	mvsw_owq_lock();

	if (sw->router->aborted)
		goto out;

	/* For now provided only deletion */
	if (fib_work->event == FIB_EVENT_NH_DEL)
		mvsw_pr_k_arb_nh_evt(sw, false, fib_nh);

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
	struct prestera_router *router;
	struct fib_info *fi;

	if (info->family != AF_INET)
		return NOTIFY_DONE;

	router = container_of(nb, struct prestera_router, fib_nb);

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

			if (fib_info_num_path(fi) > PRESTERA_NHGR_SIZE_MAX) {
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
	struct prestera_router *router;

	/* Flush pending FIB notifications and then flush the device's
	 * table before requesting another dump. The FIB notification
	 * block is unregistered, so no need to take RTNL.
	 * No neighbours are expected to be present since FIBs  are not
	 * registered yet
	 */
	router = container_of(nb, struct prestera_router, fib_nb);
	flush_workqueue(mvsw_r_owq);
	flush_workqueue(mvsw_r_wq);
	mvsw_pr_fib_node_destroy_ht(router->sw);
}

static int
mvsw_pr_router_port_change(struct prestera_rif *rif)
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
mvsw_pr_router_port_pre_change(struct prestera_rif *rif,
			       struct netdev_notifier_pre_changeaddr_info *info)
{
	struct netlink_ext_ack *extack;

	extack = netdev_notifier_info_to_extack(&info->info);
	return mvsw_pr_router_port_check_rif_addr(rif->sw, rif->dev,
						  info->dev_addr, extack);
}

int prestera_netdevice_router_port_event(struct net_device *dev,
					 unsigned long event, void *ptr)
{
	struct prestera_switch *sw;
	struct prestera_rif *rif;

	sw = prestera_switch_get(dev);
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

static int mvsw_pr_port_vrf_join(struct prestera_switch *sw,
				 struct net_device *dev,
				 struct netlink_ext_ack *extack)
{
	struct prestera_rif *rif;

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

static void mvsw_pr_port_vrf_leave(struct prestera_switch *sw,
				   struct net_device *dev,
				   struct netlink_ext_ack *extack)
{
	struct prestera_rif *rif;
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

int prestera_netdevice_vrf_event(struct net_device *dev, unsigned long event,
				 struct netdev_notifier_changeupper_info *info)
{
	struct prestera_switch *sw = prestera_switch_get(dev);
	struct netlink_ext_ack *extack = NULL;
	int err = 0;

	if (!sw || netif_is_macvlan(dev))
		return 0;

	mvsw_owq_flush();

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
	struct prestera_rif *rif = priv->data;

	if (!netif_is_macvlan(dev))
		return 0;

	return mvsw_pr_rif_fdb_op(rif, dev->dev_addr, false);
}

static int mvsw_pr_rif_macvlan_flush(struct prestera_rif *rif)
{
	struct netdev_nested_priv priv = {
		.data = (void *)rif,
	};

	if (!netif_is_macvlan_port(rif->dev))
		return 0;

	netdev_warn(rif->dev,
		    "Router interface is deleted. Upper macvlans will not work\n");
	return netdev_walk_all_upper_dev_rcu(rif->dev,
					     __mvsw_pr_rif_macvlan_flush,
					     &priv);
}

#ifdef CONFIG_IP_ROUTE_MULTIPATH
static int mvsw_pr_mp_hash_init(struct prestera_switch *sw)
{
	u8 hash_policy;

	hash_policy = init_net.ipv4.sysctl_fib_multipath_hash_policy;
	return  prestera_mp4_hash_set(sw, hash_policy);
}
#else
static int mvsw_pr_mp_hash_init(struct prestera_switch *sw)
{
	return 0;
}
#endif

static struct notifier_block mvsw_pr_inetaddr_valid_nb __read_mostly = {
	.notifier_call = prestera_inetaddr_valid_event,
};

int prestera_router_init(struct prestera_switch *sw)
{
	struct prestera_router *router;
	int err, nhgrp_cache_bytes;

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

	nhgrp_cache_bytes = sw->size_tbl_router_nexthop / 8 + 1;
	router->nhgrp_hw_state_cache = kzalloc(nhgrp_cache_bytes, GFP_KERNEL);
	if (!router->nhgrp_hw_state_cache)
		return -ENOMEM;

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

static void mvsw_pr_rifs_fini(struct prestera_switch *sw)
{
	struct prestera_rif *rif, *tmp;

	list_for_each_entry_safe(rif, tmp, &sw->router->rif_list, router_node) {
		rif->is_active = false;
		mvsw_pr_rif_destroy(rif);
	}
}

void prestera_router_fini(struct prestera_switch *sw)
{
	unregister_fib_notifier(&init_net, &sw->router->fib_nb);
	unregister_netevent_notifier(&sw->router->netevent_nb);
	unregister_inetaddr_notifier(&sw->router->inetaddr_nb);
	unregister_inetaddr_validator_notifier(&mvsw_pr_inetaddr_valid_nb);
	mvsw_pr_neigh_fini(sw);
	/* TODO: check if vrs necessary ? */
	mvsw_pr_rifs_fini(sw);
	mvsw_pr_k_arb_abort(sw);

	rhashtable_destroy(&sw->router->kern_neigh_cache_ht);
	rhashtable_destroy(&sw->router->kern_fib_cache_ht);
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

static struct mvsw_pr_vr *__mvsw_pr_vr_find(struct prestera_switch *sw,
					    u32 tb_id)
{
	struct mvsw_pr_vr *vr;

	list_for_each_entry(vr, &sw->router->vr_list, router_node) {
		if (vr->tb_id == tb_id)
			return vr;
	}

	return NULL;
}

static struct mvsw_pr_vr *__mvsw_pr_vr_create(struct prestera_switch *sw,
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

static void __mvsw_pr_vr_destroy(struct prestera_switch *sw,
				 struct mvsw_pr_vr *vr)
{
	mvsw_pr_hw_vr_delete(sw, vr->hw_vr_id);
	list_del(&vr->router_node);
	kfree(vr);
}

static struct mvsw_pr_vr *mvsw_pr_vr_get(struct prestera_switch *sw, u32 tb_id,
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

static void mvsw_pr_vr_put(struct prestera_switch *sw, struct mvsw_pr_vr *vr)
{
	if (!vr->ref_cnt)
		__mvsw_pr_vr_destroy(sw, vr);
}

static void mvsw_pr_vr_util_hw_abort(struct prestera_switch *sw)
{
	struct mvsw_pr_vr *vr, *vr_tmp;

	list_for_each_entry_safe(vr, vr_tmp,
				 &sw->router->vr_list, router_node)
		mvsw_pr_hw_vr_abort(sw, vr->hw_vr_id);
}

static struct prestera_rif*
mvsw_pr_rif_alloc(struct prestera_switch *sw,
		  struct mvsw_pr_vr *vr,
		  const struct mvsw_pr_rif_params *params)
{
	struct prestera_rif *rif;
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

static int mvsw_pr_rif_offload(struct prestera_rif *rif)
{
	return mvsw_pr_hw_rif_create(rif->sw, &rif->iface, rif->addr,
				     &rif->rif_id);
}

static struct prestera_rif *mvsw_pr_rif_create(struct prestera_switch *sw,
					       const struct mvsw_pr_rif_params
					       *params,
					       struct netlink_ext_ack *extack)
{
	u32 tb_id = mvsw_pr_fix_tb_id(l3mdev_fib_table(params->dev));
	struct prestera_rif *rif;
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

static int mvsw_pr_rif_delete(struct prestera_rif *rif)
{
	return mvsw_pr_hw_rif_delete(rif->sw, rif->rif_id, &rif->iface);
}

static void mvsw_pr_rif_destroy(struct prestera_rif *rif)
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

static void mvsw_pr_rif_put(struct prestera_rif *rif)
{
	if (!rif->ref_cnt && !rif->is_active)
		mvsw_pr_rif_destroy(rif);
}

void prestera_rif_enable(struct prestera_switch *sw,
			 struct net_device *dev, bool enable)
{
	struct prestera_rif *rif;

	rif = mvsw_pr_rif_find(sw, dev);
	if (!rif)
		return;

	if (enable)
		mvsw_pr_rif_offload(rif);
	else
		mvsw_pr_rif_delete(rif);
}

static int mvsw_pr_rif_update(struct prestera_rif *rif, char *mac)
{
	return mvsw_pr_hw_rif_set(rif->sw, &rif->rif_id, &rif->iface, mac);
}

static int mvsw_pr_rif_vr_update(struct prestera_switch *sw,
				 struct prestera_rif *rif,
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

void prestera_router_lag_member_leave(const struct prestera_port *port,
				      const struct net_device *dev)
{
	struct prestera_rif *rif;
	u16 vr_id;

	rif = mvsw_pr_rif_find(port->sw, dev);
	if (!rif)
		return;

	vr_id = mvsw_pr_rif_vr_id(rif);
	prestera_lag_member_rif_leave(port, port->lag_id, vr_id);
}

void prestera_lag_router_leave(struct prestera_switch *sw,
			       struct net_device *lag_dev)
{
	struct prestera_rif *rif;

	rif = mvsw_pr_rif_find(sw, lag_dev);
	if (rif) {
		rif->is_active = false;
		mvsw_pr_rif_put(rif);
	}
}

static int mvsw_pr_bridge_device_rif_put(struct net_device *dev,
					 struct netdev_nested_priv *priv)
{
	struct prestera_switch *sw = priv->data;
	struct prestera_rif *rif;

	rif = mvsw_pr_rif_find(sw, dev);
	if (rif) {
		/* Hold refcnt, because "is_active = false" may cause freeing */
		rif->ref_cnt++;
		rif->is_active = false;
		mvsw_pr_k_arb_rif_evt(sw, rif);
		rif->ref_cnt--;
		mvsw_pr_rif_put(rif);
	}

	return 0;
}

void prestera_bridge_device_rifs_destroy(struct prestera_switch *sw,
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

struct prestera_neigh_info *
prestera_kern_neigh_cache_to_neigh_info(struct prestera_kern_neigh_cache *nc)
{
	return &nc->nh_neigh_info;
}
