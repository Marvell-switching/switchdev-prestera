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
#include <net/ip6_route.h>
#include <linux/rhashtable.h>

#include "prestera.h"
#include "prestera_ct.h"
#include "prestera_hw.h"
#include "prestera_log.h"
#include "prestera_router_hw.h"

#define MVSW_PR_IMPLICITY_RESOLVE_DEAD_NEIGH
#define MVSW_PR_NH_PROBE_INTERVAL 5000 /* ms */

static const char mvsw_driver_name[] = "mrvl_switchdev";

/* Represent kernel object */
struct prestera_rif {
	struct net_device *dev;
	struct prestera_rif_entry_key rif_entry_key; /* Key to hw object */
	unsigned char addr[ETH_ALEN];
	u32 kern_tb_id; /* tb_id from kernel (not fixed) */
	struct list_head router_node;
	bool is_active;
	unsigned int ref_cnt;
};

struct mvsw_pr_rif_params {
	struct net_device *dev;
	u16 vid;
};

struct prestera_fib {
	struct prestera_switch *sw;
	struct notifier_block fib_nb;
	struct notifier_block netevent_nb;
};

enum mvsw_pr_mp_hash_policy {
	MVSW_MP_L3_HASH_POLICY,
	MVSW_MP_L4_HASH_POLICY,
	MVSW_MP_HASH_POLICY_MAX,
};

struct prestera_kern_neigh_cache_key {
	struct prestera_ip_addr addr;
	struct prestera_rif *rif;
};

struct prestera_kern_neigh_cache {
	struct prestera_kern_neigh_cache_key key;
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
		enum prestera_fib_type fib_type;
		struct prestera_nexthop_group_key nh_grp_key;
	} lpm_info; /* hold prepared lpm info */
	/* Indicate if route is not overlapped by another table */
	bool reachable;
	struct rhash_head ht_node; /* node of mvsw_pr_router */
	struct mvsw_pr_kern_neigh_cache_head {
		struct mvsw_pr_kern_fib_cache *this;
		struct list_head head;
		struct prestera_kern_neigh_cache *n_cache;
	} kern_neigh_cache_head[PRESTERA_NHGR_SIZE_MAX];
	union {
		struct fib_notifier_info info; /* point to any of 4/6 */
		struct fib6_entry_notifier_info fen6_info;
		struct fib_entry_notifier_info fen4_info;
	};
};

/* This is definition to hold links to kern_neigh_cache.
 * Used for techincal purposes.
 */
struct prestera_kern_nc_lnode {
	struct list_head head;
	struct prestera_kern_neigh_cache *nc;
};

static const struct rhashtable_params __mvsw_pr_kern_neigh_cache_ht_params = {
	.key_offset  = offsetof(struct prestera_kern_neigh_cache, key),
	.head_offset = offsetof(struct prestera_kern_neigh_cache, ht_node),
	.key_len     = sizeof(struct prestera_kern_neigh_cache_key),
	.automatic_shrinking = true,
};

/* This is definition to hold links to kern_fib_cache.
 * Used for techincal purposes.
 */
struct prestera_kern_fc_lnode {
	struct list_head head;
	struct mvsw_pr_kern_fib_cache *fc;
};

static const struct rhashtable_params __mvsw_pr_kern_fib_cache_ht_params = {
	.key_offset  = offsetof(struct mvsw_pr_kern_fib_cache, key),
	.head_offset = offsetof(struct mvsw_pr_kern_fib_cache, ht_node),
	.key_len     = sizeof(struct mvsw_pr_kern_fib_cache_key),
	.automatic_shrinking = true,
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
/* static void mvsw_owq_flush(void)
 * {
 *         if (rtnl_trylock())
 *                 panic("%s: called without rtnl_lock !", __func__);
 *
 *         mutex_lock(&mvsw_owq_mutex_wip);
 *         WRITE_ONCE(mvsw_owq_flushing, true);
 *         mutex_unlock(&mvsw_owq_mutex_wip);
 *
 *         flush_workqueue(mvsw_r_owq);
 *
 *         mutex_lock(&mvsw_owq_mutex_wip);
 *         WRITE_ONCE(mvsw_owq_flushing, false);
 *         mutex_unlock(&mvsw_owq_mutex_wip);
 * }
 */

static const unsigned char mvsw_pr_mac_mask[ETH_ALEN] = {
	0xff, 0xff, 0xff, 0xff, 0xfc, 0x00
};

static u32 mvsw_pr_fix_tb_id(u32 tb_id);
static struct prestera_rif *
prestera_rif_create(struct prestera_switch *sw,
		    const struct mvsw_pr_rif_params *params,
		    struct netlink_ext_ack *extack);
static void prestera_rif_destroy(struct prestera_switch *sw,
				 struct prestera_rif *rif);
static void prestera_rif_put(struct prestera_switch *sw,
			     struct prestera_rif *rif);
static int prestera_rif_update(struct prestera_switch *sw,
			       struct net_device *dev);
static struct prestera_rif *mvsw_pr_rif_find(const struct prestera_switch *sw,
					     const struct net_device *dev);
static bool prestera_fi_is_direct(struct fib_info *fi);
static bool prestera_fi_is_nh(struct fib_info *fi);
static bool prestera_fi6_is_direct(struct fib6_info *fi);
static bool prestera_fi6_is_nh(struct fib6_info *fi);
static bool prestera_fib_info_is_direct(struct fib_notifier_info *info);
static bool prestera_fib_info_is_nh(struct fib_notifier_info *info);
static bool
mvsw_pr_fib_node_util_is_neighbour(struct prestera_fib_node *fib_node);
static int
mvsw_pr_util_fi2nh_gr_key(struct prestera_switch *sw, struct fib_info *fi,
			  size_t limit,
			  struct prestera_nexthop_group_key *grp_key);

static struct fib_nh_common *
prestera_kern_fib_info_nhc(struct fib_notifier_info *info, int n)
{
	struct fib6_entry_notifier_info *fen6_info;
	struct fib_entry_notifier_info *fen4_info;

	if (info->family == AF_INET) {
		fen4_info = container_of(info, struct fib_entry_notifier_info,
					 info);
		return &fib_info_nh(fen4_info->fi, n)->nh_common;
	} else if (info->family == AF_INET6) {
		fen6_info = container_of(info, struct fib6_entry_notifier_info,
					 info);
		return &fen6_info->rt->fib6_nh[n].nh_common;
	}

	return NULL;
}

static int prestera_kern_fib_info_nhs(struct fib_notifier_info *info)
{
	struct fib6_entry_notifier_info *fen6_info;
	struct fib_entry_notifier_info *fen4_info;

	if (info->family == AF_INET) {
		fen4_info = container_of(info, struct fib_entry_notifier_info,
					 info);
		return fib_info_num_path(fen4_info->fi);
	} else if (info->family == AF_INET6) {
		fen6_info = container_of(info, struct fib6_entry_notifier_info,
					 info);
		/* TODO: ECMP in ipv6 is several routes.
		 * Every route has single nh.
		 */
		return fen6_info->rt->fib6_nh ? 1 : 0;
	}

	return 0;
}

static unsigned char
prestera_kern_fib_info_type(struct fib_notifier_info *info)
{
	struct fib6_entry_notifier_info *fen6_info;
	struct fib_entry_notifier_info *fen4_info;

	if (info->family == AF_INET) {
		fen4_info = container_of(info, struct fib_entry_notifier_info,
					 info);
		return fen4_info->fi->fib_type;
	} else if (info->family == AF_INET6) {
		fen6_info = container_of(info, struct fib6_entry_notifier_info,
					 info);
		/* TODO: ECMP in ipv6 is several routes.
		 * Every route has single nh.
		 */
		return fen6_info->rt->fib6_type;
	}

	return RTN_UNSPEC;
}

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
		vid = prestera_vlan_dev_vlan_id(sw, dev);
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

static int prestera_dev2iface(struct prestera_switch *sw,
			      struct net_device *dev,
			      struct prestera_iface *iface)
{
	struct prestera_port *port = netdev_priv(dev);

	memset(iface, 0, sizeof(*iface));
	iface->type = prestera_dev_if_type(dev);
	switch (iface->type) {
	case PRESTERA_IF_PORT_E:
		iface->dev_port.hw_dev_num = port->dev_id;
		iface->dev_port.port_num = port->hw_id;
		break;
	case PRESTERA_IF_LAG_E:
		prestera_lag_id_find(sw, dev, &iface->lag_id);
		break;
	case PRESTERA_IF_VID_E:
		iface->vlan_id = mvsw_pr_nh_dev_to_vid(sw, dev);
		break;
	default:
		pr_err("Unsupported rif type");
		return -EINVAL;
	}

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
	case PRESTERA_IF_PORT_E:
	case PRESTERA_IF_VID_E:
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
	case PRESTERA_IF_LAG_E:
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
prestera_util_kern_set_nh_offload(struct fib_nh_common *nhc, bool offloaded,
				  bool trap)
{
		if (offloaded)
			nhc->nhc_flags |= RTNH_F_OFFLOAD;
		else
			nhc->nhc_flags &= ~RTNH_F_OFFLOAD;

		if (trap)
			nhc->nhc_flags |= RTNH_F_TRAP;
		else
			nhc->nhc_flags &= ~RTNH_F_TRAP;
}

/* must be called with rcu_read_lock() */
static int prestera_util_kern_get_route(struct fib_result *res, u32 tb_id,
					__be32 *addr)
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
	fl4.daddr = *addr;
	ret = fib_table_lookup(tb, &fl4, res, FIB_LOOKUP_NOREF);
	if (ret)
		return ret;

	return 0;
}

/* must be called with rcu_read_lock() */
static int prestera_util_kern_get_route6(struct fib6_result *res, u32 tb_id,
					 struct in6_addr *addr)
{
	struct fib6_table *tb;
	struct flowi6 fl6;
	int err;

	/* TODO: walkthrough appropriate tables in kernel
	 * to know if the same prefix exists in several tables
	 */
	tb = ipv6_stub->fib6_get_table(&init_net, tb_id);
	if (!tb)
		return -ENOENT;

	memset(&fl6, 0, sizeof(fl6));
	fl6.daddr = *addr;
	fl6.flowi6_flags |= FLOWI_FLAG_SKIP_NH_OIF;
	err = ipv6_stub->fib6_table_lookup(&init_net, tb, 0 /* oif */, &fl6,
					   res, RT6_LOOKUP_F_DST_NOREF);
	if (err)
		return err;

	return 0;
}

int prestera_util_kern_dip2nh_grp_key(struct prestera_switch *sw,
				      u32 tb_id, struct prestera_ip_addr *addr,
				      struct prestera_nexthop_group_key *res)
{
	int err;
	struct fib_result fib_res;
	struct fib_nh *fib_nh;
	struct prestera_rif *rif;

	/* TODO: support IPv6 */
	if (addr->v != PRESTERA_IPV4)
		return 0;

	err = prestera_util_kern_get_route(&fib_res, tb_id, &addr->u.ipv4);
	if (err)
		return 0;

	if (prestera_fi_is_direct(fib_res.fi)) {
		fib_nh = fib_info_nh(fib_res.fi, 0);
		memset(res, 0, sizeof(*res));
		res->neigh[0].addr = *addr;
		rif = mvsw_pr_rif_find(sw, fib_nh->fib_nh_dev);
		if (!rif || !rif->is_active)
			return 0;

		res->neigh[0].rif = rif;
		return 1;
	}

	return mvsw_pr_util_fi2nh_gr_key(sw, fib_res.fi,
					 PRESTERA_NHGR_SIZE_MAX, res);
}

static void
prestera_util_n_cache_key2nh_key(struct prestera_kern_neigh_cache_key *ck,
				 struct prestera_nh_neigh_key *nk)
{
	memset(nk, 0, sizeof(*nk));
	nk->addr = ck->addr;
	nk->rif = (void *)ck->rif;
}

static bool
__prestera_util_kern_n_is_reachable_v4(u32 tb_id, __be32 *addr,
				       struct net_device *dev)
{
	bool reachable;
	struct fib_nh *fib_nh;
	struct fib_result res;

	reachable = false;

	if (!prestera_util_kern_get_route(&res, tb_id, addr))
		if (prestera_fi_is_direct(res.fi)) {
			fib_nh = fib_info_nh(res.fi, 0);
			if (dev == fib_nh->fib_nh_dev)
				reachable = true;
		}

	return reachable;
}

static bool
__prestera_util_kern_n_is_reachable_v6(u32 tb_id, struct in6_addr *addr,
				       struct net_device *dev)
{
	bool reachable;
	struct fib_nh_common *nhc;
	struct fib6_result res;

	reachable = false;

	if (!prestera_util_kern_get_route6(&res, tb_id, addr))
		if (prestera_fi6_is_direct(res.f6i)) {
			nhc = &res.f6i->fib6_nh->nh_common;
			if (dev == nhc->nhc_dev)
				reachable = true;
		}

	return reachable;
}

/* Check if neigh route is reachable */
static bool
prestera_util_kern_n_is_reachable(u32 tb_id,
				  struct prestera_ip_addr *addr,
				  struct net_device *dev)
{
	if (addr->v == PRESTERA_IPV4)
		return __prestera_util_kern_n_is_reachable_v4(tb_id,
							      &addr->u.ipv4,
							      dev);
	else
		return __prestera_util_kern_n_is_reachable_v6(tb_id,
							      &addr->u.ipv6,
							      dev);
}

static bool
prestera_util_fi_is_point2dev(struct fib_notifier_info *info,
			      const struct net_device *dev)
{
	int nhs, i;
	struct fib_nh_common *nhc;

	nhs = prestera_kern_fib_info_nhs(info);
	for (i = 0; i < nhs; i++) {
		nhc = prestera_kern_fib_info_nhc(info, i);
		if (nhc->nhc_dev == dev)
			return true;
	}

	return false;
}

static int
prestera_util_nhc2nh_neigh_key(struct prestera_switch *sw,
			       struct fib_nh_common *nhc,
			       struct prestera_nh_neigh_key *nh_key)
{
	struct prestera_rif *rif;

	memset(nh_key, 0, sizeof(*nh_key));
	if (nhc->nhc_gw_family == AF_INET) {
		nh_key->addr.v = PRESTERA_IPV4;
		nh_key->addr.u.ipv4 = nhc->nhc_gw.ipv4;
	} else if (nhc->nhc_gw_family == AF_INET6) {
		nh_key->addr.v = PRESTERA_IPV6;
		nh_key->addr.u.ipv6 = nhc->nhc_gw.ipv6;
	} else {
		return -EOPNOTSUPP;
	}

	rif = mvsw_pr_rif_find(sw, nhc->nhc_dev);
	if (!rif || !rif->is_active)
		return -ENOENT;

	nh_key->rif = rif;
	return 0;
}

static int
prestera_util_fc2nh_gr_key(struct prestera_switch *sw,
			   struct mvsw_pr_kern_fib_cache *fc,
			   struct prestera_nexthop_group_key *grp_key)
{
	int i;

	memset(grp_key, 0, sizeof(*grp_key));
	for (i = 0; i < PRESTERA_NHGR_SIZE_MAX; i++) {
		if (!fc->kern_neigh_cache_head[i].n_cache)
			break;

		grp_key->neigh[i].addr =
			fc->kern_neigh_cache_head[i].n_cache->key.addr;
		grp_key->neigh[i].rif =
			fc->kern_neigh_cache_head[i].n_cache->key.rif;
	}

	return i;
}

static int
mvsw_pr_util_fi2nh_gr_key(struct prestera_switch *sw, struct fib_info *fi,
			  size_t limit,
			  struct prestera_nexthop_group_key *grp_key)
{
	int i, nhs, err;
	struct fib_nh *fib_nh;

	if (!prestera_fi_is_nh(fi))
		return 0;

	nhs = fib_info_num_path(fi);
	if (nhs > limit)
		return 0;

	memset(grp_key, 0, sizeof(*grp_key));
	for (i = 0; i < nhs; i++) {
		fib_nh = fib_info_nh(fi, i);
		err = prestera_util_nhc2nh_neigh_key(sw, &fib_nh->nh_common,
						     &grp_key->neigh[i]);
		if (err)
			return 0;
	}

	return nhs;
}

static void
prestera_util_fen_info2fib_cache_key(struct fib_notifier_info *info,
				     struct mvsw_pr_kern_fib_cache_key *key)
{
	struct fib6_entry_notifier_info *fen6_info =
		container_of(info, struct fib6_entry_notifier_info, info);
	struct fib_entry_notifier_info *fen_info =
		container_of(info, struct fib_entry_notifier_info, info);

	memset(key, 0, sizeof(*key));
	if (info->family == AF_INET) {
		key->addr.v = PRESTERA_IPV4;
		key->addr.u.ipv4 = cpu_to_be32(fen_info->dst);
		key->prefix_len = fen_info->dst_len;
		key->kern_tb_id = fen_info->tb_id;
	} else if (info->family == AF_INET6) {
		key->addr.v = PRESTERA_IPV6;
		key->addr.u.ipv6 = fen6_info->rt->fib6_dst.addr;
		key->prefix_len = fen6_info->rt->fib6_dst.plen;
		key->kern_tb_id = fen6_info->rt->fib6_table->tb6_id;
	}
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

static int
prestera_util_nhc2n_cache_key(struct prestera_switch *sw,
			      struct fib_nh_common *nhc,
			      struct prestera_kern_neigh_cache_key *nk)
{
	struct prestera_rif *rif;

	memset(nk, 0, sizeof(*nk));
	if (nhc->nhc_gw_family == AF_INET) {
		nk->addr.v = PRESTERA_IPV4;
		nk->addr.u.ipv4 = nhc->nhc_gw.ipv4;
	} else {
		nk->addr.v = PRESTERA_IPV6;
		nk->addr.u.ipv6 = nhc->nhc_gw.ipv6;
	}
	rif = mvsw_pr_rif_find(sw, nhc->nhc_dev);
	if (!rif || !rif->is_active)
		return -ENOENT;

	nk->rif = rif;
	return 0;
}

static bool
prestera_util_nhc_eq_n_cache_key(struct prestera_switch *sw,
				 struct fib_nh_common *nhc,
				 struct prestera_kern_neigh_cache_key *nk)
{
	int err;
	struct prestera_kern_neigh_cache_key tk;

	err = prestera_util_nhc2n_cache_key(sw, nhc, &tk);
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
	if (n->tbl->family == AF_INET) {
		key->addr.v = PRESTERA_IPV4;
		key->addr.u.ipv4 = *(__be32 *)n->primary_key;
	} else if (n->tbl->family == AF_INET6) {
		key->addr.v = PRESTERA_IPV6;
		key->addr.u.ipv6 = *(struct in6_addr *)n->primary_key;
	} else {
		return -ENOENT;
	}

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
	prestera_rif_put(sw, n_cache->key.rif);
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
	prestera_rif_put(sw, n_cache->key.rif);
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

	if (fib_cache->key.addr.v == PRESTERA_IPV4)
		fib_info_put(fib_cache->fen4_info.fi);
	else if (fib_cache->key.addr.v == PRESTERA_IPV6)
		fib6_info_release(fib_cache->fen6_info.rt);

	rhashtable_remove_fast(&sw->router->kern_fib_cache_ht,
			       &fib_cache->ht_node,
			       __mvsw_pr_kern_fib_cache_ht_params);
	kfree(fib_cache);
}

static int
__prestera_kern_fib_cache_create_nhs4(struct prestera_switch *sw,
				      struct mvsw_pr_kern_fib_cache *fc)
{
	struct prestera_kern_neigh_cache *n_cache;
	struct prestera_nh_neigh_key nh_key;
	struct fib_nh_common *nhc;
	int i, nhs, err;

	if (!prestera_fib_info_is_nh(&fc->info))
		return 0;

	nhs = prestera_kern_fib_info_nhs(&fc->info);
	if (nhs > PRESTERA_NHGR_SIZE_MAX)
		return 0;

	for (i = 0; i < nhs; i++) {
		nhc = prestera_kern_fib_info_nhc(&fc->fen4_info.info, i);
		err = prestera_util_nhc2nh_neigh_key(sw, nhc, &nh_key);
		if (err)
			return 0;

		n_cache = mvsw_pr_kern_neigh_cache_get(sw, &nh_key);
		if (!n_cache)
			return 0;

		fc->kern_neigh_cache_head[i].this = fc;
		fc->kern_neigh_cache_head[i].n_cache = n_cache;
		list_add(&fc->kern_neigh_cache_head[i].head,
			 &n_cache->kern_fib_cache_list);
	}

	return 0;
}

static int
__prestera_kern_fib_cache_create_nhs6(struct prestera_switch *sw,
				      struct mvsw_pr_kern_fib_cache *fc)
{
	struct prestera_kern_neigh_cache *n_cache;
	struct fib6_info *fi = fc->fen6_info.rt;
	struct prestera_nh_neigh_key nh_key;
	struct fib_nh_common *nhc;
	int i, nhs, err;

	if (!prestera_fi6_is_nh(fi))
		return 0;

	nhs = prestera_kern_fib_info_nhs(&fc->fen6_info.info);
	if (nhs > PRESTERA_NHGR_SIZE_MAX)
		return 0;

	for (i = 0; i < nhs; i++) {
		nhc = &fi->fib6_nh[i].nh_common;
		err = prestera_util_nhc2nh_neigh_key(sw, nhc, &nh_key);
		if (err)
			return 0;

		n_cache = mvsw_pr_kern_neigh_cache_get(sw, &nh_key);
		if (!n_cache)
			return 0;

		fc->kern_neigh_cache_head[i].this = fc;
		fc->kern_neigh_cache_head[i].n_cache = n_cache;
		list_add(&fc->kern_neigh_cache_head[i].head,
			 &n_cache->kern_fib_cache_list);
	}

	return 0;
}

/* Operations on fi (offload, etc) must be wrapped in utils.
 * This function just create storage.
 */
static struct mvsw_pr_kern_fib_cache *
prestera_kern_fib_cache_create(struct prestera_switch *sw,
			       struct mvsw_pr_kern_fib_cache_key *key,
			       struct fib_notifier_info *info)
{
	struct fib6_entry_notifier_info *fen6_info =
		container_of(info, struct fib6_entry_notifier_info, info);
	struct fib_entry_notifier_info *fen_info =
		container_of(info, struct fib_entry_notifier_info, info);
	struct mvsw_pr_kern_fib_cache *fib_cache;
	int err;

	/* Sanity */
	if (key->addr.v == PRESTERA_IPV4) {
		if (info->family != AF_INET) {
			WARN_ON(1);
			return NULL;
		}
	} else if (key->addr.v == PRESTERA_IPV6) {
		if (info->family != AF_INET6) {
			WARN_ON(1);
			return NULL;
		}
	} else {
		return NULL;
	}

	fib_cache = kzalloc(sizeof(*fib_cache), GFP_KERNEL);
	if (!fib_cache)
		goto err_kzalloc;

	memcpy(&fib_cache->key, key, sizeof(*key));

	if (key->addr.v == PRESTERA_IPV4) {
		fib_info_hold(fen_info->fi);
		memcpy(&fib_cache->fen4_info, fen_info, sizeof(*fen_info));
	} else {
		fib6_info_hold(fen6_info->rt);
		memcpy(&fib_cache->fen6_info, fen6_info, sizeof(*fen6_info));
	}

	err = rhashtable_insert_fast(&sw->router->kern_fib_cache_ht,
				     &fib_cache->ht_node,
				     __mvsw_pr_kern_fib_cache_ht_params);
	if (err)
		goto err_ht_insert;

	/* Handle nexthops */
	if (key->addr.v == PRESTERA_IPV4)
		err = __prestera_kern_fib_cache_create_nhs4(sw, fib_cache);
	else
		err = __prestera_kern_fib_cache_create_nhs6(sw, fib_cache);

	if (err)
		goto out; /* Not critical */

out:
	return fib_cache;

err_ht_insert:
	if (key->addr.v == PRESTERA_IPV4)
		fib_info_hold(fen_info->fi);
	else
		fib6_info_release(fen6_info->rt);

	kfree(fib_cache);
err_kzalloc:
	return NULL;
}

static void
__prestera_k_arb_fib_nh_offload_set(struct prestera_switch *sw,
				    struct mvsw_pr_kern_fib_cache *fibc,
				    struct prestera_kern_neigh_cache *nc,
				    bool offloaded, bool trap)
{
	int i, nhs;
	struct fib_nh_common *nhc;

	nhs = prestera_kern_fib_info_nhs(&fibc->info);
	for (i = 0; i < nhs; i++) {
		nhc = prestera_kern_fib_info_nhc(&fibc->info, i);
		if (!nc) {
			prestera_util_kern_set_nh_offload(nhc, offloaded, trap);
			continue;
		}

		if (prestera_util_nhc_eq_n_cache_key(sw, nhc, &nc->key)) {
			prestera_util_kern_set_nh_offload(nhc, offloaded, trap);
			break;
		}
	}
}

static void
__prestera_k_arb_fib_lpm_offload_set(struct prestera_switch *sw,
				     struct mvsw_pr_kern_fib_cache *fc,
				     bool fail, bool offload, bool trap)
{
	struct fib_rt_info fri;

	switch (fc->key.addr.v) {
	case PRESTERA_IPV4:
		fri.fi = fc->fen4_info.fi;
		fri.tb_id = fc->key.kern_tb_id;
		fri.dst = fc->key.addr.u.ipv4;
		fri.dst_len = fc->key.prefix_len;
		fri.tos = fc->fen4_info.tos;
		fri.type = fc->fen4_info.type;
		/* flags begin */
		fri.offload = offload;
		fri.trap = trap;
		fri.offload_failed = fail;
		/* flags end */
		fib_alias_hw_flags_set(&init_net, &fri);
		return;
	case PRESTERA_IPV6:
		fib6_info_hw_flags_set(&init_net, fc->fen6_info.rt,
				       offload, trap, fail);
		return;
	}
}

static void
__mvsw_pr_k_arb_n_offload_set(struct prestera_switch *sw,
			      struct prestera_kern_neigh_cache *nc,
			      bool offloaded)
{
	struct neighbour *n;

	if (nc->key.addr.v == PRESTERA_IPV4)
		n = neigh_lookup(&arp_tbl, &nc->key.addr.u.ipv4,
				 nc->key.rif->dev);
	else if (nc->key.addr.v == PRESTERA_IPV6)
		n = neigh_lookup(&nd_tbl, &nc->key.addr.u.ipv6,
				 nc->key.rif->dev);
	else
		n = NULL;

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
	struct mvsw_pr_kern_fib_cache_key fc_key;
	struct mvsw_pr_kern_fib_cache *fib_cache;
	struct prestera_fib_key fib_key;
	struct prestera_fib_node *fib_node;
	struct prestera_nexthop_group_key nh_grp_key;

	/* Exception for fc with prefix 32: LPM entry is already used by fib */
	memset(&fc_key, 0, sizeof(fc_key));
	fc_key.addr = n_cache->key.addr;
	fc_key.prefix_len = PRESTERA_IP_ADDR_PLEN(n_cache->key.addr.v);
	/* But better to use tb_id of route, which pointed to this neighbour. */
	/* We take it from rif, because rif inconsistent.
	 * Must be separated in_rif and out_rif.
	 */
	fc_key.kern_tb_id = n_cache->key.rif->kern_tb_id;
	fib_cache = mvsw_pr_kern_fib_cache_find(sw, &fc_key);
	if (!fib_cache || !fib_cache->reachable) {
		memset(&fib_key, 0, sizeof(fib_key));
		fib_key.addr = n_cache->key.addr;
		fib_key.prefix_len = PRESTERA_IP_ADDR_PLEN(n_cache->key.addr.v);
		fib_key.tb_id = mvsw_pr_fix_tb_id(n_cache->key.rif->kern_tb_id);
		fib_node = prestera_fib_node_find(sw, &fib_key);
		if (!enabled && fib_node) {
			if (mvsw_pr_fib_node_util_is_neighbour(fib_node))
				prestera_fib_node_destroy(sw, fib_node);
			return;
		}
	}

	if (enabled && !fib_node) {
		memset(&nh_grp_key, 0, sizeof(nh_grp_key));
		prestera_util_n_cache_key2nh_key(&n_cache->key,
						 &nh_grp_key.neigh[0]);
		fib_node = prestera_fib_node_create(sw, &fib_key,
						    PRESTERA_FIB_TYPE_UC_NH,
						    &nh_grp_key);
		if (!fib_node)
			MVSW_LOG_ERROR("%s failed ip=%pI4n",
				       "prestera_fib_node_create",
				       &fib_key.addr.u.ipv4);
		return;
	}
}

static void
__mvsw_pr_k_arb_nc_kern_fib_fetch(struct prestera_switch *sw,
				  struct prestera_kern_neigh_cache *nc)
{
	if (prestera_util_kern_n_is_reachable(nc->key.rif->kern_tb_id,
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
	struct prestera_rif_entry *re;
	int err;

	memset(&nc->nh_neigh_info, 0, sizeof(nc->nh_neigh_info));
	if (nc->key.addr.v == PRESTERA_IPV4)
		n = neigh_lookup(&arp_tbl, &nc->key.addr.u.ipv4,
				 nc->key.rif->dev);
	else if (nc->key.addr.v == PRESTERA_IPV6)
		n = neigh_lookup(&nd_tbl, &nc->key.addr.u.ipv6,
				 nc->key.rif->dev);
	else
		n = NULL;

	if (!n)
		goto out;

	read_lock_bh(&n->lock);
	if (n->nud_state & NUD_VALID && !n->dead) {
		err = mvsw_pr_neigh_iface_init(sw, &nc->nh_neigh_info.iface, n);
		if (err) {
			/* TODO: message for ipv6 */
			MVSW_LOG_ERROR("Cannot initialize iface for %pI4n %pM",
				       n->primary_key, &n->ha[0]);
			goto n_read_out;
		}
		/* This line is dirty.
		 * We add it, because there is vlan, wich mapped by vr_id.
		 * But this is incorrect. Because nh is pointed to vlan, not vr!
		 * If kernel will manage routing vlans - this will be more
		 * logicaly.
		 */
		re = prestera_rif_entry_find(sw, &nc->key.rif->rif_entry_key);
		if (re)
			nc->nh_neigh_info.iface.vr_id = re->vr->hw_vr_id;
		else
			goto n_read_out;

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
	struct prestera_nh_neigh_key nh_key;
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
	/* Note: should be no such lines here. It's iincorrect static NAT. */
	port_hw_id = nc->key.rif->rif_entry_key.iface.dev_port.port_num;
	port_dev_id = nc->key.rif->rif_entry_key.iface.dev_port.hw_dev_num;
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
	prestera_util_n_cache_key2nh_key(&nc->key, &nh_key);
	nh_neigh = prestera_nh_neigh_find(sw, &nh_key);
	if (!nh_neigh)
		goto out;

	/* Do hw update only if something changed to prevent nh flap */
	if (memcmp(&nc->nh_neigh_info, &nh_neigh->info,
		   sizeof(nh_neigh->info))) {
		memcpy(&nh_neigh->info, &nc->nh_neigh_info,
		       sizeof(nh_neigh->info));
		err = prestera_nh_neigh_set(sw, nh_neigh);
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
		__prestera_k_arb_fib_nh_offload_set(sw, nhead->this, nc,
						    nc->in_kernel,
						    !nc->in_kernel);
	}
}

static void __mvsw_pr_k_arb_hw_state_upd(struct prestera_switch *sw,
					 struct prestera_kern_neigh_cache *nc)
{
	bool hw_active;
	struct prestera_nh_neigh_key nh_key;
	struct prestera_nh_neigh *nh_neigh;
	struct neighbour *n;

	prestera_util_n_cache_key2nh_key(&nc->key, &nh_key);
	nh_neigh = prestera_nh_neigh_find(sw, &nh_key);
	if (!nh_neigh) {
		MVSW_LOG_ERROR("Cannot find nh_neigh for cached %pI4n",
			       &nc->key.addr.u.ipv4);
		return;
	}

	hw_active = prestera_nh_neigh_util_hw_state(sw, nh_neigh);

#ifdef MVSW_PR_IMPLICITY_RESOLVE_DEAD_NEIGH
	if (!hw_active && nc->in_kernel)
		goto out;
#else /* MVSW_PR_IMPLICITY_RESOLVE_DEAD_NEIGH */
	if (!hw_active)
		goto out;
#endif /* MVSW_PR_IMPLICITY_RESOLVE_DEAD_NEIGH */

	if (nc->key.addr.v == PRESTERA_IPV4) {
		n = neigh_lookup(&arp_tbl, &nc->key.addr.u.ipv4,
				 nc->key.rif->dev);
		if (!n)
			n = neigh_create(&arp_tbl, &nc->key.addr.u.ipv4,
					 nc->key.rif->dev);
	} else if (nc->key.addr.v == PRESTERA_IPV6) {
		n = neigh_lookup(&nd_tbl, &nc->key.addr.u.ipv6,
				 nc->key.rif->dev);
		if (!n)
			n = neigh_create(&nd_tbl, &nc->key.addr.u.ipv6,
					 nc->key.rif->dev);
	} else {
		n = NULL;
	}

	if (!IS_ERR(n) && n) {
		neigh_event_send(n, NULL);
		neigh_release(n);
	} else {
		MVSW_LOG_ERROR("Cannot create neighbour %pI4n",
			       &nc->key.addr.u.ipv4);
	}

out:
	return;
}

static int __mvsw_pr_k_arb_f_lpm_set(struct prestera_switch *sw,
				     struct mvsw_pr_kern_fib_cache *fc,
				     bool enabled)
{
	struct prestera_fib_node *fib_node;

	fib_node = prestera_fib_node_find(sw, &fc->lpm_info.fib_key);
	if (fib_node)
		prestera_fib_node_destroy(sw, fib_node);

	if (!enabled)
		return 0;

	fib_node = prestera_fib_node_create(sw, &fc->lpm_info.fib_key,
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

static int
__prestera_pr_k_arb_fc_lpm_info_calc(struct prestera_switch *sw,
				     struct mvsw_pr_kern_fib_cache *fc)
{
	int nh_cnt;
	struct prestera_rif *rif;
	struct fib_nh_common *nhc;

	memset(&fc->lpm_info, 0, sizeof(fc->lpm_info));

	switch (prestera_kern_fib_info_type(&fc->info)) {
	case RTN_UNICAST:
		if (prestera_fib_info_is_direct(&fc->info) &&
		    fc->key.prefix_len ==
			PRESTERA_IP_ADDR_PLEN(fc->key.addr.v)) {
			/* This is special case.
			 * When prefix is 32. Than we will have conflict in lpm
			 * for direct route - once TRAP added, there is no
			 * place for neighbour entry. So represent direct route
			 * with prefix 32, as NH. So neighbour will be resolved
			 * as nexthop of this route.
			 */
			nhc = prestera_kern_fib_info_nhc(&fc->info, 0);
			rif = mvsw_pr_rif_find(sw, nhc->nhc_dev);
			/* If we realy can access this route via HW */
			if (!rif || !rif->is_active) {
				fc->lpm_info.fib_type = PRESTERA_FIB_TYPE_TRAP;
			} else {
				fc->lpm_info.fib_type = PRESTERA_FIB_TYPE_UC_NH;
				fc->lpm_info.nh_grp_key.neigh[0].addr =
					fc->key.addr;
				fc->lpm_info.nh_grp_key.neigh[0].rif = rif;
			}

			break;
		}

		/* We can also get nh_grp_key from fi. This will be correct to
		 * because cache not always represent, what actually written to
		 * lpm. But we use nh cache, as well for now (for this case).
		 */
		nh_cnt = prestera_util_fc2nh_gr_key(sw, fc,
						    &fc->lpm_info.nh_grp_key);
		fc->lpm_info.fib_type = nh_cnt ?
					PRESTERA_FIB_TYPE_UC_NH :
					PRESTERA_FIB_TYPE_TRAP;
		break;
	/* Unsupported. Leave it for kernel: */
	case RTN_BROADCAST:
	case RTN_MULTICAST:
	/* Routes we must trap by design: */
	case RTN_LOCAL:
	case RTN_UNREACHABLE:
	case RTN_PROHIBIT:
		fc->lpm_info.fib_type = PRESTERA_FIB_TYPE_TRAP;
		break;
	case RTN_BLACKHOLE:
		fc->lpm_info.fib_type = PRESTERA_FIB_TYPE_DROP;
		break;
	default:
		MVSW_LOG_ERROR("Unsupported fib_type");
		return -EOPNOTSUPP;
	}

	mvsw_pr_util_fib_cache_key2fib_key(&fc->key,
					   &fc->lpm_info.fib_key);
	return 0;
}

static int __mvsw_pr_k_arb_fc_apply(struct prestera_switch *sw,
				    struct mvsw_pr_kern_fib_cache *fc)
{
	int err;

	err = __prestera_pr_k_arb_fc_lpm_info_calc(sw, fc);
	if (err)
		return err;

	err = __mvsw_pr_k_arb_f_lpm_set(sw, fc, fc->reachable);
	if (err) {
		__prestera_k_arb_fib_lpm_offload_set(sw, fc,
						     true, false, false);
		return err;
	}

	switch (fc->lpm_info.fib_type) {
	case PRESTERA_FIB_TYPE_UC_NH:
		/* let nc_apply manage nexthops */
		__prestera_k_arb_fib_lpm_offload_set(sw, fc, false,
						     fc->reachable, false);
		break;
	case PRESTERA_FIB_TYPE_TRAP:
		__prestera_k_arb_fib_lpm_offload_set(sw, fc, false,
						     false, fc->reachable);
		break;
	case PRESTERA_FIB_TYPE_DROP:
		__prestera_k_arb_fib_lpm_offload_set(sw, fc, false, true,
						     false);
		break;
	case PRESTERA_FIB_TYPE_INVALID:
		break;
	}

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
			if (!list_empty(&n_cache->kern_fib_cache_list)) {
				WARN_ON(1); /* BUG */
				continue;
			}
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
			__prestera_k_arb_fib_lpm_offload_set(sw, fib_cache,
							     true, false,
							     false);
			__prestera_k_arb_fib_nh_offload_set(sw, fib_cache, NULL,
							    false, false);
			/* No need to destroy lpm.
			 * It will be aborted by destroy_ht
			 */
			mvsw_pr_kern_fib_cache_destroy(sw, fib_cache);
		}
	}
}

static void prestera_k_arb_flush(struct prestera_switch *sw)
{
	/* Function to remove all arbiter entries and related hw objects. */
	/* Sequence:
	 *   1) Clear arbiter tables, but don't touch hw
	 *   2) Clear hw
	 * We use such approach, because arbiter object is not directly mapped
	 * to hw. So deletion of one arbiter object may even lead to creation of
	 * hw object (e.g. in case of overlapped routes).
	 */
	__mvsw_pr_k_arb_abort_fib(sw);
	__mvsw_pr_k_arb_abort_neigh(sw);

	/* Clear hw layer */
	prestera_fib_node_destroy_ht(sw);
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
			__mvsw_pr_k_arb_nc_kern_n_fetch(sw, n_cache);
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
		      struct fib_notifier_info *info)
{
	struct mvsw_pr_kern_fib_cache_key fc_key;
	struct mvsw_pr_kern_fib_cache *fib_cache;
	struct mvsw_pr_kern_fib_cache *tfib_cache, *bfib_cache;
	int err;

	prestera_util_fen_info2fib_cache_key(info, &fc_key);
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
			if (err)
				MVSW_LOG_ERROR("Applying fib_cache btm failed");
		}

		mvsw_pr_kern_fib_cache_destroy(sw, fib_cache);
	}

	if (replace) {
		fib_cache = prestera_kern_fib_cache_create(sw, &fc_key, info);
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
		if (err)
			MVSW_LOG_ERROR("Applying fib_cache failed");
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

	err = prestera_util_nhc2nh_neigh_key(sw, &fib_nh->nh_common, &nkey);
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
	struct fib6_entry_notifier_info fen6_info;
	struct fib_entry_notifier_info fen4_info;
	struct fib_notifier_info *info;
	struct mvsw_pr_kern_fib_cache_key key;
	struct mvsw_pr_kern_fib_cache *new_fc;
	bool reachable;

	memcpy(&key, &fc->key, sizeof(key));
	if (key.addr.v == PRESTERA_IPV4) {
		memcpy(&fen4_info, &fc->fen4_info, sizeof(fen4_info));
		fib_info_hold(fen4_info.fi);
		info = &fen4_info.info;
	} else if (key.addr.v == PRESTERA_IPV6) {
		memcpy(&fen6_info, &fc->fen6_info, sizeof(fen6_info));
		fib6_info_hold(fen6_info.rt);
		info = &fen6_info.info;
	} else {
		return NULL;
	}
	reachable = fc->reachable;

	fc->reachable = false;
	__mvsw_pr_k_arb_fc_apply(sw, fc);
	mvsw_pr_kern_fib_cache_destroy(sw, fc);

	new_fc = prestera_kern_fib_cache_create(sw, &key, info);
	if (key.addr.v == PRESTERA_IPV4)
		fib_info_put(fen4_info.fi);
	else if (key.addr.v == PRESTERA_IPV6)
		fib6_info_release(fen6_info.rt);

	if (!new_fc)
		return NULL;

	new_fc->reachable = reachable;
	__mvsw_pr_k_arb_fc_apply(sw, new_fc);

	return new_fc;
}

static void mvsw_pr_k_arb_rif_evt(struct prestera_switch *sw,
				  struct prestera_rif *rif)
{
	struct prestera_kern_nc_lnode *nc_lnode;
	struct prestera_kern_fc_lnode *fc_lnode;
	struct prestera_kern_neigh_cache *nc;
	struct mvsw_pr_kern_fib_cache *fc;
	struct rhashtable_iter iter;
	struct list_head tmp_list;

	/* Walk every fc, which related to rif and set to trap */
	INIT_LIST_HEAD(&tmp_list);
	rhashtable_walk_enter(&sw->router->kern_fib_cache_ht, &iter);
	rhashtable_walk_start(&iter);
	while ((fc = rhashtable_walk_next(&iter))) {
		if (IS_ERR(fc))
			continue;

		if (prestera_util_fi_is_point2dev(&fc->info, rif->dev)) {
			fc_lnode = kzalloc(sizeof(*fc_lnode), GFP_ATOMIC);
			if (WARN_ON(!fc_lnode))
				break;

			fc_lnode->fc = fc;
			list_add(&fc_lnode->head, &tmp_list);
		}
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
	while (!list_empty(&tmp_list)) {
		fc_lnode = list_last_entry(&tmp_list,
					   struct prestera_kern_fc_lnode, head);

		WARN_ON(!__mvsw_pr_k_arb_fc_rebuild(sw, fc_lnode->fc));

		list_del(&fc_lnode->head);
		kfree(fc_lnode);
	}

	/* Destroy every nc, which related to rif */
	INIT_LIST_HEAD(&tmp_list);
	rhashtable_walk_enter(&sw->router->kern_neigh_cache_ht, &iter);
	rhashtable_walk_start(&iter);
	while ((nc = rhashtable_walk_next(&iter))) {
		if (IS_ERR(nc))
			continue;

		if (nc->key.rif == rif) {
			nc_lnode = kzalloc(sizeof(*nc_lnode), GFP_ATOMIC);
			if (WARN_ON(!nc_lnode))
				break;

			nc_lnode->nc = nc;
			list_add(&nc_lnode->head, &tmp_list);
		}
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
	while (!list_empty(&tmp_list)) {
		nc_lnode = list_last_entry(&tmp_list,
					   struct prestera_kern_nc_lnode, head);

		nc_lnode->nc->in_kernel = false;
		__mvsw_pr_k_arb_nc_apply(sw, nc_lnode->nc);
		WARN_ON(mvsw_pr_kern_neigh_cache_put(sw, nc_lnode->nc));

		list_del(&nc_lnode->head);
		kfree(nc_lnode);
	}
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

	mvsw_pr_k_arb_n_evt(sw, n);

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
		if (n->tbl->family != AF_INET && n->tbl->family != AF_INET6)
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

	mvsw_pr_k_arb_hw_evt(router->sw);

	rtnl_unlock();
	mvsw_pr_router_neighs_update_interval_init(router);
	queue_delayed_work(mvsw_r_wq, &router->neighs_update.dw,
			   msecs_to_jiffies(router->neighs_update.interval));
}

static int prestera_neigh_work_init(struct prestera_switch *sw)
{
	mvsw_pr_router_neighs_update_interval_init(sw->router);

	INIT_DELAYED_WORK(&sw->router->neighs_update.dw,
			  mvsw_pr_router_update_neighs_work);
	queue_delayed_work(mvsw_r_wq, &sw->router->neighs_update.dw, 0);
	return 0;
}

static void prestera_neigh_work_fini(struct prestera_switch *sw)
{
	cancel_delayed_work_sync(&sw->router->neighs_update.dw);
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
	struct prestera_port *port = mvsw_pr_port_vlan->port;
	struct prestera_switch *sw = port->sw;

	struct mvsw_pr_rif_params params = {
		.dev = dev,
	};
	struct prestera_rif *rif;

	MVSW_LOG_ERROR("NOT IMPLEMENTED!!!");

	rif = mvsw_pr_rif_find(sw, dev);
	if (!rif)
		rif = prestera_rif_create(sw, &params, extack);

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
	struct prestera_port *port = mvsw_pr_port_vlan->port;
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
		rif = prestera_rif_create(sw, &params, extack);

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
		prestera_rif_put(port->sw, rif);
	}
}

static int mvsw_pr_rif_macvlan_add(struct prestera_switch *sw,
				   const struct net_device *macvlan_dev,
				   struct netlink_ext_ack *extack)
{
	struct macvlan_dev *vlan = netdev_priv(macvlan_dev);
	struct prestera_rif *rif;
	struct prestera_rif_entry *re;
	int err;

	rif = mvsw_pr_rif_find(sw, vlan->lowerdev);
	if (!rif) {
		NL_SET_ERR_MSG_MOD(extack,
				   "macvlan is only supported on top of RIF");
		return -EOPNOTSUPP;
	}

	re = prestera_rif_entry_find(sw, &rif->rif_entry_key);
	if (!re)
		return -ENOENT;

	err = prestera_rif_entry_set_macvlan(sw, re, true,
					     macvlan_dev->dev_addr);
	if (err)
		return err;

	return err;
}

static void __mvsw_pr_rif_macvlan_del(struct prestera_switch *sw,
				      const struct net_device *macvlan_dev)
{
	struct macvlan_dev *vlan = netdev_priv(macvlan_dev);
	struct prestera_rif *rif;
	struct prestera_rif_entry *re;

	rif = mvsw_pr_rif_find(sw, vlan->lowerdev);
	if (!rif)
		return;

	re = prestera_rif_entry_find(sw, &rif->rif_entry_key);
	if (!re)
		return;

	prestera_rif_entry_set_macvlan(sw, re, false, macvlan_dev->dev_addr);
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
			rif = prestera_rif_create(sw, &params, extack);

		if (IS_ERR(rif))
			return PTR_ERR(rif);
		rif->is_active = true;
		break;
	case NETDEV_DOWN:
		rif = mvsw_pr_rif_find(sw, dev);
		if (!rif)
			break;
		rif->is_active = false;
		prestera_rif_put(sw, rif);
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
			rif = prestera_rif_create(sw, &params, extack);

		if (IS_ERR(rif))
			return PTR_ERR(rif);
		rif->is_active = true;
		break;
	case NETDEV_DOWN:
		rif = mvsw_pr_rif_find(sw, lag_dev);
		if (!rif)
			break;
		rif->is_active = false;
		prestera_rif_put(sw, rif);
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
	else if (netif_is_lag_master(dev) && !netif_is_bridge_port(dev))
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
	struct inet6_dev *i6dev;

	switch (event) {
	case NETDEV_UP:
		return !rif;
	case NETDEV_DOWN:
		idev = __in_dev_get_rtnl(dev);
		if (idev && idev->ifa_list)
			addr_list_empty = false;

		i6dev = __in6_dev_get(dev);
		if (i6dev && i6dev->ac_list)
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

static int prestera_inetaddr_valid_event(struct notifier_block *unused,
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

static int prestera_inet6addr_event(struct notifier_block *nb,
				    unsigned long event, void *ptr)
{
	struct inet6_ifaddr *ifa = (struct inet6_ifaddr *)ptr;
	struct net_device *dev = ifa->idev->dev;
	struct prestera_router *router =
		container_of(nb, struct prestera_router, inet6addr_nb);
	struct prestera_rif *rif;
	int err = 0;

	/* NETDEV_UP event is handled by mvsw_pr_inetaddr_valid_event */
	if (event == NETDEV_UP)
		goto out;

	if (netif_is_macvlan(dev))
		goto mac_vlan;

	rif = mvsw_pr_rif_find(router->sw, dev);
	if (!rif)
		goto out;

	if (!mvsw_pr_rif_should_config(rif, dev, event))
		goto out;
mac_vlan:
	err = __mvsw_pr_inetaddr_event(router->sw, dev, event, NULL);
out:
	return notifier_from_errno(err);
}

static int prestera_inet6addr_valid_event(struct notifier_block *nb,
					  unsigned long event, void *ptr)
{
	struct in6_validator_info *ivi = (struct in6_validator_info *)ptr;
	struct net_device *dev = ivi->i6vi_dev->dev;
	struct prestera_router *router =
		container_of(nb, struct prestera_router, inet6addr_valid_nb);
	struct prestera_rif *rif;
	int err = 0;

	rif = mvsw_pr_rif_find(router->sw, dev);
	if (!mvsw_pr_rif_should_config(rif, dev, event))
		goto out;

	err = mvsw_pr_router_port_check_rif_addr(router->sw, dev, dev->dev_addr,
						 ivi->extack);
	if (err)
		goto out;

	err = __mvsw_pr_inetaddr_event(router->sw, dev, event, ivi->extack);
out:
	return notifier_from_errno(err);
}

static bool __prestera_fi_is_direct(struct fib_info *fi)
{
	struct fib_nh *fib_nh;

	if (fib_info_num_path(fi) == 1) {
		fib_nh = fib_info_nh(fi, 0);
		if (fib_nh->fib_nh_scope == RT_SCOPE_HOST)
			return true;
	}

	return false;
}

static bool prestera_fi_is_direct(struct fib_info *fi)
{
	if (fi->fib_type != RTN_UNICAST)
		return false;

	return __prestera_fi_is_direct(fi);
}

static bool prestera_fi_is_nh(struct fib_info *fi)
{
	if (fi->fib_type != RTN_UNICAST)
		return false;

	return !__prestera_fi_is_direct(fi);
}

static bool __prestera_fi6_is_direct(struct fib6_info *fi)
{
	if (!fi->fib6_nh->nh_common.nhc_gw_family)
		return true;

	return false;
}

static bool prestera_fi6_is_direct(struct fib6_info *fi)
{
	if (fi->fib6_type != RTN_UNICAST)
		return false;

	return __prestera_fi6_is_direct(fi);
}

static bool prestera_fi6_is_nh(struct fib6_info *fi)
{
	if (fi->fib6_type != RTN_UNICAST)
		return false;

	return !__prestera_fi6_is_direct(fi);
}

static bool prestera_fib_info_is_direct(struct fib_notifier_info *info)
{
	struct fib6_entry_notifier_info *fen6_info =
		container_of(info, struct fib6_entry_notifier_info, info);
	struct fib_entry_notifier_info *fen_info =
		container_of(info, struct fib_entry_notifier_info, info);

	if (info->family == AF_INET)
		return prestera_fi_is_direct(fen_info->fi);
	else
		return prestera_fi6_is_direct(fen6_info->rt);
}

static bool prestera_fib_info_is_nh(struct fib_notifier_info *info)
{
	struct fib6_entry_notifier_info *fen6_info =
		container_of(info, struct fib6_entry_notifier_info, info);
	struct fib_entry_notifier_info *fen_info =
		container_of(info, struct fib_entry_notifier_info, info);

	if (info->family == AF_INET)
		return prestera_fi_is_nh(fen_info->fi);
	else
		return prestera_fi6_is_nh(fen6_info->rt);
}

/* Decided, that uc_nh route with key==nh is obviously neighbour route */
static bool
mvsw_pr_fib_node_util_is_neighbour(struct prestera_fib_node *fib_node)
{
	if (fib_node->info.type != PRESTERA_FIB_TYPE_UC_NH)
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

struct prestera_fib_event_work {
	struct work_struct work;
	struct prestera_switch *sw;
	union {
		struct fib_entry_notifier_info fen_info;
		struct fib_nh_notifier_info fnh_info;
	};
	unsigned long event;
};

static void prestera_router_fib4_event_work(struct work_struct *work)
{
	struct prestera_fib_event_work *fib_work =
			container_of(work, struct prestera_fib_event_work,
				     work);
	struct prestera_switch *sw = fib_work->sw;
	int err;

	mvsw_owq_lock();

	switch (fib_work->event) {
	case FIB_EVENT_ENTRY_REPLACE:
		err = mvsw_pr_k_arb_fib_evt(sw, true,
					    &fib_work->fen_info.info);
		if (err)
			goto err_out;

		break;
	case FIB_EVENT_ENTRY_DEL:
		err = mvsw_pr_k_arb_fib_evt(sw, false,
					    &fib_work->fen_info.info);
		if (err)
			dev_err(sw->dev->dev, "Cant delete %pI4n/%d",
				&fib_work->fen_info.dst,
				fib_work->fen_info.dst_len);

		break;
	}

	goto out;

err_out:
	dev_err(sw->dev->dev, "Error when processing %pI4h/%d",
		&fib_work->fen_info.dst,
		fib_work->fen_info.dst_len);
out:
	fib_info_put(fib_work->fen_info.fi);
	mvsw_owq_unlock();
	kfree(fib_work);
}

struct prestera_fib6_event_work {
	struct work_struct work;
	struct prestera_switch *sw;
	struct fib6_entry_notifier_info fen_info;
	unsigned long event;
};

static void prestera_router_fib6_event_work(struct work_struct *work)
{
	struct prestera_fib6_event_work *fib_work =
		container_of(work, struct prestera_fib6_event_work,
			     work);
	struct prestera_switch *sw = fib_work->sw;
	int err;

	mvsw_owq_lock();

	switch (fib_work->event) {
	case FIB_EVENT_ENTRY_REPLACE:
		err = mvsw_pr_k_arb_fib_evt(sw, true,
					    &fib_work->fen_info.info);
		if (err)
			goto err_out;

		break;
	case FIB_EVENT_ENTRY_DEL:
		err = mvsw_pr_k_arb_fib_evt(sw, false,
					    &fib_work->fen_info.info);
		if (err)
			dev_err(sw->dev->dev, "Cant delete ipv6 entry");
			/* TODO: more informative message (prefix) */

		break;
	}

	goto out;

err_out:
	dev_err(sw->dev->dev, "Error when processing %pI6h/%d",
		&fib_work->fen_info.rt->fib6_dst.addr,
		fib_work->fen_info.rt->fib6_dst.plen);
out:
	fib6_info_release(fib_work->fen_info.rt);
	mvsw_owq_unlock();
	kfree(fib_work);
}

static void mvsw_pr_router_nh_update_event_work(struct work_struct *work)
{
	struct prestera_fib_event_work *fib_work =
			container_of(work, struct prestera_fib_event_work, work);
	struct prestera_switch *sw = fib_work->sw;
	struct fib_nh *fib_nh = fib_work->fnh_info.fib_nh;

	mvsw_owq_lock();

	/* For now provided only deletion */
	if (fib_work->event == FIB_EVENT_NH_DEL)
		mvsw_pr_k_arb_nh_evt(sw, false, fib_nh);

	fib_info_put(fib_nh->nh_parent);
	mvsw_owq_unlock();
	kfree(fib_work);
	return;
}

static int
__prestera_router_fib4_event(struct prestera_switch *sw, unsigned long event,
			     struct fib_entry_notifier_info *fen_info)
{
	struct prestera_fib_event_work *fib_work;

	if (!fen_info->fi)
		return NOTIFY_DONE;

	/* Sanity */
	if (event == FIB_EVENT_ENTRY_REPLACE) {
		if (fen_info->fi->nh)
			return notifier_from_errno(-EINVAL);

		if (fen_info->fi->fib_nh_is_v6)
			return notifier_from_errno(-EINVAL);
	}

	fib_work = kzalloc(sizeof(*fib_work), GFP_ATOMIC);
	if (WARN_ON(!fib_work))
		return NOTIFY_BAD;

	fib_info_hold(fen_info->fi);
	fib_work->fen_info = *fen_info;
	fib_work->event = event;
	fib_work->sw = sw;
	INIT_WORK(&fib_work->work,
		  prestera_router_fib4_event_work);
	queue_work(mvsw_r_owq, &fib_work->work);

	return NOTIFY_DONE;
}

static int
__prestera_router_fib6_event(struct prestera_switch *sw, unsigned long event,
			     struct fib6_entry_notifier_info *fen_info)
{
	struct prestera_fib6_event_work *fib_work;

	if (!fen_info->rt)
		return NOTIFY_DONE;

	fib_work = kzalloc(sizeof(*fib_work), GFP_ATOMIC);
	if (WARN_ON(!fib_work))
		return NOTIFY_BAD;

	fib6_info_hold(fen_info->rt);
	fib_work->fen_info = *fen_info;
	fib_work->event = event;
	fib_work->sw = sw;
	INIT_WORK(&fib_work->work,
		  prestera_router_fib6_event_work);
	queue_work(mvsw_r_owq, &fib_work->work);

	return NOTIFY_DONE;
}

static int
__prestera_router_nh4_event(struct prestera_switch *sw, unsigned long event,
			    struct fib_nh_notifier_info *fnh_info)
{
	struct prestera_fib_event_work *fib_work;
	struct fib_info *fi;

	if (!fnh_info->fib_nh->nh_parent)
		return NOTIFY_DONE;

	fi = fnh_info->fib_nh->nh_parent;

	fib_work = kzalloc(sizeof(*fib_work), GFP_ATOMIC);
	if (WARN_ON(!fib_work))
		return NOTIFY_BAD;

	fib_info_hold(fi);
	fib_work->fnh_info = *fnh_info;
	fib_work->event = event;
	fib_work->sw = sw;
	INIT_WORK(&fib_work->work, mvsw_pr_router_nh_update_event_work);
	queue_work(mvsw_r_owq, &fib_work->work);

	return NOTIFY_DONE;
}

/* Called with rcu_read_lock() */
static int mvsw_pr_router_fib_event(struct notifier_block *nb,
				    unsigned long event, void *ptr)
{
	struct fib6_entry_notifier_info *fen6_info;
	struct fib_entry_notifier_info *fen_info;
	struct fib_nh_notifier_info *fnh_info;
	struct fib_notifier_info *info = ptr;
	struct prestera_router *router;

	router = container_of(nb, struct prestera_router, fib_nb);

	switch (event) {
	case FIB_EVENT_ENTRY_REPLACE:
	case FIB_EVENT_ENTRY_DEL:
		fen_info = container_of(info, struct fib_entry_notifier_info,
					info);
		fen6_info = container_of(info, struct fib6_entry_notifier_info,
					 info);
		if (info->family == AF_INET)
			return __prestera_router_fib4_event(router->sw, event,
							    fen_info);
		else if (info->family == AF_INET6)
			return __prestera_router_fib6_event(router->sw, event,
							    fen6_info);

		break;
	case FIB_EVENT_NH_DEL:
		if (info->family != AF_INET)
			return NOTIFY_DONE;

		/* Set down nh as fast as possible */
		fnh_info = container_of(info, struct fib_nh_notifier_info,
					info);
		return __prestera_router_nh4_event(router->sw, event, fnh_info);
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
	prestera_k_arb_flush(router->sw);
}

static int
mvsw_pr_router_port_change(struct prestera_switch *sw,
			   struct net_device *dev)
{
	int err;

	err = prestera_rif_update(sw, dev);
	if (err)
		return err;

	netdev_dbg(dev, "Update RIF\n");

	return 0;
}

static int
mvsw_pr_router_port_pre_change(struct prestera_switch *sw,
			       struct net_device *dev,
			       struct netdev_notifier_pre_changeaddr_info *info)
{
	struct netlink_ext_ack *extack;
	struct prestera_rif *rif;

	extack = netdev_notifier_info_to_extack(&info->info);
	rif = mvsw_pr_rif_find(sw, dev);
	if (!rif)
		return 0;

	return mvsw_pr_router_port_check_rif_addr(sw, rif->dev, info->dev_addr,
						  extack);
}

int prestera_netdevice_router_port_event(struct net_device *dev,
					 unsigned long event, void *ptr)
{
	struct prestera_switch *sw;

	sw = prestera_switch_get(dev);
	if (!sw)
		return 0;

	switch (event) {
	case NETDEV_CHANGEADDR:
		return mvsw_pr_router_port_change(sw, dev);
	case NETDEV_PRE_CHANGEADDR:
		return mvsw_pr_router_port_pre_change(sw, dev, ptr);
	}

	return 0;
}

static int mvsw_pr_port_vrf_join(struct prestera_switch *sw,
				 struct net_device *dev,
				 struct netlink_ext_ack *extack)
{
	return prestera_rif_update(sw, dev);
}

static void mvsw_pr_port_vrf_leave(struct prestera_switch *sw,
				   struct net_device *dev,
				   struct netlink_ext_ack *extack)
{
	prestera_rif_update(sw, dev);
}

int prestera_netdevice_vrf_event(struct net_device *dev, unsigned long event,
				 struct netdev_notifier_changeupper_info *info)
{
	struct prestera_switch *sw = prestera_switch_get(dev);
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

	err = prestera_router_hw_init(sw);
	if (err)
		goto err_router_lib_init;

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

	router->inet6addr_valid_nb.notifier_call =
		prestera_inet6addr_valid_event;
	register_inet6addr_validator_notifier(&router->inet6addr_valid_nb);
	router->inet6addr_nb.notifier_call = prestera_inet6addr_event;
	register_inet6addr_notifier(&router->inet6addr_nb);

	err = prestera_neigh_work_init(sw);
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
	prestera_neigh_work_fini(sw);
err_neigh_init:
	unregister_inet6addr_notifier(&router->inet6addr_nb);
	unregister_inet6addr_validator_notifier(&router->inet6addr_valid_nb);
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
err_router_lib_init:
err_mp_hash_init:
	kfree(sw->router);
	return err;
}

static void mvsw_pr_rifs_fini(struct prestera_switch *sw)
{
	struct prestera_rif *rif, *tmp;

	list_for_each_entry_safe(rif, tmp, &sw->router->rif_list, router_node) {
		/* We expect, that rif is holded by is_active.
		 * ref_cnt must already became 0
		 */
		if (rif->ref_cnt || !rif->is_active) {
			WARN_ON(1); /* BUG */
			continue;
		}
		prestera_rif_destroy(sw, rif);
	}
}

void prestera_router_fini(struct prestera_switch *sw)
{
	unregister_fib_notifier(&init_net, &sw->router->fib_nb);
	unregister_netevent_notifier(&sw->router->netevent_nb);
	unregister_inet6addr_notifier(&sw->router->inet6addr_nb);
	unregister_inet6addr_validator_notifier(&sw->router->inet6addr_valid_nb);
	unregister_inetaddr_notifier(&sw->router->inetaddr_nb);
	unregister_inetaddr_validator_notifier(&mvsw_pr_inetaddr_valid_nb);
	prestera_neigh_work_fini(sw);
	destroy_workqueue(mvsw_r_wq);
	destroy_workqueue(mvsw_r_owq);

	/* I not sure, that unregistering notifiers is enough to prevent
	 * arbiter events... We can receive it, e.g. from bridge routine.
	 * So hold rtnl_lock()
	 */
	/* prestera_switchdev_fini() flushing WQ without mvsw_owq_flush().
	 * So lock rtnl here to prevent deadlock.
	 */
	rtnl_lock();

	/* TODO: check if vrs necessary ? */
	prestera_k_arb_flush(sw);
	mvsw_pr_rifs_fini(sw);
	rhashtable_destroy(&sw->router->kern_neigh_cache_ht);
	rhashtable_destroy(&sw->router->kern_fib_cache_ht);
	WARN_ON(!list_empty(&sw->router->rif_list));

	prestera_router_hw_fini(sw);

	kfree(sw->router);
	sw->router = NULL;

	rtnl_unlock();
}

static u32 mvsw_pr_fix_tb_id(u32 tb_id)
{
	if (tb_id == RT_TABLE_UNSPEC ||
	    tb_id == RT_TABLE_LOCAL ||
	    tb_id == RT_TABLE_DEFAULT)
		return tb_id = RT_TABLE_MAIN;

	return tb_id;
}

static int
__prestera_rif_macvlan_offload_cb(struct net_device *dev,
				  struct netdev_nested_priv *priv)
{
	struct prestera_rif_entry *re = priv->data;
	struct prestera_switch *sw = prestera_switch_get(dev);

	if (!netif_is_macvlan(dev))
		return 0;

	return prestera_rif_entry_set_macvlan(sw, re, true, dev->dev_addr);
}

static int __prestera_rif_offload(struct prestera_switch *sw, bool replace,
				  struct prestera_rif *rif)
{
	struct prestera_rif_entry *re;
	struct netdev_nested_priv priv;

	re = prestera_rif_entry_find(sw, &rif->rif_entry_key);
	if (re)
		prestera_rif_entry_destroy(sw, re);

	if (!replace)
		return 0;

	re = prestera_rif_entry_create(sw, &rif->rif_entry_key,
				       mvsw_pr_fix_tb_id(rif->kern_tb_id),
				       rif->addr);
	if (!re)
		return -EINVAL;

	priv.data = re;
	if (netdev_walk_all_upper_dev_rcu(rif->dev,
					  __prestera_rif_macvlan_offload_cb,
					  &priv)) {
		prestera_rif_entry_destroy(sw, re);
		return -ENOENT;
	}

	return 0;
}

static struct prestera_rif *
prestera_rif_create(struct prestera_switch *sw,
		    const struct mvsw_pr_rif_params *params,
		    struct netlink_ext_ack *extack)
{
	struct prestera_rif *rif;
	int err;

	rif = kzalloc(sizeof(*rif), GFP_KERNEL);
	if (!rif) {
		err = -ENOMEM;
		goto err_rif_alloc;
	}

	rif->dev = params->dev;
	dev_hold(rif->dev);

	err = prestera_dev2iface(sw, rif->dev, &rif->rif_entry_key.iface);
	if (err)
		goto err_dev2iface;

	ether_addr_copy(rif->addr, params->dev->dev_addr);
	rif->kern_tb_id = l3mdev_fib_table(params->dev);

	err = __prestera_rif_offload(sw, true, rif);
	if (err)  {
		NL_SET_ERR_MSG_MOD(extack,
				   "Exceeded number of supported rifs");
		goto err_rif_offload;
	}

	list_add(&rif->router_node, &sw->router->rif_list);

	return rif;

err_rif_offload:
err_dev2iface:
	dev_put(rif->dev);
	kfree(rif);
err_rif_alloc:
	return ERR_PTR(err);
}

static void prestera_rif_destroy(struct prestera_switch *sw,
				 struct prestera_rif *rif)
{
	list_del(&rif->router_node);
	__prestera_rif_offload(sw, false, rif);
	dev_put(rif->dev);
	kfree(rif);
}

static void prestera_rif_put(struct prestera_switch *sw,
			     struct prestera_rif *rif)
{
	if (!rif->ref_cnt && !rif->is_active)
		prestera_rif_destroy(sw, rif);
}

void prestera_rif_enable(struct prestera_switch *sw,
			 struct net_device *dev, bool enable)
{
	struct prestera_rif *rif;

	rif = mvsw_pr_rif_find(sw, dev);
	if (!rif)
		return;

	__prestera_rif_offload(sw, enable, rif);
}

static int prestera_rif_update(struct prestera_switch *sw,
			       struct net_device *dev)
{
	struct prestera_rif *rif;

	rif = mvsw_pr_rif_find(sw, dev);
	if (!rif)
		return 0;

	ether_addr_copy(rif->addr, rif->dev->dev_addr);
	rif->kern_tb_id = l3mdev_fib_table(rif->dev);
	return __prestera_rif_offload(sw, true, rif);
}

void prestera_router_lag_member_leave(const struct prestera_port *port,
				      const struct net_device *dev)
{
	struct prestera_rif *rif;
	u16 vr_id;

	rif = mvsw_pr_rif_find(port->sw, dev);
	if (!rif)
		return;

	vr_id = mvsw_pr_fix_tb_id(rif->kern_tb_id);
	prestera_lag_member_rif_leave(port, port->lag_id, vr_id);
}

void prestera_lag_router_leave(struct prestera_switch *sw,
			       struct net_device *lag_dev)
{
	struct prestera_rif *rif;

	rif = mvsw_pr_rif_find(sw, lag_dev);
	if (rif) {
		rif->is_active = false;
		prestera_rif_put(sw, rif);
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
		prestera_rif_put(sw, rif);
	}

	return 0;
}

void prestera_bridge_rifs_destroy(struct prestera_switch *sw,
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
