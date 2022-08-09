/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 *
 * Copyright (c) 2019-2020 Marvell International Ltd. All rights reserved.
 *
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>
#include <linux/notifier.h>
#include <net/switchdev.h>
#include <net/netevent.h>
#include <net/vxlan.h>
#include <linux/rhashtable.h>

#include "prestera.h"
#include "prestera_switchdev.h"
#include "prestera_hw.h"

#define PRESTERA_VID_ALL (0xffff)
#define PRESTERA_DEFAULT_ISOLATION_SRCID 1 /* source_id */

struct prestera_switchdev {
	struct prestera_switch *sw;
	struct notifier_block swdev_n;
	struct notifier_block swdev_blocking_n;

	u32 ageing_time;
	struct list_head bridge_list;
	struct rhashtable routed_fdb_ht;
	bool bridge_8021q_exists;
};

struct prestera_br_mdb_port {
	struct prestera_bridge_port *br_port;
	struct list_head br_mdb_port_node;
};

/* Software representation of MDB table. */
struct prestera_br_mdb_entry {
	struct prestera_bridge *bridge;
	struct prestera_mdb_entry *mdb;
	struct list_head br_mdb_port_list;
	struct list_head br_mdb_entry_node;
	bool enabled;
};

struct prestera_routed_fdb_entry {
	struct prestera_routed_fdb_entry_key {
		u8 addr[ETH_ALEN];
		u16 vid;
	} key;
	struct rhash_head ht_node;
};

struct prestera_bridge {
	struct net_device *dev;
	struct list_head bridge_node;
	struct list_head port_list;
	struct list_head br_mdb_entry_list;
	bool mrouter_exist;
	u16 bridge_id;
	/* This can be extended to list of isolation groups */
	u32 isolation_srcid; /* source_id */
	u8 vlan_enabled:1, multicast_enabled:1, mrouter:1;
	/* TODO: Dont use refcnt type, as it can reach zero
	 * (Still hold by br_ports). Need to refactor.
	 */
	unsigned int ref_count;
};

struct prestera_bridge_port {
	struct net_device *dev;
	struct prestera_bridge *bridge;
	struct list_head bridge_node;
	struct list_head vlan_list;
	struct list_head br_mdb_port_list;
	unsigned int ref_count;
	u8 stp_state;
	bool mrouter;
	unsigned long flags;
};

struct prestera_bridge_vlan {
	struct list_head bridge_port_node;
	struct list_head port_vlan_list;
	u16 vid;
};

struct prestera_swdev_work {
	struct work_struct work;
	struct prestera_switch *sw;
	struct switchdev_notifier_fdb_info fdb_info;
	struct net_device *dev;
	unsigned long event;
};

static const struct rhashtable_params __prestera_routed_fdb_ht_params = {
	.key_offset  = offsetof(struct prestera_routed_fdb_entry, key),
	.head_offset = offsetof(struct prestera_routed_fdb_entry, ht_node),
	.key_len     = sizeof(struct prestera_routed_fdb_entry_key),
	.automatic_shrinking = true,
};

static struct workqueue_struct *swdev_owq;

static struct prestera_bridge_port *
prestera_bridge_port_get(struct prestera_switch *sw,
			 struct net_device *brport_dev);

static void prestera_bridge_port_put(struct prestera_switch *sw,
				     struct prestera_bridge_port *br_port);

static int
prestera_mdb_port_addr_obj_add(const struct switchdev_obj_port_mdb *mdb);
static int
prestera_mdb_port_addr_obj_del(struct prestera_port *port,
			       const struct switchdev_obj_port_mdb *mdb);

static void
prestera_mdb_flush_bridge_port(struct prestera_bridge_port *br_port);
static int
prestera_mdb_port_add(struct prestera_mdb_entry *br_mdb,
		      struct net_device *orig_dev,
		      const unsigned char addr[ETH_ALEN], u16 vid);

static void
prestera_br_mdb_entry_put(struct prestera_br_mdb_entry *br_mdb_entry);
static int prestera_br_mdb_mc_enable_sync(struct prestera_bridge *br_dev);
static int prestera_br_mdb_sync(struct prestera_bridge *br_dev);
static int prestera_br_mdb_port_add(struct prestera_br_mdb_entry *br_mdb,
				    struct prestera_bridge_port *br_port);
static void
prestera_mdb_port_del(struct prestera_mdb_entry *mdb,
		      struct net_device *orig_dev);

static struct prestera_bridge *
prestera_bridge_get(struct prestera_switch *sw, struct net_device *br_dev);
static void
prestera_bridge_put(struct prestera_switch *sw, struct prestera_bridge *bridge);

static struct prestera_routed_fdb_entry *
prestera_routed_fdb_entry_find(const struct prestera_switch *sw,
			       const struct prestera_routed_fdb_entry_key *k)
{
	return rhashtable_lookup_fast(&sw->swdev->routed_fdb_ht, k,
				      __prestera_routed_fdb_ht_params);
}

static void
prestera_routed_fdb_entry_destroy(struct prestera_switch *sw,
				  struct prestera_routed_fdb_entry *e)
{
	rhashtable_remove_fast(&sw->swdev->routed_fdb_ht, &e->ht_node,
			       __prestera_routed_fdb_ht_params);
	prestera_hw_fdb_routed_del(sw, e->key.addr, e->key.vid);
	kfree(e);
}

static struct prestera_routed_fdb_entry *
prestera_routed_fdb_entry_create(struct prestera_switch *sw,
				 struct prestera_routed_fdb_entry_key *k)
{
	struct prestera_routed_fdb_entry *e;
	int err;

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		goto err_kzalloc;

	memcpy(&e->key, k, sizeof(*k));

	/* HW */
	err = prestera_hw_fdb_routed_add(sw, e->key.addr, e->key.vid);
	if (err)
		goto err_hw_add;

	err = rhashtable_insert_fast(&sw->swdev->routed_fdb_ht, &e->ht_node,
				     __prestera_routed_fdb_ht_params);
	if (err)
		goto err_rhashtable_insert;

	return e;

err_rhashtable_insert:
	prestera_hw_fdb_routed_del(sw, e->key.addr, e->key.vid);
err_hw_add:
	kfree(e);
err_kzalloc:
	return NULL;
}

static struct prestera_bridge *
prestera_bridge_find(const struct prestera_switch *sw,
		     const struct net_device *br_dev)
{
	struct prestera_bridge *bridge;

	list_for_each_entry(bridge, &sw->swdev->bridge_list,
			    bridge_node)
		if (bridge->dev == br_dev)
			return bridge;

	return NULL;
}

bool prestera_bridge_is_offloaded(const struct prestera_switch *sw,
				  const struct net_device *br_dev)
{
	return !!prestera_bridge_find(sw, br_dev);
}

static struct prestera_bridge_port *
__prestera_bridge_port_find(const struct prestera_bridge *bridge,
			    const struct net_device *brport_dev)
{
	struct prestera_bridge_port *br_port;

	list_for_each_entry(br_port, &bridge->port_list,
			    bridge_node) {
		if (br_port->dev == brport_dev)
			return br_port;
	}

	return NULL;
}

static struct prestera_bridge_port *
prestera_bridge_port_find(struct prestera_switch *sw,
			  struct net_device *brport_dev)
{
	struct net_device *br_dev = netdev_master_upper_dev_get(brport_dev);
	struct prestera_bridge *bridge;

	if (!br_dev)
		return NULL;

	bridge = prestera_bridge_find(sw, br_dev);
	if (!bridge)
		return NULL;

	return __prestera_bridge_port_find(bridge, brport_dev);
}

static void
prestera_br_port_flags_reset(struct prestera_bridge_port *br_port,
			     struct prestera_port *port)
{
	prestera_port_uc_flood_set(port, false);
	prestera_port_mc_flood_set(port, false);
	prestera_port_learning_set(port, false);
	prestera_port_isolation_grp_set(port, PRESTERA_PORT_SRCID_ZERO);
}

static int prestera_br_port_flags_set(struct prestera_bridge_port *br_port,
				      struct prestera_port *port)
{
	struct prestera_bridge *br_dev;
	u32 iso_srcid;
	int err;

	br_dev = br_port->bridge;

	err = prestera_port_uc_flood_set(port, br_port->flags & BR_FLOOD);
	if (err)
		goto err_out;

	err = prestera_br_mdb_mc_enable_sync(br_port->bridge);
	if (err)
		goto err_out;

	err = prestera_port_learning_set(port, br_port->flags & BR_LEARNING);
	if (err)
		goto err_out;

	iso_srcid = br_port->flags & BR_ISOLATED ?
			br_dev->isolation_srcid : PRESTERA_PORT_SRCID_ZERO;
	err = prestera_port_isolation_grp_set(port, iso_srcid);
	if (err)
		goto err_out;

	return 0;

err_out:
	prestera_br_port_flags_reset(br_port, port);
	return err;
}

static struct prestera_bridge_vlan *
prestera_bridge_vlan_find(const struct prestera_bridge_port *br_port, u16 vid)
{
	struct prestera_bridge_vlan *br_vlan;

	list_for_each_entry(br_vlan, &br_port->vlan_list, bridge_port_node) {
		if (br_vlan->vid == vid)
			return br_vlan;
	}

	return NULL;
}

u16 prestera_vlan_dev_vlan_id(struct prestera_switch *sw,
			      struct net_device *dev)
{
	struct prestera_bridge *bridge_dev;

	bridge_dev = prestera_bridge_find(sw, dev);

	return bridge_dev ? bridge_dev->bridge_id : 0;
}

static struct prestera_bridge_vlan *
prestera_bridge_vlan_create(struct prestera_bridge_port *br_port, u16 vid)
{
	struct prestera_bridge_vlan *br_vlan;

	br_vlan = kzalloc(sizeof(*br_vlan), GFP_KERNEL);
	if (!br_vlan)
		return NULL;

	INIT_LIST_HEAD(&br_vlan->port_vlan_list);
	br_vlan->vid = vid;
	list_add(&br_vlan->bridge_port_node, &br_port->vlan_list);

	return br_vlan;
}

static void
prestera_bridge_vlan_destroy(struct prestera_bridge_vlan *br_vlan)
{
	list_del(&br_vlan->bridge_port_node);
	WARN_ON(!list_empty(&br_vlan->port_vlan_list));
	kfree(br_vlan);
}

static struct prestera_bridge_vlan *
prestera_bridge_vlan_get(struct prestera_bridge_port *br_port, u16 vid)
{
	struct prestera_bridge_vlan *br_vlan;

	br_vlan = prestera_bridge_vlan_find(br_port, vid);
	if (br_vlan)
		return br_vlan;

	return prestera_bridge_vlan_create(br_port, vid);
}

static void prestera_bridge_vlan_put(struct prestera_bridge_vlan *br_vlan)
{
	if (list_empty(&br_vlan->port_vlan_list))
		prestera_bridge_vlan_destroy(br_vlan);
}

static int
prestera_port_vlan_bridge_join(struct prestera_port_vlan *port_vlan,
			       struct prestera_bridge_port *br_port,
			       struct netlink_ext_ack *extack)
{
	struct prestera_port *port = port_vlan->port;
	struct prestera_bridge_vlan *br_vlan;
	u16 vid = port_vlan->vid;
	int err;

	if (port_vlan->bridge_port)
		return 0;

	err = prestera_br_port_flags_set(br_port, port);
	if (err)
		goto err_flags2port_set;

	err = prestera_port_vid_stp_set(port, vid, br_port->stp_state);
	if (err)
		goto err_port_vid_stp_set;

	br_vlan = prestera_bridge_vlan_get(br_port, vid);
	if (!br_vlan) {
		err = -ENOMEM;
		goto err_bridge_vlan_get;
	}

	list_add(&port_vlan->bridge_vlan_node, &br_vlan->port_vlan_list);

	prestera_bridge_port_get(port->sw, br_port->dev);
	port_vlan->bridge_port = br_port;

	return 0;

err_bridge_vlan_get:
	prestera_port_vid_stp_set(port, vid, BR_STATE_FORWARDING);
err_port_vid_stp_set:
	prestera_br_port_flags_reset(br_port, port);
err_flags2port_set:
	return err;
}

static int
prestera_bridge_vlan_port_count_get(struct prestera_bridge *bridge,
				    u16 vid)
{
	int count = 0;
	struct prestera_bridge_port *br_port;
	struct prestera_bridge_vlan *br_vlan;

	list_for_each_entry(br_port, &bridge->port_list, bridge_node) {
		list_for_each_entry(br_vlan, &br_port->vlan_list,
				    bridge_port_node) {
			if (br_vlan->vid == vid) {
				count += 1;
				break;
			}
		}
	}

	return count;
}

static int prestera_fdb_flush_vlan(struct prestera_switch *sw, u16 vid,
				   enum prestera_fdb_flush_mode mode)
{
	return prestera_hw_fdb_flush_vlan(sw, vid, mode);
}

static int prestera_fdb_flush_port_vlan(struct prestera_port *port, u16 vid,
					enum prestera_fdb_flush_mode mode)
{
	if (prestera_port_is_lag_member(port))
		return prestera_hw_fdb_flush_lag_vlan(port->sw, port->lag_id,
						      vid, mode);
	else
		return prestera_hw_fdb_flush_port_vlan(port, vid, mode);
}

static int prestera_fdb_flush_port(struct prestera_port *port,
				   enum prestera_fdb_flush_mode mode)
{
	if (prestera_port_is_lag_member(port))
		return prestera_hw_fdb_flush_lag(port->sw, port->lag_id, mode);
	else
		return prestera_hw_fdb_flush_port(port, mode);
}

int prestera_bridge_port_down(struct prestera_port *port)
{
	return prestera_fdb_flush_port(port, PRESTERA_FDB_FLUSH_MODE_DYNAMIC);
}

void
prestera_port_vlan_bridge_leave(struct prestera_port_vlan *port_vlan)
{
	struct prestera_port *port = port_vlan->port;
	u32 mode = PRESTERA_FDB_FLUSH_MODE_DYNAMIC;
	struct prestera_bridge_vlan *br_vlan;
	struct prestera_bridge_port *br_port;
	u16 vid = port_vlan->vid;
	bool last_port, last_vlan;
	int port_count;

	br_port = port_vlan->bridge_port;
	last_vlan = list_is_singular(&br_port->vlan_list);
	port_count = prestera_bridge_vlan_port_count_get(br_port->bridge, vid);
	br_vlan = prestera_bridge_vlan_find(br_port, vid);
	last_port = port_count == 1;

	if (last_vlan)
		prestera_fdb_flush_port(port, mode);
	else if (last_port)
		prestera_fdb_flush_vlan(port->sw, vid, mode);
	else
		prestera_fdb_flush_port_vlan(port, vid, mode);

	prestera_mdb_flush_bridge_port(br_port);

	list_del(&port_vlan->bridge_vlan_node);
	prestera_bridge_vlan_put(br_vlan);
	prestera_port_vid_stp_set(port, vid, BR_STATE_FORWARDING);
	prestera_bridge_port_put(port->sw, br_port);
	port_vlan->bridge_port = NULL;
}

static int
prestera_bridge_port_vlan_add(struct prestera_port *port,
			      struct prestera_bridge_port *br_port,
			      u16 vid, bool is_untagged, bool is_pvid,
			      struct netlink_ext_ack *extack)
{
	u16 pvid;
	struct prestera_port_vlan *port_vlan;
	u16 old_pvid = port->pvid;
	int err;

	if (is_pvid)
		pvid = vid;
	else
		pvid = port->pvid == vid ? 0 : port->pvid;

	port_vlan = prestera_port_vlan_find_by_vid(port, vid);
	if (port_vlan->used && port_vlan->bridge_port != br_port)
		return -EEXIST;

	if (!port_vlan->used) {
		port_vlan = prestera_port_vlan_create(port, vid, is_untagged);
		if (IS_ERR(port_vlan))
			return PTR_ERR(port_vlan);
	} else {
		err = prestera_port_vlan_set(port, vid, true, is_untagged);
		if (err)
			goto err_port_vlan_set;
	}

	err = prestera_port_pvid_set(port, pvid);
	if (err)
		goto err_port_pvid_set;

	err = prestera_port_vlan_bridge_join(port_vlan, br_port, extack);
	if (err)
		goto err_port_vlan_bridge_join;

	return 0;

err_port_vlan_bridge_join:
	prestera_port_pvid_set(port, old_pvid);
err_port_pvid_set:
	prestera_port_vlan_set(port, vid, false, false);
err_port_vlan_set:
	prestera_port_vlan_destroy(port_vlan);

	return err;
}

static int prestera_port_vlans_add(struct prestera_port *port,
				   const struct switchdev_obj_port_vlan *vlan,
				   struct netlink_ext_ack *extack)
{
	bool flag_untagged = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED;
	bool flag_pvid = vlan->flags & BRIDGE_VLAN_INFO_PVID;
	struct net_device *orig_dev = vlan->obj.orig_dev;
	struct prestera_bridge_port *br_port;
	struct prestera_bridge *bridge;
	struct prestera_switch *sw = port->sw;
	int err;

	if (netif_is_bridge_master(orig_dev))
		return 0;

	br_port = prestera_bridge_port_find(sw, orig_dev);
	if (WARN_ON(!br_port))
		return -EINVAL;

	bridge = br_port->bridge;
	if (!bridge->vlan_enabled)
		return 0;

	err = prestera_bridge_port_vlan_add(port, br_port,
					    vlan->vid, flag_untagged,
					    flag_pvid, extack);
	if (err)
		return err;

	if (list_is_singular(&bridge->port_list))
		prestera_rif_enable(port->sw, bridge->dev, true);

	return 0;
}

static int prestera_port_obj_add(struct net_device *dev, const void *ctx,
				 const struct switchdev_obj *obj,
				 struct netlink_ext_ack *extack)
{
	struct prestera_port *port = netdev_priv(dev);
	const struct switchdev_obj_port_vlan *vlan;
	const struct switchdev_obj_port_mdb *mdb;
	int err = 0;

	switch (obj->id) {
	case SWITCHDEV_OBJ_ID_PORT_VLAN:
		vlan = SWITCHDEV_OBJ_PORT_VLAN(obj);
		err = prestera_port_vlans_add(port, vlan, extack);
		break;
	case SWITCHDEV_OBJ_ID_PORT_MDB:
		mdb = SWITCHDEV_OBJ_PORT_MDB(obj);
		err = prestera_mdb_port_addr_obj_add(mdb);
		break;
	case SWITCHDEV_OBJ_ID_HOST_MDB:
		fallthrough;
	default:
		err = -EOPNOTSUPP;
	}

	return err;
}

static void
prestera_bridge_port_vlan_del(struct prestera_port *port,
			      struct prestera_bridge_port *br_port, u16 vid)
{
	u16 pvid = port->pvid == vid ? 0 : port->pvid;
	struct prestera_port_vlan *port_vlan;

	port_vlan = prestera_port_vlan_find_by_vid(port, vid);
	if (WARN_ON(!port_vlan))
		return;

	prestera_port_vlan_bridge_leave(port_vlan);
	prestera_port_pvid_set(port, pvid);
	prestera_port_vlan_destroy(port_vlan);
}

static int prestera_port_vlans_del(struct prestera_port *port,
				   const struct switchdev_obj_port_vlan *vlan)
{
	struct prestera_switch *sw = port->sw;
	struct net_device *orig_dev = vlan->obj.orig_dev;
	struct prestera_bridge_port *br_port;

	if (netif_is_bridge_master(orig_dev))
		return -EOPNOTSUPP;

	br_port = prestera_bridge_port_find(sw, orig_dev);
	if (WARN_ON(!br_port))
		return -EINVAL;

	if (!br_port->bridge->vlan_enabled)
		return 0;

	prestera_bridge_port_vlan_del(port, br_port, vlan->vid);

	return 0;
}

static int prestera_port_obj_del(struct net_device *dev, const void *ctx,
				 const struct switchdev_obj *obj)
{
	struct prestera_port *port = netdev_priv(dev);
	const struct switchdev_obj_port_mdb *mdb;
	int err = 0;

	switch (obj->id) {
	case SWITCHDEV_OBJ_ID_PORT_VLAN:
		err = prestera_port_vlans_del(port,
					      SWITCHDEV_OBJ_PORT_VLAN(obj));
		break;
	case SWITCHDEV_OBJ_ID_PORT_MDB:
		mdb = SWITCHDEV_OBJ_PORT_MDB(obj);
		err = prestera_mdb_port_addr_obj_del(port, mdb);
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

static int prestera_port_attr_br_vlan_set(struct prestera_port *port,
					  struct net_device *orig_dev,
					  bool vlan_enabled)
{
	struct prestera_switch *sw = port->sw;
	struct prestera_bridge *bridge;

	bridge = prestera_bridge_find(sw, orig_dev);
	if (WARN_ON(!bridge))
		return -EINVAL;

	if (bridge->vlan_enabled == vlan_enabled)
		return 0;

	netdev_err(bridge->dev,
		   "VLAN filtering can't be changed for existing bridge\n");
	return -EINVAL;
}

static int prestera_port_attr_br_flags_set(struct prestera_port *port,
					   struct net_device *orig_dev,
					   struct switchdev_brport_flags flags)
{
	struct prestera_bridge_port *br_port;

	br_port = prestera_bridge_port_find(port->sw, orig_dev);
	if (!br_port)
		return 0;

	br_port->flags &= ~flags.mask;
	br_port->flags |= flags.val & flags.mask;
	/* TODO: restore path ? */
	return prestera_br_port_flags_set(br_port, port);
}

static int prestera_switch_ageing_set(struct prestera_switch *sw,
				      u32 ageing_time)
{
	return prestera_hw_switch_ageing_set(sw, ageing_time / 1000);
}

static int prestera_port_attr_br_ageing_set(struct prestera_port *port,
					    unsigned long ageing_clock_t)
{
	int err;
	struct prestera_switch *sw = port->sw;
	unsigned long ageing_jiffies = clock_t_to_jiffies(ageing_clock_t);
	u32 ageing_time = jiffies_to_msecs(ageing_jiffies);

	if (ageing_time < PRESTERA_MIN_AGEING_TIME ||
	    ageing_time > PRESTERA_MAX_AGEING_TIME)
		return -ERANGE;

	err = prestera_switch_ageing_set(sw, ageing_time);
	if (!err)
		sw->swdev->ageing_time = ageing_time;

	return err;
}

static int
prestera_port_bridge_vlan_stp_set(struct prestera_port *port,
				  struct prestera_bridge_vlan *br_vlan,
				  u8 state)
{
	struct prestera_port_vlan *port_vlan;

	list_for_each_entry(port_vlan, &br_vlan->port_vlan_list,
			    bridge_vlan_node) {
		if (port_vlan->port != port)
			continue;
		return prestera_port_vid_stp_set(port, br_vlan->vid, state);
	}

	return 0;
}

static int prestera_port_attr_stp_state_set(struct prestera_port *port,
					    struct net_device *orig_dev,
					    u8 state)
{
	struct prestera_bridge_port *br_port;
	struct prestera_bridge_vlan *br_vlan;
	int err;
	u16 vid;

	br_port = prestera_bridge_port_find(port->sw, orig_dev);
	if (!br_port)
		return 0;

	if (!br_port->bridge->vlan_enabled) {
		vid = br_port->bridge->bridge_id;
		err = prestera_port_vid_stp_set(port, vid, state);
		if (err)
			goto err_port_bridge_stp_set;
	} else {
		list_for_each_entry(br_vlan, &br_port->vlan_list,
				    bridge_port_node) {
			err = prestera_port_bridge_vlan_stp_set(port, br_vlan,
								state);
			if (err)
				goto err_port_bridge_vlan_stp_set;
		}
	}

	br_port->stp_state = state;

	return 0;

err_port_bridge_vlan_stp_set:
	list_for_each_entry_continue_reverse(br_vlan, &br_port->vlan_list,
					     bridge_port_node)
		prestera_port_bridge_vlan_stp_set(port, br_vlan,
						  br_port->stp_state);
	return err;

err_port_bridge_stp_set:
	prestera_port_vid_stp_set(port, vid, br_port->stp_state);

	return err;
}

static int
prestera_br_port_lag_mdb_mc_enable_sync(struct prestera_bridge_port *br_port,
					bool enabled)
{
	struct prestera_port *pr_port;
	struct prestera_switch *sw;
	u16 lag_id;
	int err;

	pr_port = prestera_port_dev_lower_find(br_port->dev);
	if (!pr_port)
		return 0;

	sw = pr_port->sw;
	err = prestera_lag_id_find(sw, br_port->dev, &lag_id);
	if (err)
		return err;

	list_for_each_entry(pr_port, &sw->port_list, list) {
		if (pr_port->lag_id == lag_id) {
			err = prestera_port_mc_flood_set(pr_port, enabled);
			if (err)
				return err;
		}
	}

	return 0;
}

static int prestera_br_mdb_mc_enable_sync(struct prestera_bridge *br_dev)
{
	struct prestera_bridge_port *br_port;
	struct prestera_port *port;
	bool enabled;
	int err;

	/*
	 * if mrouter exists:
	 *  - make sure every mrouter receives unreg mcast traffic;
	 * if mrouter doesn't exists:
	 *  - make sure every port receives unreg mcast traffic;
	 */
	list_for_each_entry(br_port, &br_dev->port_list,
			    bridge_node) {
		if (br_dev->multicast_enabled && br_dev->mrouter_exist)
			enabled = br_port->mrouter;
		else
			enabled = br_port->flags & BR_MCAST_FLOOD;

		if (netif_is_lag_master(br_port->dev)) {
			err = prestera_br_port_lag_mdb_mc_enable_sync(br_port,
								      enabled);
			if (err)
				return err;
			continue;
		}

		port = prestera_port_dev_lower_find(br_port->dev);
		if (!port)
			continue;

		err = prestera_port_mc_flood_set(port, enabled);
		if (err)
			return err;
	}

	return 0;
}

static bool
prestera_br_mdb_port_is_member(struct prestera_br_mdb_entry *br_mdb,
			       struct net_device *orig_dev)
{
	struct prestera_br_mdb_port *tmp_port;

	list_for_each_entry(tmp_port, &br_mdb->br_mdb_port_list,
			    br_mdb_port_node)
		if (tmp_port->br_port->dev == orig_dev)
			return true;

	return false;
}

/* Sync bridge mdb (software table) with HW table (if MC is enabled). */
static int prestera_br_mdb_sync(struct prestera_bridge *br_dev)
{
	struct prestera_br_mdb_port *br_mdb_port;
	struct prestera_bridge_port *br_port;
	struct prestera_br_mdb_entry *br_mdb;
	struct prestera_mdb_entry *mdb;
	struct prestera_port *pr_port;
	int err = 0;

	if (!br_dev->multicast_enabled)
		return 0;

	list_for_each_entry(br_mdb, &br_dev->br_mdb_entry_list,
			    br_mdb_entry_node) {
		mdb = br_mdb->mdb;
		/*
		 * Make sure every port that explicitly been added to the mdb
		 * joins the specified group.
		 */
		list_for_each_entry(br_mdb_port, &br_mdb->br_mdb_port_list,
				    br_mdb_port_node) {
			br_port = br_mdb_port->br_port;
			pr_port = prestera_port_dev_lower_find(br_port->dev);

			/*
			 * Match only mdb and br_mdb ports that belong to the
			 * same broadcast domain.
			 */
			if (br_dev->vlan_enabled &&
			    !prestera_port_vlan_find_by_vid(pr_port,
							    mdb->vid)->used)
				continue;

			/*
			 * If port is not in MDB or there's no Mrouter
			 * clear HW mdb.
			 */
			if (prestera_br_mdb_port_is_member(br_mdb,
							   br_mdb_port->br_port->dev) &&
							   br_dev->mrouter_exist)
				err = prestera_mdb_port_add(mdb, br_port->dev,
							    mdb->addr,
							    mdb->vid);
			else
				prestera_mdb_port_del(mdb, br_port->dev);

			if (err)
				return err;
		}

		/*
		 * Make sure that every mrouter port joins every MC group int
		 * broadcast domain. If it's not an mrouter - it should leave
		 */
		list_for_each_entry(br_port, &br_dev->port_list, bridge_node) {
			pr_port = prestera_port_dev_lower_find(br_port->dev);

			/*
			 * Make sure mrouter woudln't receive traffci from
			 * another broadcast domain (e.g. from a vlan, which
			 * mrouter port is not a member of).
			 */
			if (br_dev->vlan_enabled &&
			    !prestera_port_vlan_find_by_vid(pr_port,
							    mdb->vid)->used)
				continue;

			if (br_port->mrouter) {
				err = prestera_mdb_port_add(mdb, br_port->dev,
							    mdb->addr,
							    mdb->vid);
				if (err)
					return err;
			} else if (!br_port->mrouter &&
				   !prestera_br_mdb_port_is_member
				   (br_mdb, br_port->dev)) {
				prestera_mdb_port_del(mdb, br_port->dev);
			}
		}
	}

	return 0;
}

static int
prestera_mdb_enable_set(struct prestera_br_mdb_entry *br_mdb, bool enable)
{
	int err;

	if (enable != br_mdb->enabled) {
		if (enable)
			err = prestera_hw_mdb_create(br_mdb->mdb);
		else
			err = prestera_hw_mdb_destroy(br_mdb->mdb);

		if (err)
			return err;

		br_mdb->enabled = enable;
	}

	return 0;
}

static int
prestera_br_mdb_enable_set(struct prestera_bridge *br_dev, bool enable)
{
	struct prestera_br_mdb_entry *br_mdb;
	int err;

	list_for_each_entry(br_mdb, &br_dev->br_mdb_entry_list,
			    br_mdb_entry_node)
		if (prestera_mdb_enable_set(br_mdb, enable))
			return err;

	return 0;
}

static int prestera_port_attr_br_mc_disabled_set(struct prestera_port *port,
						 struct net_device *orig_dev,
						 bool mc_disabled)
{
	struct prestera_switch *sw = port->sw;
	struct prestera_bridge *br_dev;

	br_dev = prestera_bridge_find(sw, orig_dev);
	if (!br_dev)
		return 0;

	br_dev->multicast_enabled = !mc_disabled;

	/* There's no point in enabling mdb back if router is missing. */
	WARN_ON(prestera_br_mdb_enable_set(br_dev, br_dev->multicast_enabled &&
					   br_dev->mrouter_exist));

	WARN_ON(prestera_br_mdb_sync(br_dev));

	WARN_ON(prestera_br_mdb_mc_enable_sync(br_dev));

	return 0;
}

static bool
prestera_bridge_mdb_mc_mrouter_exists(struct prestera_bridge *br_dev)
{
	struct prestera_bridge_port *br_port;

	list_for_each_entry(br_port, &br_dev->port_list, bridge_node)
		if (br_port->mrouter)
			return true;

	return false;
}

static int
prestera_port_attr_mrouter_set(struct prestera_port *port,
			       struct net_device *orig_dev,
			       bool is_port_mrouter)
{
	struct prestera_bridge_port *br_port;
	struct prestera_bridge *br_dev;

	br_port = prestera_bridge_port_find(port->sw, orig_dev);
	if (!br_port)
		return 0;

	br_dev = br_port->bridge;
	br_port->mrouter = is_port_mrouter;

	br_dev->mrouter_exist = prestera_bridge_mdb_mc_mrouter_exists(br_dev);

	/*
	 * Enable MDB processing if both mrouter exists and mc is enabled.
	 * In case if MC enabled, but there is no mrouter, device would flood
	 * all multicast traffic (even if MDB table is not empty) with the use
	 * of bridge's flood capabilities (without the use of flood_domain).
	 */
	WARN_ON(prestera_br_mdb_enable_set(br_dev, br_dev->multicast_enabled &&
					   br_dev->mrouter_exist));

	WARN_ON(prestera_br_mdb_sync(br_dev));

	WARN_ON(prestera_br_mdb_mc_enable_sync(br_dev));

	return 0;
}

static int prestera_port_obj_attr_set(struct net_device *dev, const void *ctx,
				      const struct switchdev_attr *attr,
				      struct netlink_ext_ack *extack)
{
	int err = 0;
	struct prestera_port *port = netdev_priv(dev);

	switch (attr->id) {
	case SWITCHDEV_ATTR_ID_PORT_STP_STATE:
		err = prestera_port_attr_stp_state_set(port, attr->orig_dev,
						       attr->u.stp_state);
		break;
	case SWITCHDEV_ATTR_ID_PORT_PRE_BRIDGE_FLAGS:
		if (attr->u.brport_flags.mask &
		    ~(BR_LEARNING | BR_FLOOD | BR_MCAST_FLOOD | BR_ISOLATED))
			err = -EINVAL;
		break;
	case SWITCHDEV_ATTR_ID_PORT_BRIDGE_FLAGS:
		err = prestera_port_attr_br_flags_set(port, attr->orig_dev,
						      attr->u.brport_flags);
		break;
	case SWITCHDEV_ATTR_ID_BRIDGE_AGEING_TIME:
		err = prestera_port_attr_br_ageing_set(port,
						       attr->u.ageing_time);
		break;
	case SWITCHDEV_ATTR_ID_BRIDGE_VLAN_FILTERING:
		err = prestera_port_attr_br_vlan_set(port, attr->orig_dev,
						     attr->u.vlan_filtering);
		break;
	case SWITCHDEV_ATTR_ID_PORT_MROUTER:
		err = prestera_port_attr_mrouter_set(port, attr->orig_dev,
						     attr->u.mrouter);
		break;
	case SWITCHDEV_ATTR_ID_BRIDGE_MC_DISABLED:
		err = prestera_port_attr_br_mc_disabled_set(port, attr->orig_dev,
							    attr->u.mc_disabled);
		break;
	default:
		err = -EOPNOTSUPP;
	}

	return err;
}

static void
prestera_fdb_offload_notify(struct prestera_port *port,
			    struct switchdev_notifier_fdb_info *info)
{
	struct switchdev_notifier_fdb_info send_info;
	struct net_device *net_dev = port->net_dev;
	struct prestera_lag *lag;

	send_info.addr = info->addr;
	send_info.vid = info->vid;
	send_info.offloaded = true;
	if (prestera_port_is_lag_member(port)) {
		lag = prestera_lag_get(port->sw, port->lag_id);
		if (lag)
			net_dev = lag->dev;
	}
	call_switchdev_notifiers(SWITCHDEV_FDB_OFFLOADED,
				 net_dev, &send_info.info, NULL);
}

static int prestera_fdb_add(struct prestera_port *port,
			    const unsigned char *mac,
			    u16 vid, bool dynamic)
{
	if (prestera_port_is_lag_member(port))
		return prestera_hw_lag_fdb_add(port->sw, port->lag_id,
					       mac, vid, dynamic);
	else
		return prestera_hw_fdb_add(port, mac, vid, dynamic);
}

static int prestera_fdb_del(struct prestera_port *port,
			    const unsigned char *mac, u16 vid)
{
	if (prestera_port_is_lag_member(port))
		return prestera_hw_lag_fdb_del(port->sw, port->lag_id,
					       mac, vid);
	else
		return prestera_hw_fdb_del(port, mac, vid);
}

static int
prestera_port_fdb_set(struct prestera_port *port,
		      struct switchdev_notifier_fdb_info *fdb_info,
		      bool adding)
{
	struct prestera_switch *sw = port->sw;
	struct prestera_bridge_port *br_port;
	struct prestera_bridge *bridge;
	struct net_device *orig_dev = fdb_info->info.dev;
	int err;
	u16 vid;

	br_port = prestera_bridge_port_find(sw, orig_dev);
	if (!br_port)
		return -EINVAL;

	bridge = br_port->bridge;

	if (bridge->vlan_enabled)
		vid = fdb_info->vid;
	else
		vid = bridge->bridge_id;

	if (adding)
		err = prestera_fdb_add(port, fdb_info->addr, vid, false);
	else
		err = prestera_fdb_del(port, fdb_info->addr, vid);

	return err;
}

static int
prestera_port_fdb_local_set(struct prestera_switch *sw,
			    struct switchdev_notifier_fdb_info *fdb_info,
			    bool adding)
{
	struct prestera_routed_fdb_entry_key rek;
	struct prestera_bridge *bridge = NULL;
	struct prestera_routed_fdb_entry *re;
	u16 vid = 0;
	int err = 0;

	if (br_vlan_enabled(fdb_info->info.dev)) {
		/* vid will be 0, in case .1Q bridge and entry without vid */
		vid = fdb_info->vid;
	} else {
		if (fdb_info->vid)
			goto out; /* ignore entries with vlan id .1D bridge */

		bridge = prestera_bridge_get(sw, fdb_info->info.dev);
		if (!bridge)
			goto out;

		vid = bridge->bridge_id;
	}

	if (!vid)
		goto out;

	memset(&rek, 0, sizeof(rek));
	rek.vid = vid;
	ether_addr_copy((u8 *)&rek.addr, fdb_info->addr);
	re = prestera_routed_fdb_entry_find(sw, &rek);

	if (adding && !re) {
		re = prestera_routed_fdb_entry_create(sw, &rek);
		if (!re) {
			err = -EINVAL;
			goto out;
		}

		/* keep bridge_id of .1D until all local fdb entries deleted */
		if (bridge)
			bridge->ref_count++;

	} else if (!adding && re) {
		prestera_routed_fdb_entry_destroy(sw, re);
		if (bridge)
			bridge->ref_count--;
	}

out:
	/* Use get/put here, but not in _routed_fdb_entry_create/destroy,
	 * because need object, that represent HW's vid (remove 1Q case here,
	 * use generic vid for 1D and 1Q).
	 */
	if (bridge)
		prestera_bridge_put(sw, bridge);

	return err;
}

static void prestera_bridge_fdb_event_work(struct work_struct *work)
{
	int err = 0;
	struct prestera_swdev_work *swdev_work =
	    container_of(work, struct prestera_swdev_work, work);
	struct net_device *dev = swdev_work->dev;
	struct switchdev_notifier_fdb_info *fdb_info;
	struct prestera_port *port;

	rtnl_lock();
	if (netif_is_vxlan(dev))
		goto out;

	/* TODO: make function more pretty:
	 * - check, if dev_lover realy needed by every case
	 * - use sw in swdev_work for each case
	 */

	switch (swdev_work->event) {
	case SWITCHDEV_FDB_ADD_TO_DEVICE:
		fdb_info = &swdev_work->fdb_info;
		if (fdb_info->is_local) {
			prestera_port_fdb_local_set(swdev_work->sw,
						    fdb_info, true);
			break;
		}

		port = prestera_port_dev_lower_find(dev);
		if (!port)
			goto out;

		if (!fdb_info->added_by_user)
			break;
		err = prestera_port_fdb_set(port, fdb_info, true);
		if (err)
			break;
		prestera_fdb_offload_notify(port, fdb_info);
		break;
	case SWITCHDEV_FDB_DEL_TO_DEVICE:
		fdb_info = &swdev_work->fdb_info;
		if (fdb_info->is_local) {
			prestera_port_fdb_local_set(swdev_work->sw,
						    fdb_info, false);
			break;
		}

		port = prestera_port_dev_lower_find(dev);
		if (!port)
			goto out;

		prestera_port_fdb_set(port, fdb_info, false);
		break;
	case SWITCHDEV_FDB_ADD_TO_BRIDGE:
	case SWITCHDEV_FDB_DEL_TO_BRIDGE:
		port = prestera_port_dev_lower_find(dev);
		if (!port)
			goto out;

		prestera_k_arb_fdb_evt(port->sw, port->net_dev);
		break;
	}

out:
	rtnl_unlock();
	kfree(swdev_work->fdb_info.addr);
	kfree(swdev_work);
	dev_put(dev);
}

static int prestera_switchdev_event(struct notifier_block *nb,
				    unsigned long event, void *ptr)
{
	int err = 0;
	struct net_device *net_dev = switchdev_notifier_info_to_dev(ptr);
	struct prestera_swdev_work *swdev_work;
	struct switchdev_notifier_fdb_info *fdb_info;
	struct switchdev_notifier_info *info = ptr;
	struct prestera_switchdev *swdev;

	swdev = container_of(nb, struct prestera_switchdev, swdev_n);

	if (event == SWITCHDEV_PORT_ATTR_SET) {
		err = switchdev_handle_port_attr_set(net_dev, ptr,
						     prestera_netdev_check,
						     prestera_port_obj_attr_set);
		return notifier_from_errno(err);
	}

	swdev_work = kzalloc(sizeof(*swdev_work), GFP_ATOMIC);
	if (!swdev_work)
		return NOTIFY_BAD;

	swdev_work->sw = swdev->sw;
	swdev_work->dev = net_dev;
	swdev_work->event = event;

	switch (event) {
	case SWITCHDEV_FDB_ADD_TO_DEVICE:
	case SWITCHDEV_FDB_DEL_TO_DEVICE:
	case SWITCHDEV_FDB_ADD_TO_BRIDGE:
	case SWITCHDEV_FDB_DEL_TO_BRIDGE:
		fdb_info = container_of(info,
					struct switchdev_notifier_fdb_info,
					info);
		INIT_WORK(&swdev_work->work, prestera_bridge_fdb_event_work);
		memcpy(&swdev_work->fdb_info, ptr,
		       sizeof(swdev_work->fdb_info));
		swdev_work->fdb_info.addr = kzalloc(ETH_ALEN, GFP_ATOMIC);
		if (!swdev_work->fdb_info.addr)
			goto out;
		ether_addr_copy((u8 *)swdev_work->fdb_info.addr,
				fdb_info->addr);
		dev_hold(net_dev);

		break;
	case SWITCHDEV_VXLAN_FDB_ADD_TO_DEVICE:
	case SWITCHDEV_VXLAN_FDB_DEL_TO_DEVICE:
	default:
		kfree(swdev_work);
		return NOTIFY_DONE;
	}

	queue_work(swdev_owq, &swdev_work->work);
	return NOTIFY_DONE;
out:
	kfree(swdev_work);
	return NOTIFY_BAD;
}

static int prestera_switchdev_blocking_event(struct notifier_block *unused,
					     unsigned long event, void *ptr)
{
	int err = 0;
	struct net_device *net_dev = switchdev_notifier_info_to_dev(ptr);

	switch (event) {
	case SWITCHDEV_PORT_OBJ_ADD:
		if (netif_is_vxlan(net_dev)) {
			err = -EOPNOTSUPP;
		} else {
			err = switchdev_handle_port_obj_add
			    (net_dev, ptr, prestera_netdev_check,
			     prestera_port_obj_add);
		}
		break;
	case SWITCHDEV_PORT_OBJ_DEL:
		if (netif_is_vxlan(net_dev)) {
			err = -EOPNOTSUPP;
		} else {
			err = switchdev_handle_port_obj_del
			    (net_dev, ptr, prestera_netdev_check,
			     prestera_port_obj_del);
		}
		break;
	case SWITCHDEV_PORT_ATTR_SET:
		err = switchdev_handle_port_attr_set
		    (net_dev, ptr, prestera_netdev_check,
		    prestera_port_obj_attr_set);
		break;
	default:
		err = -EOPNOTSUPP;
	}

	return notifier_from_errno(err);
}

static struct prestera_bridge *
prestera_bridge_create(struct prestera_switch *sw, struct net_device *br_dev)
{
	struct prestera_bridge *bridge;
	bool vlan_enabled = br_vlan_enabled(br_dev);
	u16 bridge_id;
	int err;

	if (vlan_enabled && sw->swdev->bridge_8021q_exists) {
		netdev_err(br_dev, "Only one VLAN-aware bridge is supported\n");
		return ERR_PTR(-EINVAL);
	}

	bridge = kzalloc(sizeof(*bridge), GFP_KERNEL);
	if (!bridge)
		return ERR_PTR(-ENOMEM);

	if (vlan_enabled) {
		sw->swdev->bridge_8021q_exists = true;
	} else {
		err = prestera_hw_bridge_create(sw, &bridge_id);
		if (err) {
			kfree(bridge);
			return ERR_PTR(err);
		}

		bridge->bridge_id = bridge_id;
	}

	bridge->dev = br_dev;
	bridge->vlan_enabled = vlan_enabled;
	bridge->isolation_srcid = PRESTERA_DEFAULT_ISOLATION_SRCID;
	bridge->multicast_enabled = br_multicast_enabled(br_dev);
	bridge->mrouter = br_multicast_router(br_dev);
	INIT_LIST_HEAD(&bridge->port_list);
	INIT_LIST_HEAD(&bridge->br_mdb_entry_list);

	list_add(&bridge->bridge_node, &sw->swdev->bridge_list);

	return bridge;
}

static void
prestera_bridge_destroy(struct prestera_switch *sw,
			struct prestera_bridge *bridge)
{
	list_del(&bridge->bridge_node);
	if (bridge->vlan_enabled)
		sw->swdev->bridge_8021q_exists = false;
	else
		prestera_hw_bridge_delete(sw, bridge->bridge_id);

	WARN_ON(!list_empty(&bridge->br_mdb_entry_list));
	WARN_ON(!list_empty(&bridge->port_list));
	kfree(bridge);
}

static struct prestera_bridge *
prestera_bridge_get(struct prestera_switch *sw, struct net_device *br_dev)
{
	struct prestera_bridge *bridge;

	bridge = prestera_bridge_find(sw, br_dev);
	if (bridge)
		return bridge;

	return prestera_bridge_create(sw, br_dev);
}

static void
prestera_bridge_put(struct prestera_switch *sw, struct prestera_bridge *bridge)
{
	if (list_empty(&bridge->port_list) && !bridge->ref_count)
		prestera_bridge_destroy(sw, bridge);
}

static struct prestera_bridge_port *
prestera_bridge_port_create(struct prestera_bridge *bridge,
			    struct net_device *brport_dev)
{
	struct prestera_bridge_port *br_port;
	struct prestera_port *port;

	br_port = kzalloc(sizeof(*br_port), GFP_KERNEL);
	if (!br_port)
		return NULL;

	port = prestera_port_dev_lower_find(brport_dev);

	br_port->dev = brport_dev;
	br_port->bridge = bridge;
	br_port->stp_state = BR_STATE_DISABLED;
	br_port->flags = BR_LEARNING | BR_FLOOD | BR_LEARNING_SYNC |
				BR_MCAST_FLOOD;
	INIT_LIST_HEAD(&br_port->vlan_list);
	INIT_LIST_HEAD(&br_port->br_mdb_port_list);

	list_add(&br_port->bridge_node, &bridge->port_list);
	br_port->ref_count = 1;

	return br_port;
}

static void
prestera_bridge_port_destroy(struct prestera_bridge_port *br_port)
{
	list_del(&br_port->bridge_node);
	WARN_ON(!list_empty(&br_port->vlan_list));
	WARN_ON(!list_empty(&br_port->br_mdb_port_list));
	kfree(br_port);
}

static struct prestera_bridge_port *
prestera_bridge_port_get(struct prestera_switch *sw, struct net_device *dev)
{
	struct net_device *br_dev = netdev_master_upper_dev_get(dev);
	struct prestera_bridge *bridge;
	struct prestera_bridge_port *br_port;
	int err;

	br_port = prestera_bridge_port_find(sw, dev);
	if (br_port) {
		br_port->ref_count++;
		return br_port;
	}

	bridge = prestera_bridge_get(sw, br_dev);
	if (IS_ERR(bridge))
		return ERR_CAST(bridge);

	br_port = prestera_bridge_port_create(bridge, dev);
	if (!br_port) {
		err = -ENOMEM;
		goto err_brport_create;
	}

	return br_port;

err_brport_create:
	prestera_bridge_put(sw, bridge);
	return ERR_PTR(err);
}

static void prestera_bridge_port_put(struct prestera_switch *sw,
				     struct prestera_bridge_port *br_port)
{
	struct prestera_bridge *bridge;

	if (--br_port->ref_count != 0)
		return;

	bridge = br_port->bridge;
	prestera_bridge_port_destroy(br_port);
	if (list_empty(&bridge->port_list)) {
		prestera_rif_enable(sw, bridge->dev, false);
		prestera_bridge_rifs_destroy(sw, bridge->dev);
	}
	prestera_bridge_put(sw, bridge);
}

static int
prestera_bridge_8021q_port_join(struct prestera_bridge *bridge,
				struct prestera_bridge_port *br_port,
				struct prestera_port *port,
				struct netlink_ext_ack *extack)
{
	if (is_vlan_dev(br_port->dev)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Can not enslave a VLAN device to a VLAN-aware bridge");
		return -EINVAL;
	}

	return 0;
}

static int
prestera_bridge_8021d_port_join(struct prestera_bridge *bridge,
				struct prestera_bridge_port *br_port,
				struct prestera_port *port,
				struct netlink_ext_ack *extack)
{
	int err;

	if (is_vlan_dev(br_port->dev)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Enslaving of a VLAN device is not supported");
		return -ENOTSUPP;
	}
	err = prestera_hw_bridge_port_add(port, bridge->bridge_id);
	if (err)
		return err;

	err = prestera_br_port_flags_set(br_port, port);
	if (err)
		goto err_flags2port_set;

	if (list_is_singular(&bridge->port_list))
		prestera_rif_enable(port->sw, bridge->dev, true);

	return err;

err_flags2port_set:
	prestera_hw_bridge_port_delete(port, bridge->bridge_id);
	return err;
}

int prestera_port_bridge_join(struct prestera_port *port,
			      struct net_device *brport_dev,
			      struct net_device *br_dev,
			      struct netlink_ext_ack *extack)
{
	struct prestera_bridge *bridge;
	struct prestera_switch *sw = port->sw;
	struct prestera_bridge_port *br_port;
	struct net_device *port_upper;
	int err;

	br_port = prestera_bridge_port_get(sw, brport_dev);
	if (IS_ERR(br_port))
		return PTR_ERR(br_port);

	bridge = br_port->bridge;

	/* Neither enslaved port nor its upper LAG is usable as a router interface */
	port_upper = netdev_master_upper_dev_get(port->net_dev);
	if (port_upper &&
	    netif_is_lag_master(port_upper) &&
	    prestera_rif_exists(sw, port_upper)) {
		prestera_rif_enable(sw, port_upper, false);
	}

	if (prestera_rif_exists(sw, port->net_dev))
		prestera_rif_enable(sw, port->net_dev, false);

	if (bridge->vlan_enabled) {
		err = prestera_bridge_8021q_port_join(bridge, br_port,
						      port, extack);
	} else {
		err = prestera_bridge_8021d_port_join(bridge, br_port,
						      port, extack);
	}

	if (err)
		goto err_port_join;

	return 0;

err_port_join:
	/* Offload RIF that was previosly disabled */
	if (prestera_rif_exists(sw, port->net_dev))
		prestera_rif_enable(sw, port->net_dev, true);

	if (port_upper &&
	    netif_is_lag_master(port_upper) &&
	    prestera_rif_exists(sw, port_upper))
		prestera_rif_enable(sw, port_upper, true);

	prestera_bridge_port_put(sw, br_port);
	return err;
}

static void
prestera_bridge_8021d_port_leave(struct prestera_bridge *bridge,
				 struct prestera_bridge_port *br_port,
				 struct prestera_port *port)
{
	prestera_fdb_flush_port(port, PRESTERA_FDB_FLUSH_MODE_ALL);
	prestera_hw_bridge_port_delete(port, bridge->bridge_id);
}

static void
prestera_bridge_8021q_port_leave(struct prestera_bridge *bridge,
				 struct prestera_bridge_port *br_port,
				 struct prestera_port *port)
{
	prestera_fdb_flush_port(port, PRESTERA_FDB_FLUSH_MODE_ALL);
	prestera_port_pvid_set(port, PRESTERA_DEFAULT_VID);
}

void prestera_port_bridge_leave(struct prestera_port *port,
				struct net_device *brport_dev,
				struct net_device *br_dev)
{
	struct prestera_switch *sw = port->sw;
	struct prestera_bridge *bridge;
	struct prestera_bridge_port *br_port;
	struct net_device *port_upper;

	bridge = prestera_bridge_find(sw, br_dev);
	if (!bridge)
		return;
	br_port = __prestera_bridge_port_find(bridge, brport_dev);
	if (!br_port)
		return;

	if (bridge->vlan_enabled)
		prestera_bridge_8021q_port_leave(bridge, br_port, port);
	else
		prestera_bridge_8021d_port_leave(bridge, br_port, port);

	prestera_mdb_flush_bridge_port(br_port);

	prestera_br_port_flags_reset(br_port, port);
	prestera_port_vid_stp_set(port, PRESTERA_VID_ALL, BR_STATE_FORWARDING);
	prestera_bridge_port_put(sw, br_port);

	/* Offload RIF that was previosly disabled */
	if (prestera_rif_exists(sw, port->net_dev))
		prestera_rif_enable(sw, port->net_dev, true);

	if (port_upper &&
	    netif_is_lag_master(port_upper) &&
	    prestera_rif_exists(sw, port_upper))
		prestera_rif_enable(sw, port_upper, true);
}

static int prestera_fdb_init(struct prestera_switch *sw)
{
	int err;

	err = prestera_switch_ageing_set(sw, PRESTERA_DEFAULT_AGEING_TIME);
	if (err)
		return err;

	return 0;
}

static struct prestera_br_mdb_entry *
prestera_br_mdb_entry_create(struct prestera_switch *sw,
			     struct prestera_bridge *br_dev,
			     const unsigned char *addr, u16 vid)
{
	struct prestera_br_mdb_entry *br_mdb_entry;
	struct prestera_mdb_entry *mdb_entry;

	br_mdb_entry = kzalloc(sizeof(*br_mdb_entry), GFP_KERNEL);
	if (!br_mdb_entry)
		return NULL;

	mdb_entry = prestera_mdb_entry_create(sw, addr, vid);
	if (!mdb_entry)
		goto err_mdb_alloc;

	br_mdb_entry->mdb = mdb_entry;
	br_mdb_entry->bridge = br_dev;
	br_mdb_entry->enabled = true;
	INIT_LIST_HEAD(&br_mdb_entry->br_mdb_port_list);

	list_add(&br_mdb_entry->br_mdb_entry_node, &br_dev->br_mdb_entry_list);

	return br_mdb_entry;

err_mdb_alloc:
	kfree(br_mdb_entry);
	return NULL;
}

static struct prestera_br_mdb_entry *
prestera_br_mdb_entry_find(struct prestera_bridge *br_dev,
			   const unsigned char *addr, u16 vid)
{
	struct prestera_br_mdb_entry *br_mdb;

	list_for_each_entry(br_mdb, &br_dev->br_mdb_entry_list,
			    br_mdb_entry_node)
		if (ether_addr_equal(&br_mdb->mdb->addr[0], addr) &&
		    vid == br_mdb->mdb->vid)
			return br_mdb;

	return NULL;
}

static struct prestera_br_mdb_entry *
prestera_br_mdb_entry_get(struct prestera_switch *sw,
			  struct prestera_bridge *br_dev,
			  const unsigned char *addr, u16 vid)
{
	struct prestera_br_mdb_entry *br_mdb;

	br_mdb = prestera_br_mdb_entry_find(br_dev, addr, vid);
	if (br_mdb)
		return br_mdb;

	return prestera_br_mdb_entry_create(sw, br_dev, addr, vid);
}

static void
prestera_br_mdb_entry_put(struct prestera_br_mdb_entry *br_mdb)
{
	struct prestera_bridge_port *br_port;

	if (list_empty(&br_mdb->br_mdb_port_list)) {
		list_for_each_entry(br_port, &br_mdb->bridge->port_list,
				    bridge_node)
			prestera_mdb_port_del(br_mdb->mdb, br_port->dev);

		prestera_mdb_entry_destroy(br_mdb->mdb);
		list_del(&br_mdb->br_mdb_entry_node);
		kfree(br_mdb);
	}
}

static int prestera_br_mdb_port_add(struct prestera_br_mdb_entry *br_mdb,
				    struct prestera_bridge_port *br_port)
{
	struct prestera_br_mdb_port *br_mdb_port;

	list_for_each_entry(br_mdb_port, &br_mdb->br_mdb_port_list,
			    br_mdb_port_node) {
		if (br_mdb_port->br_port == br_port)
			return 0;
	}

	br_mdb_port = kzalloc(sizeof(*br_mdb_port), GFP_KERNEL);
	if (!br_mdb_port)
		return -ENOMEM;

	br_mdb_port->br_port = br_port;
	list_add(&br_mdb_port->br_mdb_port_node,
		 &br_mdb->br_mdb_port_list);

	return 0;
}

static void
prestera_br_mdb_port_del(struct prestera_br_mdb_entry *br_mdb,
			 struct prestera_bridge_port *br_port)
{
	struct prestera_br_mdb_port *br_mdb_port, *tmp;

	list_for_each_entry_safe(br_mdb_port, tmp, &br_mdb->br_mdb_port_list,
				 br_mdb_port_node) {
		if (br_mdb_port->br_port == br_port) {
			list_del(&br_mdb_port->br_mdb_port_node);
			kfree(br_mdb_port);
		}
	}
}

static int
prestera_mdb_port_add(struct prestera_mdb_entry *mdb,
		      struct net_device *orig_dev,
		      const unsigned char addr[ETH_ALEN], u16 vid)
{
	struct prestera_flood_domain *flood_domain = mdb->flood_domain;
	int err;

	if (!prestera_flood_domain_port_find(flood_domain,
					     orig_dev, vid)) {
		err = prestera_flood_domain_port_create(flood_domain, orig_dev,
							vid);
		if (err)
			return err;
	}

	return 0;
}

static void
prestera_mdb_port_del(struct prestera_mdb_entry *mdb,
		      struct net_device *orig_dev)
{
	struct prestera_flood_domain *fl_domain = mdb->flood_domain;
	struct prestera_flood_domain_port *flood_domain_port;

	flood_domain_port = prestera_flood_domain_port_find(fl_domain,
							    orig_dev,
							    mdb->vid);
	if (flood_domain_port)
		prestera_flood_domain_port_destroy(flood_domain_port);
}

static void
prestera_mdb_flush_bridge_port(struct prestera_bridge_port *br_port)
{
	struct prestera_br_mdb_port *br_mdb_port, *tmp_port;
	struct prestera_br_mdb_entry *br_mdb, *br_mdb_tmp;
	struct prestera_bridge *br_dev = br_port->bridge;
	struct prestera_mdb_entry *mdb;

	list_for_each_entry_safe(br_mdb, br_mdb_tmp, &br_dev->br_mdb_entry_list,
				 br_mdb_entry_node) {
		mdb = br_mdb->mdb;

		WARN_ON(prestera_mdb_enable_set(br_mdb, false));

		list_for_each_entry_safe(br_mdb_port, tmp_port,
					 &br_mdb->br_mdb_port_list,
					 br_mdb_port_node) {
			prestera_mdb_port_del(br_mdb->mdb,
					      br_mdb_port->br_port->dev);
			prestera_br_mdb_port_del(br_mdb,  br_mdb_port->br_port);
			prestera_br_mdb_entry_put(br_mdb);
		}
	}
}

static int
prestera_mdb_port_addr_obj_add(const struct switchdev_obj_port_mdb *mdb)
{
	struct prestera_br_mdb_entry *br_mdb;
	struct prestera_bridge_port *br_port;
	struct prestera_bridge *br_dev;
	struct prestera_switch *sw;
	struct prestera_port *port;
	int err;

	sw = prestera_switch_get(mdb->obj.orig_dev);
	port = prestera_port_dev_lower_find(mdb->obj.orig_dev);

	br_port = prestera_bridge_port_find(sw, mdb->obj.orig_dev);
	if (!br_port)
		return 0;

	br_dev = br_port->bridge;

	if (mdb->vid && !prestera_port_vlan_find_by_vid(port, mdb->vid)->used)
		return 0;

	if (mdb->vid)
		br_mdb = prestera_br_mdb_entry_get(sw, br_dev, &mdb->addr[0],
						   mdb->vid);
	else
		br_mdb = prestera_br_mdb_entry_get(sw, br_dev, &mdb->addr[0],
						   br_dev->bridge_id);

	if (!br_mdb)
		return -ENOMEM;

	/*
	 * Make sure newly allocated MDB entry gets disabled if either MC is
	 * disabled, or the mrouter does not exist.
	 */
	WARN_ON(prestera_mdb_enable_set(br_mdb, br_dev->multicast_enabled &&
					br_dev->mrouter_exist));

	err = prestera_br_mdb_port_add(br_mdb, br_port);
	if (err) {
		prestera_br_mdb_entry_put(br_mdb);
		return err;
	}

	err = prestera_br_mdb_sync(br_dev);
	if (err)
		return err;

	return 0;
}

static int
prestera_mdb_port_addr_obj_del(struct prestera_port *port,
			       const struct switchdev_obj_port_mdb *mdb)
{
	struct prestera_br_mdb_entry *br_mdb;
	struct prestera_bridge_port *br_port;
	struct prestera_bridge *br_dev;
	int err;

	/* Bridge port no longer exists - and so does this MDB entry */
	br_port = prestera_bridge_port_find(port->sw, mdb->obj.orig_dev);
	if (!br_port)
		return 0;

	/* Removing MDB with non-existing VLAN - not supported; */
	if (mdb->vid && !prestera_port_vlan_find_by_vid(port, mdb->vid)->used)
		return 0;

	br_dev = br_port->bridge;

	if (br_port->bridge->vlan_enabled)
		br_mdb = prestera_br_mdb_entry_find(br_dev, &mdb->addr[0],
						    mdb->vid);
	else
		br_mdb = prestera_br_mdb_entry_find(br_dev, &mdb->addr[0],
						    br_port->bridge->bridge_id);

	if (!br_mdb)
		return 0;

	/*
	 * Since there might be a situation that this port was the last in the
	 * MDB group, we have to both remove this port from software and HW MDB,
	 * and then sync MDB table, and destroy software MDB (if needed).
	 */
	prestera_br_mdb_port_del(br_mdb, br_port);

	prestera_br_mdb_entry_put(br_mdb);

	err = prestera_br_mdb_sync(br_dev);
	if (err)
		return err;

	return 0;
}

int prestera_switchdev_init(struct prestera_switch *sw)
{
	struct prestera_switchdev *swdev;
	int err = 0;

	if (sw->swdev)
		return -EPERM;

	swdev = kzalloc(sizeof(*sw->swdev), GFP_KERNEL);
	if (!swdev)
		return -ENOMEM;

	sw->swdev = swdev;
	swdev->sw = sw;

	INIT_LIST_HEAD(&sw->swdev->bridge_list);
	err = rhashtable_init(&sw->swdev->routed_fdb_ht,
			      &__prestera_routed_fdb_ht_params);
	if (err)
		goto err_init_rfdb_ht;

	swdev_owq = alloc_ordered_workqueue("%s_ordered", 0, "prestera_sw");
	if (!swdev_owq) {
		err = -ENOMEM;
		goto err_alloc_workqueue;
	}

	swdev->swdev_n.notifier_call = prestera_switchdev_event;
	err = register_switchdev_notifier(&swdev->swdev_n);
	if (err)
		goto err_register_switchdev_notifier;

	swdev->swdev_blocking_n.notifier_call =
			prestera_switchdev_blocking_event;
	err = register_switchdev_blocking_notifier(&swdev->swdev_blocking_n);
	if (err)
		goto err_register_block_switchdev_notifier;

	prestera_fdb_init(sw);

	return 0;

err_register_block_switchdev_notifier:
	unregister_switchdev_notifier(&swdev->swdev_n);
err_register_switchdev_notifier:
	destroy_workqueue(swdev_owq);
err_alloc_workqueue:
	rhashtable_destroy(&sw->swdev->routed_fdb_ht);
err_init_rfdb_ht:
	kfree(swdev);
	return err;
}

void prestera_switchdev_fini(struct prestera_switch *sw)
{
	if (!sw->swdev)
		return;

	unregister_switchdev_notifier(&sw->swdev->swdev_n);
	unregister_switchdev_blocking_notifier
	    (&sw->swdev->swdev_blocking_n);
	flush_workqueue(swdev_owq);
	destroy_workqueue(swdev_owq);
	rhashtable_destroy(&sw->swdev->routed_fdb_ht);
	kfree(sw->swdev);
	sw->swdev = NULL;
}
