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

#include "prestera.h"

#define MVSW_PR_VID_ALL (0xffff)
#define PRESTERA_DEFAULT_ISOLATION_SRCID 1 /* source_id */

struct prestera_bridge {
	struct prestera_switch *sw;
	u32 ageing_time;
	struct list_head bridge_list;
	bool bridge_8021q_exists;
};

struct prestera_bridge_device {
	struct net_device *dev;
	struct list_head bridge_node;
	struct list_head port_list;
	u16 bridge_id;
	/* This can be extended to list of isolation groups */
	u32 isolation_srcid; /* source_id */
	u8 vlan_enabled:1, multicast_enabled:1, mrouter:1;
};

struct prestera_bridge_port {
	struct net_device *dev;
	struct prestera_bridge_device *bridge_device;
	struct list_head bridge_device_node;
	struct list_head vlan_list;
	unsigned int ref_count;
	u8 stp_state;
	unsigned long flags;
};

struct mvsw_pr_bridge_vlan {
	struct list_head bridge_port_node;
	struct list_head port_vlan_list;
	u16 vid;
};

struct mvsw_pr_event_work {
	struct work_struct work;
	struct switchdev_notifier_fdb_info fdb_info;
	struct net_device *dev;
	unsigned long event;
};

static struct workqueue_struct *mvsw_owq;

static struct prestera_bridge_port *
mvsw_pr_bridge_port_get(struct prestera_bridge *bridge,
			struct net_device *brport_dev);

static void mvsw_pr_bridge_port_put(struct prestera_bridge *bridge,
				    struct prestera_bridge_port *br_port);

struct prestera_bridge_device *
prestera_bridge_device_find(const struct prestera_bridge *bridge,
			    const struct net_device *br_dev)
{
	struct prestera_bridge_device *bridge_device;

	list_for_each_entry(bridge_device, &bridge->bridge_list,
			    bridge_node)
		if (bridge_device->dev == br_dev)
			return bridge_device;

	return NULL;
}

static bool
mvsw_pr_bridge_device_is_offloaded(const struct prestera_switch *sw,
				   const struct net_device *br_dev)
{
	return !!prestera_bridge_device_find(sw->bridge, br_dev);
}

static struct prestera_bridge_port *
__mvsw_pr_bridge_port_find(const struct prestera_bridge_device *bridge_device,
			   const struct net_device *brport_dev)
{
	struct prestera_bridge_port *br_port;

	list_for_each_entry(br_port, &bridge_device->port_list,
			    bridge_device_node) {
		if (br_port->dev == brport_dev)
			return br_port;
	}

	return NULL;
}

static struct prestera_bridge_port *
mvsw_pr_bridge_port_find(struct prestera_bridge *bridge,
			 struct net_device *brport_dev)
{
	struct net_device *br_dev = netdev_master_upper_dev_get(brport_dev);
	struct prestera_bridge_device *bridge_device;

	if (!br_dev)
		return NULL;

	bridge_device = prestera_bridge_device_find(bridge, br_dev);
	if (!bridge_device)
		return NULL;

	return __mvsw_pr_bridge_port_find(bridge_device, brport_dev);
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
	struct prestera_bridge_device *br_dev;
	u32 iso_srcid;
	int err;

	br_dev = br_port->bridge_device;

	err = prestera_port_uc_flood_set(port, br_port->flags & BR_FLOOD);
	if (err)
		goto err_out;

	err = prestera_port_mc_flood_set(port, br_port->flags & BR_MCAST_FLOOD);
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

static struct mvsw_pr_bridge_vlan *
mvsw_pr_bridge_vlan_find(const struct prestera_bridge_port *br_port, u16 vid)
{
	struct mvsw_pr_bridge_vlan *br_vlan;

	list_for_each_entry(br_vlan, &br_port->vlan_list, bridge_port_node) {
		if (br_vlan->vid == vid)
			return br_vlan;
	}

	return NULL;
}

u16 prestera_vlan_dev_vlan_id(struct prestera_bridge *bridge,
			      struct net_device *dev)
{
	struct prestera_bridge_device *bridge_dev;

	bridge_dev = prestera_bridge_device_find(bridge, dev);

	return bridge_dev ? bridge_dev->bridge_id : 0;
}

static struct mvsw_pr_bridge_vlan *
mvsw_pr_bridge_vlan_create(struct prestera_bridge_port *br_port, u16 vid)
{
	struct mvsw_pr_bridge_vlan *br_vlan;

	br_vlan = kzalloc(sizeof(*br_vlan), GFP_KERNEL);
	if (!br_vlan)
		return NULL;

	INIT_LIST_HEAD(&br_vlan->port_vlan_list);
	br_vlan->vid = vid;
	list_add(&br_vlan->bridge_port_node, &br_port->vlan_list);

	return br_vlan;
}

static void
mvsw_pr_bridge_vlan_destroy(struct mvsw_pr_bridge_vlan *br_vlan)
{
	list_del(&br_vlan->bridge_port_node);
	WARN_ON(!list_empty(&br_vlan->port_vlan_list));
	kfree(br_vlan);
}

static struct mvsw_pr_bridge_vlan *
mvsw_pr_bridge_vlan_get(struct prestera_bridge_port *br_port, u16 vid)
{
	struct mvsw_pr_bridge_vlan *br_vlan;

	br_vlan = mvsw_pr_bridge_vlan_find(br_port, vid);
	if (br_vlan)
		return br_vlan;

	return mvsw_pr_bridge_vlan_create(br_port, vid);
}

static void mvsw_pr_bridge_vlan_put(struct mvsw_pr_bridge_vlan *br_vlan)
{
	if (list_empty(&br_vlan->port_vlan_list))
		mvsw_pr_bridge_vlan_destroy(br_vlan);
}

static int
mvsw_pr_port_vlan_bridge_join(struct prestera_port_vlan *port_vlan,
			      struct prestera_bridge_port *br_port,
			      struct netlink_ext_ack *extack)
{
	struct prestera_port *port = port_vlan->mvsw_pr_port;
	struct mvsw_pr_bridge_vlan *br_vlan;
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

	br_vlan = mvsw_pr_bridge_vlan_get(br_port, vid);
	if (!br_vlan) {
		err = -ENOMEM;
		goto err_bridge_vlan_get;
	}

	list_add(&port_vlan->bridge_vlan_node, &br_vlan->port_vlan_list);

	mvsw_pr_bridge_port_get(port->sw->bridge, br_port->dev);
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
mvsw_pr_bridge_vlan_port_count_get(struct prestera_bridge_device *bridge_device,
				   u16 vid)
{
	int count = 0;
	struct prestera_bridge_port *br_port;
	struct mvsw_pr_bridge_vlan *br_vlan;

	list_for_each_entry(br_port, &bridge_device->port_list,
			    bridge_device_node) {
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

void
prestera_port_vlan_bridge_leave(struct prestera_port_vlan *port_vlan)
{
	struct prestera_port *port = port_vlan->mvsw_pr_port;
	u32 mode = MVSW_PR_FDB_FLUSH_MODE_DYNAMIC;
	struct mvsw_pr_bridge_vlan *br_vlan;
	struct prestera_bridge_port *br_port;
	u16 vid = port_vlan->vid;
	bool last_port, last_vlan;
	int port_count;

	br_port = port_vlan->bridge_port;
	last_vlan = list_is_singular(&br_port->vlan_list);
	port_count =
	    mvsw_pr_bridge_vlan_port_count_get(br_port->bridge_device, vid);
	br_vlan = mvsw_pr_bridge_vlan_find(br_port, vid);
	last_port = port_count == 1;
	if (last_vlan)
		prestera_fdb_flush_port(port, mode);
	else if (last_port)
		prestera_fdb_flush_vlan(port->sw, vid, mode);
	else
		prestera_fdb_flush_port_vlan(port, vid, mode);

	list_del(&port_vlan->bridge_vlan_node);
	mvsw_pr_bridge_vlan_put(br_vlan);
	prestera_port_vid_stp_set(port, vid, BR_STATE_FORWARDING);
	mvsw_pr_bridge_port_put(port->sw->bridge, br_port);
	port_vlan->bridge_port = NULL;
}

static int
mvsw_pr_bridge_port_vlan_add(struct prestera_port *port,
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
	if (port_vlan && port_vlan->bridge_port != br_port)
		return -EEXIST;

	if (!port_vlan) {
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

	err = mvsw_pr_port_vlan_bridge_join(port_vlan, br_port, extack);
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

static int mvsw_pr_port_vlans_add(struct prestera_port *port,
				  const struct switchdev_obj_port_vlan *vlan,
				  struct switchdev_trans *trans,
				  struct netlink_ext_ack *extack)
{
	bool flag_untagged = vlan->flags & BRIDGE_VLAN_INFO_UNTAGGED;
	bool flag_pvid = vlan->flags & BRIDGE_VLAN_INFO_PVID;
	struct net_device *orig_dev = vlan->obj.orig_dev;
	struct prestera_bridge_port *br_port;
	struct prestera_bridge_device *bridge_device;
	struct prestera_switch *sw = port->sw;
	u16 vid;

	if (netif_is_bridge_master(orig_dev))
		return 0;

	if (switchdev_trans_ph_commit(trans))
		return 0;

	br_port = mvsw_pr_bridge_port_find(sw->bridge, orig_dev);
	if (WARN_ON(!br_port))
		return -EINVAL;

	bridge_device = br_port->bridge_device;
	if (!bridge_device->vlan_enabled)
		return 0;

	for (vid = vlan->vid_begin; vid <= vlan->vid_end; vid++) {
		int err;

		err = mvsw_pr_bridge_port_vlan_add(port, br_port,
						   vid, flag_untagged,
						   flag_pvid, extack);
		if (err)
			return err;
	}

	if (list_is_singular(&bridge_device->port_list))
		prestera_rif_enable(port->sw, bridge_device->dev, true);

	return 0;
}

static int mvsw_pr_port_obj_add(struct net_device *dev,
				const struct switchdev_obj *obj,
				struct switchdev_trans *trans,
				struct netlink_ext_ack *extack)
{
	int err = 0;
	struct prestera_port *port = netdev_priv(dev);
	const struct switchdev_obj_port_vlan *vlan;

	switch (obj->id) {
	case SWITCHDEV_OBJ_ID_PORT_VLAN:
		vlan = SWITCHDEV_OBJ_PORT_VLAN(obj);
		err = mvsw_pr_port_vlans_add(port, vlan, trans, extack);
		break;
	default:
		err = -EOPNOTSUPP;
	}

	return err;
}

static void
mvsw_pr_bridge_port_vlan_del(struct prestera_port *port,
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

static int mvsw_pr_port_vlans_del(struct prestera_port *port,
				  const struct switchdev_obj_port_vlan *vlan)
{
	struct prestera_switch *sw = port->sw;
	struct net_device *orig_dev = vlan->obj.orig_dev;
	struct prestera_bridge_port *br_port;
	u16 vid;

	if (netif_is_bridge_master(orig_dev))
		return -EOPNOTSUPP;

	br_port = mvsw_pr_bridge_port_find(sw->bridge, orig_dev);
	if (WARN_ON(!br_port))
		return -EINVAL;

	if (!br_port->bridge_device->vlan_enabled)
		return 0;

	for (vid = vlan->vid_begin; vid <= vlan->vid_end; vid++)
		mvsw_pr_bridge_port_vlan_del(port, br_port, vid);

	return 0;
}

static int mvsw_pr_port_obj_del(struct net_device *dev,
				const struct switchdev_obj *obj)
{
	int err = 0;
	struct prestera_port *port = netdev_priv(dev);

	switch (obj->id) {
	case SWITCHDEV_OBJ_ID_PORT_VLAN:
		err = mvsw_pr_port_vlans_del(port,
					     SWITCHDEV_OBJ_PORT_VLAN(obj));
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	return err;
}

static int mvsw_pr_port_attr_br_vlan_set(struct prestera_port *port,
					 struct switchdev_trans *trans,
					 struct net_device *orig_dev,
					 bool vlan_enabled)
{
	struct prestera_switch *sw = port->sw;
	struct prestera_bridge_device *bridge_device;

	if (!switchdev_trans_ph_prepare(trans))
		return 0;

	bridge_device = prestera_bridge_device_find(sw->bridge, orig_dev);
	if (WARN_ON(!bridge_device))
		return -EINVAL;

	if (bridge_device->vlan_enabled == vlan_enabled)
		return 0;

	netdev_err(bridge_device->dev,
		   "VLAN filtering can't be changed for existing bridge\n");
	return -EINVAL;
}

static int mvsw_pr_port_attr_br_flags_set(struct prestera_port *port,
					  struct switchdev_trans *trans,
					  struct net_device *orig_dev,
					  unsigned long flags)
{
	struct prestera_bridge_port *br_port;

	if (switchdev_trans_ph_prepare(trans))
		return 0;

	br_port = mvsw_pr_bridge_port_find(port->sw->bridge, orig_dev);
	if (!br_port)
		return 0;

	memcpy(&br_port->flags, &flags, sizeof(flags));
	return prestera_br_port_flags_set(br_port, port);
}

static int mvsw_pr_port_attr_br_ageing_set(struct prestera_port *port,
					   struct switchdev_trans *trans,
					   unsigned long ageing_clock_t)
{
	int err;
	struct prestera_switch *sw = port->sw;
	unsigned long ageing_jiffies = clock_t_to_jiffies(ageing_clock_t);
	u32 ageing_time = jiffies_to_msecs(ageing_jiffies);

	if (switchdev_trans_ph_prepare(trans)) {
		if (ageing_time < PRESTERA_MIN_AGEING_TIME ||
		    ageing_time > PRESTERA_MAX_AGEING_TIME)
			return -ERANGE;
		else
			return 0;
	}

	err = prestera_switch_ageing_set(sw, ageing_time);
	if (!err)
		sw->bridge->ageing_time = ageing_time;

	return err;
}

static int
mvsw_pr_port_bridge_vlan_stp_set(struct prestera_port *port,
				 struct mvsw_pr_bridge_vlan *br_vlan,
				 u8 state)
{
	struct prestera_port_vlan *port_vlan;

	list_for_each_entry(port_vlan, &br_vlan->port_vlan_list,
			    bridge_vlan_node) {
		if (port_vlan->mvsw_pr_port != port)
			continue;
		return prestera_port_vid_stp_set(port, br_vlan->vid, state);
	}

	return 0;
}

static int mvsw_pr_port_attr_stp_state_set(struct prestera_port *port,
					   struct switchdev_trans *trans,
					   struct net_device *orig_dev,
					   u8 state)
{
	struct prestera_bridge_port *br_port;
	struct mvsw_pr_bridge_vlan *br_vlan;
	int err;
	u16 vid;

	if (switchdev_trans_ph_prepare(trans))
		return 0;

	br_port = mvsw_pr_bridge_port_find(port->sw->bridge, orig_dev);
	if (!br_port)
		return 0;

	if (!br_port->bridge_device->vlan_enabled) {
		vid = br_port->bridge_device->bridge_id;
		err = prestera_port_vid_stp_set(port, vid, state);
		if (err)
			goto err_port_bridge_stp_set;
	} else {
		list_for_each_entry(br_vlan, &br_port->vlan_list,
				    bridge_port_node) {
			err = mvsw_pr_port_bridge_vlan_stp_set(port, br_vlan,
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
		mvsw_pr_port_bridge_vlan_stp_set(port, br_vlan,
						 br_port->stp_state);
	return err;

err_port_bridge_stp_set:
	prestera_port_vid_stp_set(port, vid, br_port->stp_state);

	return err;
}

static int mvsw_pr_port_attr_br_mc_disabled_set(struct prestera_port *port,
						struct switchdev_trans *trans,
						struct net_device *orig_dev,
						bool mc_disabled)
{
	struct prestera_switch *sw = port->sw;
	struct prestera_bridge_device *br_dev;
	struct prestera_bridge_port *br_port;
	bool enabled = !mc_disabled;
	int err;

	if (!switchdev_trans_ph_prepare(trans))
		return 0;

	br_dev = prestera_bridge_device_find(sw->bridge, orig_dev);
	if (!br_dev)
		return 0;

	if (br_dev->multicast_enabled == enabled)
		return 0;

	list_for_each_entry(br_port, &br_dev->port_list, bridge_device_node) {
		err = prestera_port_mc_flood_set(netdev_priv(br_port->dev),
						 enabled);
		if (err)
			return err;
	}

	br_dev->multicast_enabled = enabled;

	return 0;
}

static int mvsw_pr_port_obj_attr_set(struct net_device *dev,
				     const struct switchdev_attr *attr,
				     struct switchdev_trans *trans)
{
	int err = 0;
	struct prestera_port *port = netdev_priv(dev);

	switch (attr->id) {
	case SWITCHDEV_ATTR_ID_PORT_STP_STATE:
		err = mvsw_pr_port_attr_stp_state_set(port, trans,
						      attr->orig_dev,
						      attr->u.stp_state);
		break;
	case SWITCHDEV_ATTR_ID_PORT_PRE_BRIDGE_FLAGS:
		if (attr->u.brport_flags &
		    ~(BR_LEARNING | BR_FLOOD | BR_MCAST_FLOOD | BR_ISOLATED))
			err = -EINVAL;
		break;
	case SWITCHDEV_ATTR_ID_PORT_BRIDGE_FLAGS:
		err = mvsw_pr_port_attr_br_flags_set(port, trans,
						     attr->orig_dev,
						     attr->u.brport_flags);
		break;
	case SWITCHDEV_ATTR_ID_BRIDGE_AGEING_TIME:
		err = mvsw_pr_port_attr_br_ageing_set(port, trans,
						      attr->u.ageing_time);
		break;
	case SWITCHDEV_ATTR_ID_BRIDGE_VLAN_FILTERING:
		err = mvsw_pr_port_attr_br_vlan_set(port, trans,
						    attr->orig_dev,
						    attr->u.vlan_filtering);
		break;
	case SWITCHDEV_ATTR_ID_BRIDGE_MC_DISABLED:
		err = mvsw_pr_port_attr_br_mc_disabled_set(port, trans,
							   attr->orig_dev,
							   attr->u.mc_disabled);
		break;
	default:
		err = -EOPNOTSUPP;
	}

	return err;
}

static void mvsw_fdb_offload_notify(struct prestera_port *port,
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

static int
mvsw_pr_port_fdb_set(struct prestera_port *port,
		     struct switchdev_notifier_fdb_info *fdb_info, bool adding)
{
	struct prestera_switch *sw = port->sw;
	struct prestera_bridge_port *br_port;
	struct prestera_bridge_device *bridge_device;
	struct net_device *orig_dev = fdb_info->info.dev;
	int err;
	u16 vid;

	br_port = mvsw_pr_bridge_port_find(sw->bridge, orig_dev);
	if (!br_port)
		return -EINVAL;

	bridge_device = br_port->bridge_device;

	if (bridge_device->vlan_enabled)
		vid = fdb_info->vid;
	else
		vid = bridge_device->bridge_id;

	if (adding)
		err = prestera_fdb_add(port, fdb_info->addr, vid, false);
	else
		err = prestera_fdb_del(port, fdb_info->addr, vid);

	return err;
}

static void mvsw_pr_bridge_fdb_event_work(struct work_struct *work)
{
	int err = 0;
	struct mvsw_pr_event_work *switchdev_work =
	    container_of(work, struct mvsw_pr_event_work, work);
	struct net_device *dev = switchdev_work->dev;
	struct switchdev_notifier_fdb_info *fdb_info;
	struct prestera_port *port;

	rtnl_lock();
	if (netif_is_vxlan(dev))
		goto out;

	port = prestera_port_dev_lower_find(dev);
	if (!port)
		goto out;

	switch (switchdev_work->event) {
	case SWITCHDEV_FDB_ADD_TO_DEVICE:
		fdb_info = &switchdev_work->fdb_info;
		if (!fdb_info->added_by_user)
			break;
		err = mvsw_pr_port_fdb_set(port, fdb_info, true);
		if (err)
			break;
		mvsw_fdb_offload_notify(port, fdb_info);
		break;
	case SWITCHDEV_FDB_DEL_TO_DEVICE:
		fdb_info = &switchdev_work->fdb_info;
		mvsw_pr_port_fdb_set(port, fdb_info, false);
		break;
	case SWITCHDEV_FDB_ADD_TO_BRIDGE:
	case SWITCHDEV_FDB_DEL_TO_BRIDGE:
		prestera_k_arb_fdb_evt(port->sw, port->net_dev);
		break;
	}

out:
	rtnl_unlock();
	kfree(switchdev_work->fdb_info.addr);
	kfree(switchdev_work);
	dev_put(dev);
}

static int prestera_switchdev_event(struct notifier_block *unused,
				    unsigned long event, void *ptr)
{
	int err = 0;
	struct net_device *net_dev = switchdev_notifier_info_to_dev(ptr);
	struct mvsw_pr_event_work *switchdev_work;
	struct switchdev_notifier_fdb_info *fdb_info;
	struct switchdev_notifier_info *info = ptr;
	struct net_device *upper_br;

	if (event == SWITCHDEV_PORT_ATTR_SET) {
		err = switchdev_handle_port_attr_set(net_dev, ptr,
						     prestera_netdev_check,
						     mvsw_pr_port_obj_attr_set);
		return notifier_from_errno(err);
	}

	upper_br = netdev_master_upper_dev_get_rcu(net_dev);
	if (!upper_br)
		return NOTIFY_DONE;

	if (!netif_is_bridge_master(upper_br))
		return NOTIFY_DONE;

	switchdev_work = kzalloc(sizeof(*switchdev_work), GFP_ATOMIC);
	if (!switchdev_work)
		return NOTIFY_BAD;

	switchdev_work->dev = net_dev;
	switchdev_work->event = event;

	switch (event) {
	case SWITCHDEV_FDB_ADD_TO_DEVICE:
	case SWITCHDEV_FDB_DEL_TO_DEVICE:
	case SWITCHDEV_FDB_ADD_TO_BRIDGE:
	case SWITCHDEV_FDB_DEL_TO_BRIDGE:
		fdb_info = container_of(info,
					struct switchdev_notifier_fdb_info,
					info);

		INIT_WORK(&switchdev_work->work, mvsw_pr_bridge_fdb_event_work);
		memcpy(&switchdev_work->fdb_info, ptr,
		       sizeof(switchdev_work->fdb_info));
		switchdev_work->fdb_info.addr = kzalloc(ETH_ALEN, GFP_ATOMIC);
		if (!switchdev_work->fdb_info.addr)
			goto out;
		ether_addr_copy((u8 *)switchdev_work->fdb_info.addr,
				fdb_info->addr);
		dev_hold(net_dev);

		break;
	case SWITCHDEV_VXLAN_FDB_ADD_TO_DEVICE:
	case SWITCHDEV_VXLAN_FDB_DEL_TO_DEVICE:
	default:
		kfree(switchdev_work);
		return NOTIFY_DONE;
	}

	queue_work(mvsw_owq, &switchdev_work->work);
	return NOTIFY_DONE;
out:
	kfree(switchdev_work);
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
			     mvsw_pr_port_obj_add);
		}
		break;
	case SWITCHDEV_PORT_OBJ_DEL:
		if (netif_is_vxlan(net_dev)) {
			err = -EOPNOTSUPP;
		} else {
			err = switchdev_handle_port_obj_del
			    (net_dev, ptr, prestera_netdev_check,
			     mvsw_pr_port_obj_del);
		}
		break;
	case SWITCHDEV_PORT_ATTR_SET:
		err = switchdev_handle_port_attr_set
		    (net_dev, ptr, prestera_netdev_check,
		    mvsw_pr_port_obj_attr_set);
		break;
	default:
		err = -EOPNOTSUPP;
	}

	return notifier_from_errno(err);
}

static struct prestera_bridge_device *
mvsw_pr_bridge_device_create(struct prestera_bridge *bridge,
			     struct net_device *br_dev)
{
	struct prestera_bridge_device *bridge_device;
	bool vlan_enabled = br_vlan_enabled(br_dev);
	u16 bridge_id;
	int err;

	if (vlan_enabled && bridge->bridge_8021q_exists) {
		netdev_err(br_dev, "Only one VLAN-aware bridge is supported\n");
		return ERR_PTR(-EINVAL);
	}

	bridge_device = kzalloc(sizeof(*bridge_device), GFP_KERNEL);
	if (!bridge_device)
		return ERR_PTR(-ENOMEM);

	if (vlan_enabled) {
		bridge->bridge_8021q_exists = true;
	} else {
		err = prestera_8021d_bridge_create(bridge->sw, &bridge_id);
		if (err) {
			kfree(bridge_device);
			return ERR_PTR(err);
		}

		bridge_device->bridge_id = bridge_id;
	}

	bridge_device->dev = br_dev;
	bridge_device->vlan_enabled = vlan_enabled;
	bridge_device->isolation_srcid = PRESTERA_DEFAULT_ISOLATION_SRCID;
	bridge_device->multicast_enabled = br_multicast_enabled(br_dev);
	bridge_device->mrouter = br_multicast_router(br_dev);
	INIT_LIST_HEAD(&bridge_device->port_list);

	list_add(&bridge_device->bridge_node, &bridge->bridge_list);

	return bridge_device;
}

static void
mvsw_pr_bridge_device_destroy(struct prestera_bridge *bridge,
			      struct prestera_bridge_device *bridge_device)
{
	list_del(&bridge_device->bridge_node);
	if (bridge_device->vlan_enabled)
		bridge->bridge_8021q_exists = false;
	else
		prestera_8021d_bridge_delete(bridge->sw,
					     bridge_device->bridge_id);

	WARN_ON(!list_empty(&bridge_device->port_list));
	kfree(bridge_device);
}

static struct prestera_bridge_device *
mvsw_pr_bridge_device_get(struct prestera_bridge *bridge,
			  struct net_device *br_dev)
{
	struct prestera_bridge_device *bridge_device;

	bridge_device = prestera_bridge_device_find(bridge, br_dev);
	if (bridge_device)
		return bridge_device;

	return mvsw_pr_bridge_device_create(bridge, br_dev);
}

static void
mvsw_pr_bridge_device_put(struct prestera_bridge *bridge,
			  struct prestera_bridge_device *bridge_device)
{
	if (list_empty(&bridge_device->port_list))
		mvsw_pr_bridge_device_destroy(bridge, bridge_device);
}

static struct prestera_bridge_port *
mvsw_pr_bridge_port_create(struct prestera_bridge_device *bridge_device,
			   struct net_device *brport_dev)
{
	struct prestera_bridge_port *br_port;
	struct prestera_port *port;

	br_port = kzalloc(sizeof(*br_port), GFP_KERNEL);
	if (!br_port)
		return NULL;

	port = prestera_port_dev_lower_find(brport_dev);

	br_port->dev = brport_dev;
	br_port->bridge_device = bridge_device;
	br_port->stp_state = BR_STATE_DISABLED;
	br_port->flags = BR_LEARNING | BR_FLOOD | BR_LEARNING_SYNC |
				BR_MCAST_FLOOD;
	INIT_LIST_HEAD(&br_port->vlan_list);
	list_add(&br_port->bridge_device_node, &bridge_device->port_list);
	br_port->ref_count = 1;

	return br_port;
}

static void
mvsw_pr_bridge_port_destroy(struct prestera_bridge_port *br_port)
{
	list_del(&br_port->bridge_device_node);
	WARN_ON(!list_empty(&br_port->vlan_list));
	kfree(br_port);
}

static struct prestera_bridge_port *
mvsw_pr_bridge_port_get(struct prestera_bridge *bridge,
			struct net_device *brport_dev)
{
	struct net_device *br_dev = netdev_master_upper_dev_get(brport_dev);
	struct prestera_bridge_device *bridge_device;
	struct prestera_bridge_port *br_port;
	int err;

	br_port = mvsw_pr_bridge_port_find(bridge, brport_dev);
	if (br_port) {
		br_port->ref_count++;
		return br_port;
	}

	bridge_device = mvsw_pr_bridge_device_get(bridge, br_dev);
	if (IS_ERR(bridge_device))
		return ERR_CAST(bridge_device);

	br_port = mvsw_pr_bridge_port_create(bridge_device, brport_dev);
	if (!br_port) {
		err = -ENOMEM;
		goto err_brport_create;
	}

	return br_port;

err_brport_create:
	mvsw_pr_bridge_device_put(bridge, bridge_device);
	return ERR_PTR(err);
}

static void mvsw_pr_bridge_port_put(struct prestera_bridge *bridge,
				    struct prestera_bridge_port *br_port)
{
	struct prestera_bridge_device *bridge_device;

	if (--br_port->ref_count != 0)
		return;
	bridge_device = br_port->bridge_device;
	mvsw_pr_bridge_port_destroy(br_port);
	if (list_empty(&bridge_device->port_list)) {
		prestera_rif_enable(bridge->sw, bridge_device->dev, false);
		prestera_bridge_device_rifs_destroy(bridge->sw,
						    bridge_device->dev);
	}
	mvsw_pr_bridge_device_put(bridge, bridge_device);
}

static int
mvsw_pr_bridge_8021q_port_join(struct prestera_bridge_device *bridge_device,
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
mvsw_pr_bridge_8021d_port_join(struct prestera_bridge_device *bridge_device,
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
	err = prestera_8021d_bridge_port_add(port, bridge_device->bridge_id);
	if (err)
		return err;

	err = prestera_br_port_flags_set(br_port, port);
	if (err)
		goto err_flags2port_set;

	if (list_is_singular(&bridge_device->port_list))
		prestera_rif_enable(port->sw, bridge_device->dev, true);

	return err;

err_flags2port_set:
	prestera_8021d_bridge_port_delete(port, bridge_device->bridge_id);
	return err;
}

static int mvsw_pr_port_bridge_join(struct prestera_port *port,
				    struct net_device *brport_dev,
				    struct net_device *br_dev,
				    struct netlink_ext_ack *extack)
{
	struct prestera_bridge_device *bridge_device;
	struct prestera_switch *sw = port->sw;
	struct prestera_bridge_port *br_port;
	int err;

	br_port = mvsw_pr_bridge_port_get(sw->bridge, brport_dev);
	if (IS_ERR(br_port))
		return PTR_ERR(br_port);

	bridge_device = br_port->bridge_device;

	/* Enslaved port is not usable as a router interface */
	if (prestera_rif_exists(sw, port->net_dev))
		prestera_rif_enable(sw, port->net_dev, false);

	if (bridge_device->vlan_enabled) {
		err = mvsw_pr_bridge_8021q_port_join(bridge_device, br_port,
						     port, extack);
	} else {
		err = mvsw_pr_bridge_8021d_port_join(bridge_device, br_port,
						     port, extack);
	}

	if (err)
		goto err_port_join;

	return 0;

err_port_join:
	mvsw_pr_bridge_port_put(sw->bridge, br_port);
	return err;
}

static void
mvsw_pr_bridge_8021d_port_leave(struct prestera_bridge_device *bridge_device,
				struct prestera_bridge_port *br_port,
				struct prestera_port *port)
{
	prestera_fdb_flush_port(port, MVSW_PR_FDB_FLUSH_MODE_ALL);
	prestera_8021d_bridge_port_delete(port, bridge_device->bridge_id);
}

static void
mvsw_pr_bridge_8021q_port_leave(struct prestera_bridge_device *bridge_device,
				struct prestera_bridge_port *br_port,
				struct prestera_port *port)
{
	prestera_fdb_flush_port(port, MVSW_PR_FDB_FLUSH_MODE_ALL);
	prestera_port_pvid_set(port, PRESTERA_DEFAULT_VID);
}

static void mvsw_pr_port_bridge_leave(struct prestera_port *port,
				      struct net_device *brport_dev,
				      struct net_device *br_dev)
{
	struct prestera_switch *sw = port->sw;
	struct prestera_bridge_device *bridge_device;
	struct prestera_bridge_port *br_port;

	bridge_device = prestera_bridge_device_find(sw->bridge, br_dev);
	if (!bridge_device)
		return;
	br_port = __mvsw_pr_bridge_port_find(bridge_device, brport_dev);
	if (!br_port)
		return;

	if (bridge_device->vlan_enabled)
		mvsw_pr_bridge_8021q_port_leave(bridge_device, br_port, port);
	else
		mvsw_pr_bridge_8021d_port_leave(bridge_device, br_port, port);

	prestera_br_port_flags_reset(br_port, port);
	prestera_port_vid_stp_set(port, MVSW_PR_VID_ALL, BR_STATE_FORWARDING);
	mvsw_pr_bridge_port_put(sw->bridge, br_port);

	/* Offload rif that was previosly disabled */
	if (prestera_rif_exists(sw, port->net_dev))
		prestera_rif_enable(sw, port->net_dev, true);

}

static bool
prestera_lag_master_check(struct prestera_switch *sw,
			  struct net_device *lag_dev,
			  struct netdev_lag_upper_info *upper_info,
			  struct netlink_ext_ack *ext_ack)
{
	u16 lag_id;

	if (prestera_lag_id_find(sw, lag_dev, &lag_id)) {
		NL_SET_ERR_MSG_MOD(ext_ack,
				   "Exceeded max supported LAG devices");
		return false;
	}
	if (upper_info->tx_type != NETDEV_LAG_TX_TYPE_HASH) {
		NL_SET_ERR_MSG_MOD(ext_ack, "Unsupported LAG Tx type");
		return false;
	}
	return true;
}

static void mvsw_pr_port_lag_clean(struct prestera_port *port,
				   struct net_device *lag_dev)
{
	struct net_device *br_dev = netdev_master_upper_dev_get(lag_dev);
	struct prestera_port_vlan *port_vlan, *tmp;
	struct net_device *upper_dev;
	struct list_head *iter;

	list_for_each_entry_safe(port_vlan, tmp, &port->vlans_list, list) {
		prestera_port_vlan_bridge_leave(port_vlan);
		prestera_port_vlan_destroy(port_vlan);
	}

	if (netif_is_bridge_port(lag_dev))
		mvsw_pr_port_bridge_leave(port, lag_dev, br_dev);

	netdev_for_each_upper_dev_rcu(lag_dev, upper_dev, iter) {
		if (!netif_is_bridge_port(upper_dev))
			continue;
		br_dev = netdev_master_upper_dev_get(upper_dev);
		mvsw_pr_port_bridge_leave(port, upper_dev, br_dev);
	}

	prestera_port_pvid_set(port, PRESTERA_DEFAULT_VID);
}

static int mvsw_pr_port_lag_join(struct prestera_port *port,
				 struct net_device *lag_dev)
{
	u16 lag_id;
	int err;

	err = prestera_lag_id_find(port->sw, lag_dev, &lag_id);
	if (err)
		return err;

	err = prestera_lag_member_add(port, lag_dev, lag_id);
		return err;

	/* TODO: Port should no be longer usable as a router interface */

	return 0;
}

static void mvsw_pr_port_lag_leave(struct prestera_port *port,
				   struct net_device *lag_dev)
{
	prestera_router_lag_member_leave(port, lag_dev);

	if (prestera_lag_member_del(port))
		return;

	mvsw_pr_port_lag_clean(port, lag_dev);
}

static int mvsw_pr_netdevice_port_upper_event(struct net_device *lower_dev,
					      struct net_device *dev,
					      unsigned long event, void *ptr)
{
	struct netdev_notifier_changeupper_info *info;
	struct prestera_port *port;
	struct netlink_ext_ack *extack;
	struct net_device *upper_dev;
	struct prestera_switch *sw;
	int err = 0;

	port = netdev_priv(dev);
	sw = port->sw;
	info = ptr;
	extack = netdev_notifier_info_to_extack(&info->info);

	switch (event) {
	case NETDEV_PRECHANGEUPPER:
		upper_dev = info->upper_dev;
		if (!netif_is_bridge_master(upper_dev) &&
		    !netif_is_lag_master(upper_dev) &&
		    !netif_is_macvlan(upper_dev)) {
			NL_SET_ERR_MSG_MOD(extack, "Unknown upper device type");
			return -EINVAL;
		}
		if (!info->linking)
			break;
		if (netdev_has_any_upper_dev(upper_dev) &&
		    (!netif_is_bridge_master(upper_dev) ||
		     !mvsw_pr_bridge_device_is_offloaded(sw, upper_dev))) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Enslaving a port to a device that already has an upper device is not supported");
			return -EINVAL;
		}
		if (netif_is_lag_master(upper_dev) &&
		    !prestera_lag_master_check(sw, upper_dev,
					      info->upper_info, extack))
			return -EINVAL;
		if (netif_is_lag_master(upper_dev) && vlan_uses_dev(dev)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Master device is a LAG master and port has a VLAN");
			return -EINVAL;
		}
		if (netif_is_lag_port(dev) && is_vlan_dev(upper_dev) &&
		    !netif_is_lag_master(vlan_dev_real_dev(upper_dev))) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Can not put a VLAN on a LAG port");
			return -EINVAL;
		}
		if (netif_is_macvlan(upper_dev) &&
		    !prestera_rif_exists(sw, lower_dev)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "macvlan is only supported on top of router interfaces");
			return -EOPNOTSUPP;
		}
		break;
	case NETDEV_CHANGEUPPER:
		upper_dev = info->upper_dev;
		if (netif_is_bridge_master(upper_dev)) {
			if (info->linking)
				err = mvsw_pr_port_bridge_join(port,
							       lower_dev,
							       upper_dev,
							       extack);
			else
				mvsw_pr_port_bridge_leave(port,
							  lower_dev,
							  upper_dev);
		} else if (netif_is_lag_master(upper_dev)) {
			if (info->linking)
				err = mvsw_pr_port_lag_join(port,
							    upper_dev);
			else
				mvsw_pr_port_lag_leave(port,
						       upper_dev);
		}
		break;
	}

	return err;
}

static int mvsw_pr_netdevice_port_lower_event(struct net_device *dev,
					      unsigned long event, void *ptr)
{
	struct netdev_notifier_changelowerstate_info *info = ptr;
	struct netdev_lag_lower_state_info *lower_state_info;
	struct prestera_port *port = netdev_priv(dev);
	bool enabled;

	if (event != NETDEV_CHANGELOWERSTATE)
		return 0;
	if (!netif_is_lag_port(dev))
		return 0;
	if (!prestera_port_is_lag_member(port))
		return 0;

	lower_state_info = info->lower_state_info;
	enabled = lower_state_info->tx_enabled;
	return prestera_lag_member_enable(port, enabled);
}

static int mvsw_pr_netdevice_port_event(struct net_device *lower_dev,
					struct net_device *port_dev,
					unsigned long event, void *ptr)
{
	switch (event) {
	case NETDEV_PRECHANGEUPPER:
	case NETDEV_CHANGEUPPER:
		return mvsw_pr_netdevice_port_upper_event(lower_dev, port_dev,
							  event, ptr);
	case NETDEV_CHANGELOWERSTATE:
		return mvsw_pr_netdevice_port_lower_event(port_dev,
							  event, ptr);
	}

	return 0;
}

static int mvsw_pr_netdevice_bridge_event(struct net_device *br_dev,
					  unsigned long event, void *ptr)
{
	struct prestera_switch *sw = prestera_switch_get(br_dev);
	struct netdev_notifier_changeupper_info *info = ptr;
	struct netlink_ext_ack *extack;
	struct net_device *upper_dev;

	if (!sw)
		return 0;

	extack = netdev_notifier_info_to_extack(&info->info);

	switch (event) {
	case NETDEV_PRECHANGEUPPER:
		upper_dev = info->upper_dev;
		if (!is_vlan_dev(upper_dev) && !netif_is_macvlan(upper_dev)) {
			NL_SET_ERR_MSG_MOD(extack, "Unknown upper device type");
			return -EOPNOTSUPP;
		}
		if (!info->linking)
			break;
		if (netif_is_macvlan(upper_dev) &&
		    !prestera_rif_exists(sw, br_dev)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "macvlan is only supported on top of router interfaces");
			return -EOPNOTSUPP;
		}
		break;
	case NETDEV_CHANGEUPPER:
		/* TODO:  */
		break;
	}

	return 0;
}

static int mvsw_pr_netdevice_macvlan_event(struct net_device *macvlan_dev,
					   unsigned long event, void *ptr)
{
	struct prestera_switch *sw = prestera_switch_get(macvlan_dev);
	struct netdev_notifier_changeupper_info *info = ptr;
	struct netlink_ext_ack *extack;

	if (!sw || event != NETDEV_PRECHANGEUPPER)
		return 0;

	extack = netdev_notifier_info_to_extack(&info->info);

	NL_SET_ERR_MSG_MOD(extack, "Unknown upper device type");

	return -EOPNOTSUPP;
}

static bool mvsw_pr_is_vrf_event(unsigned long event, void *ptr)
{
	struct netdev_notifier_changeupper_info *info = ptr;

	if (event != NETDEV_PRECHANGEUPPER && event != NETDEV_CHANGEUPPER)
		return false;

	return netif_is_l3_master(info->upper_dev);
}

static int mvsw_pr_netdevice_lag_event(struct net_device *lag_dev,
				       unsigned long event, void *ptr)
{
	struct net_device *dev;
	struct list_head *iter;
	int err;

	netdev_for_each_lower_dev(lag_dev, dev, iter) {
		if (prestera_netdev_check(dev)) {
			err = mvsw_pr_netdevice_port_event(lag_dev, dev, event,
							   ptr);
			if (err)
				return err;
		}
	}

	return 0;
}

static int mvsw_pr_netdevice_vlan_event(struct net_device *vlan_dev,
					unsigned long event, void *ptr)
{
	struct net_device *real_dev = vlan_dev_real_dev(vlan_dev);
	struct prestera_switch *sw = prestera_switch_get(real_dev);
	struct netdev_notifier_changeupper_info *info = ptr;
	struct netlink_ext_ack *extack;
	struct net_device *upper_dev;

	if (!sw)
		return 0;

	extack = netdev_notifier_info_to_extack(&info->info);

	switch (event) {
	case NETDEV_PRECHANGEUPPER:
		upper_dev = info->upper_dev;

		if (!info->linking)
			break;

		if (mvsw_pr_bridge_device_is_offloaded(sw, real_dev) &&
		    netif_is_bridge_master(upper_dev)) {
			NL_SET_ERR_MSG_MOD(extack,
					   "Enslaving offloaded bridge to a bridge is not supported");
			return -EOPNOTSUPP;
		}
		break;
	case NETDEV_CHANGEUPPER:
		/* empty */
		break;
	}

	return 0;
}

static int mvsw_pr_netdevice_event(struct notifier_block *nb,
				   unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct prestera_switch *sw;
	int err = 0;

	sw = container_of(nb, struct prestera_switch, netdevice_nb);

	if (event == NETDEV_PRE_CHANGEADDR ||
	    event == NETDEV_CHANGEADDR)
		err = prestera_netdevice_router_port_event(dev, event, ptr);
	else if (mvsw_pr_is_vrf_event(event, ptr))
		err = prestera_netdevice_vrf_event(dev, event, ptr);
	else if (prestera_netdev_check(dev))
		err = mvsw_pr_netdevice_port_event(dev, dev, event, ptr);
	else if (netif_is_bridge_master(dev))
		err = mvsw_pr_netdevice_bridge_event(dev, event, ptr);
	else if (netif_is_lag_master(dev))
		err = mvsw_pr_netdevice_lag_event(dev, event, ptr);
	else if (is_vlan_dev(dev))
		err = mvsw_pr_netdevice_vlan_event(dev, event, ptr);
	else if (netif_is_macvlan(dev))
		err = mvsw_pr_netdevice_macvlan_event(dev, event, ptr);

	return notifier_from_errno(err);
}

static int mvsw_pr_fdb_init(struct prestera_switch *sw)
{
	int err;

	err = prestera_switch_ageing_set(sw, PRESTERA_DEFAULT_AGEING_TIME);
	if (err)
		return err;

	return 0;
}

static int prestera_switchdev_init(struct prestera_switch *sw)
{
	int err = 0;
	struct prestera_switchdev *swdev;
	struct prestera_bridge *bridge;

	if (sw->switchdev)
		return -EPERM;

	bridge = kzalloc(sizeof(*sw->bridge), GFP_KERNEL);
	if (!bridge)
		return -ENOMEM;

	swdev = kzalloc(sizeof(*sw->switchdev), GFP_KERNEL);
	if (!swdev) {
		kfree(bridge);
		return -ENOMEM;
	}

	sw->bridge = bridge;
	bridge->sw = sw;
	sw->switchdev = swdev;
	swdev->sw = sw;

	INIT_LIST_HEAD(&sw->bridge->bridge_list);

	mvsw_owq = alloc_ordered_workqueue("%s_ordered", 0, "prestera_sw");
	if (!mvsw_owq) {
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

	mvsw_pr_fdb_init(sw);

	return 0;

err_register_block_switchdev_notifier:
	unregister_switchdev_notifier(&swdev->swdev_n);
err_register_switchdev_notifier:
	destroy_workqueue(mvsw_owq);
err_alloc_workqueue:
	kfree(swdev);
	kfree(bridge);
	return err;
}

static void prestera_switchdev_fini(struct prestera_switch *sw)
{
	if (!sw->switchdev)
		return;

	unregister_switchdev_notifier(&sw->switchdev->swdev_n);
	unregister_switchdev_blocking_notifier
	    (&sw->switchdev->swdev_blocking_n);
	flush_workqueue(mvsw_owq);
	destroy_workqueue(mvsw_owq);
	kfree(sw->switchdev);
	sw->switchdev = NULL;
	kfree(sw->bridge);
}

static int mvsw_pr_netdev_init(struct prestera_switch *sw)
{
	int err = 0;

	if (sw->netdevice_nb.notifier_call)
		return -EPERM;

	sw->netdevice_nb.notifier_call = mvsw_pr_netdevice_event;
	err = register_netdevice_notifier(&sw->netdevice_nb);
	return err;
}

static void mvsw_pr_netdev_fini(struct prestera_switch *sw)
{
	if (sw->netdevice_nb.notifier_call)
		unregister_netdevice_notifier(&sw->netdevice_nb);
}

int prestera_switchdev_register(struct prestera_switch *sw)
{
	int err;

	err = prestera_switchdev_init(sw);
	if (err)
		return err;

	err = prestera_router_init(sw);

	if (err) {
		pr_err("Failed to initialize fib notifier\n");
		goto err_fib_notifier;
	}

	err = mvsw_pr_netdev_init(sw);
	if (err)
		goto err_netdevice_notifier;

	return 0;

err_netdevice_notifier:
	prestera_router_fini(sw);
err_fib_notifier:
	prestera_switchdev_fini(sw);
	return err;
}

void prestera_switchdev_unregister(struct prestera_switch *sw)
{
	mvsw_pr_netdev_fini(sw);
	prestera_router_fini(sw);
	prestera_switchdev_fini(sw);
}
