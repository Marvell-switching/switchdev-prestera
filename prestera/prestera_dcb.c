// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2021 Marvell International Ltd. All rights reserved */

#include <linux/netdevice.h>
#include <net/dcbnl.h>

#include "prestera.h"
#include "prestera_hw.h"
#include "prestera_dcb.h"
#include "prestera_acl.h"

#define PRESTERA_ACL_QOS_REMARK_PRIO (0)
#define PRESTERA_QOS_SP_TO_PROFILE_INDEX(__sp) ((__sp) | 0b1000)

struct prestera_qos {
	struct prestera_acl_rule_entry *rule[IEEE_8021QAZ_MAX_TCS];
	bool bind;
	u32 trust_mode;
	u32 vtcam_id;
	u8 uid;
};

struct prestera_acl_prio_dscp_map {
	u32 dscp[IEEE_8021QAZ_MAX_TCS];
};

static int prestera_qos_remark_port_bind(struct prestera_port *port)
{
	struct prestera_acl *acl = port->sw->acl;
	struct prestera_acl_iface iface;
	struct prestera_acl_match match;
	u32 vtcam_id;
	int err = 0;
	u32 uid = 0;
	u32 pcl_id;

	err = idr_alloc_u32(&acl->uid, NULL, &uid, U8_MAX, GFP_KERNEL);
	if (err)
		goto err_uid;

	memset(&match, 0, sizeof(match));
	rule_match_set_u16(match.mask, PCL_ID, PRESTERA_ACL_KEYMASK_PCL_ID);
	rule_match_set_u8(match.mask, QOS_PROFILE, 0xff);

	err = prestera_acl_vtcam_id_get(acl, 0, PRESTERA_HW_VTCAM_DIR_EGRESS,
					match.mask, &vtcam_id);
	if (err)
		goto err_vtcam;

	pcl_id = PRESTERA_ACL_PCL_ID_MAKE((u8)uid, 0);
	iface.type = PRESTERA_ACL_IFACE_TYPE_PORT;
	iface.port = port;

	err = prestera_hw_vtcam_iface_bind(port->sw, &iface,
					   vtcam_id, pcl_id);
	if (err)
		goto err_bind;

	port->qos->uid = uid;
	port->qos->vtcam_id = vtcam_id;
	port->qos->bind = true;

	return 0;
err_bind:
	prestera_acl_vtcam_id_put(acl, vtcam_id);
err_vtcam:
	idr_remove(&acl->uid, uid);
err_uid:
	return err;
}

static void prestera_qos_remark_port_unbind(struct prestera_port *port)
{
	struct prestera_acl *acl = port->sw->acl;
	struct prestera_acl_iface iface = {
		.type = PRESTERA_ACL_IFACE_TYPE_PORT,
		.port = port
	};

	if (!port->qos->bind)
		return;

	WARN_ON(prestera_hw_vtcam_iface_unbind(port->sw, &iface,
					       port->qos->vtcam_id));
	WARN_ON(prestera_acl_vtcam_id_put(acl, port->qos->vtcam_id));
	idr_remove(&acl->uid, port->qos->uid);

	port->qos->bind = false;
}

static void prestera_qos_remark_rules_del(struct prestera_port *port)
{
	int i;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (!port->qos->rule[i])
			continue;

		prestera_acl_rule_entry_destroy(port->sw->acl,
						port->qos->rule[i]);
		port->qos->rule[i] = NULL;
	}
}

static int prestera_qos_remark_rules_add(struct prestera_port *port,
					 struct prestera_acl_prio_dscp_map *map)
{
	struct prestera_acl_rule_entry_key re_key;
	struct prestera_acl_rule_entry_arg re_arg;
	struct prestera_acl_rule_entry *re;
	u32 pcl_id;
	int err;
	int i;

	memset(&re_key, 0, sizeof(re_key));
	memset(&re_arg, 0, sizeof(re_arg));

	pcl_id = PRESTERA_ACL_PCL_ID_MAKE(port->qos->uid, 0);
	re_key.prio = PRESTERA_ACL_QOS_REMARK_PRIO;
	re_arg.remark.valid = 1;
	re_arg.vtcam_id = port->qos->vtcam_id;

	rule_match_set_u16(re_key.match.key, PCL_ID, pcl_id);
	rule_match_set_u16(re_key.match.mask, PCL_ID,
			   PRESTERA_ACL_KEYMASK_PCL_ID);
	rule_match_set_u8(re_key.match.mask, QOS_PROFILE, 0xff);

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		rule_match_set_u8(re_key.match.key, QOS_PROFILE,
				  PRESTERA_QOS_SP_TO_PROFILE_INDEX(i));
		re_arg.remark.i.dscp = map->dscp[i];

		re = prestera_acl_rule_entry_create(port->sw->acl, &re_key,
						    &re_arg);
		err = !re ? -EINVAL : 0;
		if (err)
			goto err_rule_add;

		port->qos->rule[i] = re;
	}

	return 0;

err_rule_add:
	prestera_qos_remark_rules_del(port);
	return err;
}

static int prestera_dcb_app_validate(struct net_device *dev,
				     struct dcb_app *app)
{
	int prio;

	if (app->priority >= IEEE_8021QAZ_MAX_TCS) {
		netdev_err(dev, "APP entry with priority value %u is invalid\n",
			   app->priority);
		return -EINVAL;
	}

	switch (app->selector) {
	case IEEE_8021QAZ_APP_SEL_DSCP:
		if (app->protocol >= 64) {
			netdev_err(dev, "DSCP APP entry with protocol value %u is invalid\n",
				   app->protocol);
			return -EINVAL;
		}

		/* Warn about any DSCP APP entries with the same PID. */
		prio = fls(dcb_ieee_getapp_mask(dev, app));
		if (prio--) {
			if (prio < app->priority)
				netdev_warn(dev, "Choosing priority %d for DSCP %d in favor of previously-active value of %d\n",
					    app->priority, app->protocol, prio);
			else if (prio > app->priority)
				netdev_warn(dev, "Ignoring new priority %d for DSCP %d in favor of current value of %d\n",
					    app->priority, app->protocol, prio);
		}
		break;

	case IEEE_8021QAZ_APP_SEL_ETHERTYPE:
		if (app->protocol) {
			netdev_err(dev, "EtherType APP entries with protocol value != 0 not supported\n");
			return -EINVAL;
		}
		break;

	default:
		netdev_err(dev, "APP entries with selector %u not supported\n",
			   app->selector);
		return -EINVAL;
	}

	return 0;
}

static u8 prestera_dcb_port_default_prio(struct prestera_port *port)
{
	u8 prio_mask;

	prio_mask = dcb_ieee_getapp_default_prio_mask(port->net_dev);
	if (prio_mask)
		/* Take the highest configured priority. */
		return fls(prio_mask) - 1;

	return 0;
}

static void prestera_dcb_port_dscp_prio_map(struct prestera_port *port,
					    u8 default_prio,
					    struct dcb_ieee_app_dscp_map *map)
{
	int i;

	dcb_ieee_getapp_dscp_prio_mask_map(port->net_dev, map);
	for (i = 0; i < ARRAY_SIZE(map->map); ++i) {
		if (map->map[i])
			map->map[i] = fls(map->map[i]) - 1;
		else
			map->map[i] = default_prio;
	}
}

static bool prestera_dcb_port_prio_dscp_map(struct prestera_port *port,
					    struct dcb_ieee_app_prio_map *map)
{
	bool have_dscp = false;
	int i;

	dcb_ieee_getapp_prio_dscp_mask_map(port->net_dev, map);
	for (i = 0; i < ARRAY_SIZE(map->map); ++i) {
		if (map->map[i]) {
			map->map[i] = fls64(map->map[i]) - 1;
			have_dscp = true;
		}
	}

	return have_dscp;
}

static int prestera_port_trust_mode_set(struct prestera_port *port, u8 mode)
{
	int err;

	err = prestera_hw_port_qos_trust_mode_set(port, mode);
	if (err)
		return err;

	if (mode == PRESTERA_HW_QOS_TRUST_MODE_L3) {
		err = prestera_qos_remark_port_bind(port);
		if (err)
			goto err_trust_mode;
	} else {
		prestera_qos_remark_rules_del(port);
		prestera_qos_remark_port_unbind(port);
	}

	port->qos->trust_mode = mode;
	return 0;

err_trust_mode:
	prestera_hw_port_qos_trust_mode_set(port, port->qos->trust_mode);
	return err;
}

static int prestera_dcb_port_app_update(struct prestera_port *port,
					struct dcb_app *app)
{
	struct prestera_acl_prio_dscp_map remark_map;
	struct dcb_ieee_app_dscp_map dscp_map;
	struct dcb_ieee_app_prio_map prio_map;
	u8 default_prio;
	bool have_dscp;
	int err = 0;
	u8 mode;
	int i;

	have_dscp = prestera_dcb_port_prio_dscp_map(port, &prio_map);

	mode = have_dscp ? PRESTERA_HW_QOS_TRUST_MODE_L3 :
			   PRESTERA_HW_QOS_TRUST_MODE_L2;

	if (port->qos->trust_mode != mode) {
		err = prestera_port_trust_mode_set(port, mode);
		if (err) {
			netdev_err(port->net_dev,
				   "Failed to configure trust mode\n");
			return err;
		}
	}

	default_prio = prestera_dcb_port_default_prio(port);
	prestera_dcb_port_dscp_prio_map(port, default_prio, &dscp_map);

	err = prestera_hw_port_qos_default_prio_set(port, default_prio);
	if (err) {
		netdev_err(port->net_dev,
			   "Failed to configure default priority\n");
		return err;
	}

	if (mode != PRESTERA_HW_QOS_TRUST_MODE_L3)
		return 0;

	err = prestera_hw_port_qos_mapping_update(port, &dscp_map);
	if (err) {
		netdev_err(port->net_dev, "Failed to configure priority\n");
		return err;
	}

	for (i = 0; i < ARRAY_SIZE(remark_map.dscp); i++)
		remark_map.dscp[i] = (u32)prio_map.map[i];

	prestera_qos_remark_rules_del(port);
	err = prestera_qos_remark_rules_add(port, &remark_map);
	if (err) {
		netdev_err(port->net_dev, "Failed to create remarking rules\n");
		return err;
	}

	return err;
}

static int prestera_dcb_port_app_flush(struct prestera_port *port,
				       struct dcb_app *app)
{
	int err;

	err = prestera_hw_port_qos_default_prio_set(port, 0);
	if (err) {
		netdev_err(port->net_dev,
			   "Failed to reset default priority\n");
		return err;
	}

	err = prestera_port_trust_mode_set(port, PRESTERA_HW_QOS_TRUST_MODE_L2);
	if (err) {
		netdev_err(port->net_dev,
			   "Failed to reset trust mode\n");
		return err;
	}

	return 0;
}

static int prestera_dcb_ieee_setapp(struct net_device *dev,
				    struct dcb_app *app)
{
	struct prestera_port *port = netdev_priv(dev);
	int err;

	err = prestera_dcb_app_validate(dev, app);
	if (err)
		return err;

	err = dcb_ieee_setapp(dev, app);
	if (err)
		return err;

	err = prestera_dcb_port_app_update(port, app);
	if (err)
		dcb_ieee_delapp(dev, app);

	return err;
}

static int prestera_dcb_ieee_delapp(struct net_device *dev,
				    struct dcb_app *app)
{
	struct prestera_port *port = netdev_priv(dev);
	int err;

	err = dcb_ieee_delapp(dev, app);
	if (err)
		return err;

	err = prestera_dcb_port_app_flush(port, app);
	if (err)
		return err;

	return 0;
}

static const struct dcbnl_rtnl_ops prestera_dcbnl_ops = {
	.ieee_setapp		= prestera_dcb_ieee_setapp,
	.ieee_delapp		= prestera_dcb_ieee_delapp,
};

int prestera_port_dcb_init(struct prestera_port *port)
{
	port->qos = kzalloc(sizeof(*port->qos), GFP_KERNEL);
	if (!port->qos)
		return -ENOMEM;

	port->net_dev->dcbnl_ops = &prestera_dcbnl_ops;
	port->qos->trust_mode = PRESTERA_HW_QOS_TRUST_MODE_L2;

	return 0;
}

void prestera_port_dcb_fini(struct prestera_port *port)
{
	prestera_qos_remark_rules_del(port);
	prestera_qos_remark_port_unbind(port);
	kfree(port->qos);

	port->net_dev->dcbnl_ops = NULL;
}
