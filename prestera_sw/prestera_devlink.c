// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2020 Marvell International Ltd. All rights reserved */

#include <net/devlink.h>

#include "prestera_devlink.h"

static int prestera_dl_info_get(struct devlink *dl,
				struct devlink_info_req *req,
				struct netlink_ext_ack *extack)
{
	struct mvsw_pr_switch *sw = devlink_priv(dl);
	char buf[16];
	int err;

	err = devlink_info_driver_name_put(req, PRESTERA_DRV_NAME);
	if (err)
		return err;

	snprintf(buf, sizeof(buf), "%d.%d.%d",
		 sw->dev->fw_rev.maj,
		 sw->dev->fw_rev.min,
		 sw->dev->fw_rev.sub);

	return devlink_info_version_running_put(req,
					       DEVLINK_INFO_VERSION_GENERIC_FW,
					       buf);
}

static const struct devlink_ops prestera_dl_ops = {
	.info_get = prestera_dl_info_get,
};

struct mvsw_pr_switch *prestera_devlink_alloc(void)
{
	struct devlink *dl;

	dl = devlink_alloc(&prestera_dl_ops, sizeof(struct mvsw_pr_switch));

	return devlink_priv(dl);
}

void prestera_devlink_free(struct mvsw_pr_switch *sw)
{
	struct devlink *dl = priv_to_devlink(sw);

	devlink_free(dl);
}

int prestera_devlink_register(struct mvsw_pr_switch *sw)
{
	struct devlink *dl = priv_to_devlink(sw);
	int err;

	err = devlink_register(dl, sw->dev->dev);
	if (err)
		dev_err(sw->dev->dev, "devlink_register failed: %d\n", err);

	return err;
}

void prestera_devlink_unregister(struct mvsw_pr_switch *sw)
{
	struct devlink *dl = priv_to_devlink(sw);

	devlink_unregister(dl);
}

int prestera_devlink_port_register(struct mvsw_pr_port *port)
{
	struct mvsw_pr_switch *sw = port->sw;
	struct devlink *dl = priv_to_devlink(sw);
	int err;

	devlink_port_attrs_set(&port->dl_port, DEVLINK_PORT_FLAVOUR_PHYSICAL,
			       port->fp_id, false, 0, &port->sw->id,
			       sizeof(port->sw->id));

	err = devlink_port_register(dl, &port->dl_port, port->fp_id);
	if (err) {
		dev_err(sw->dev->dev, "devlink_port_register failed\n");
		return err;
	}

	return 0;
}

void prestera_devlink_port_unregister(struct mvsw_pr_port *port)
{
	devlink_port_unregister(&port->dl_port);
}

void prestera_devlink_port_set(struct mvsw_pr_port *port)
{
	devlink_port_type_eth_set(&port->dl_port, port->net_dev);
}

void prestera_devlink_port_clear(struct mvsw_pr_port *port)
{
	devlink_port_type_clear(&port->dl_port);
}

struct devlink_port *prestera_devlink_get_port(struct net_device *dev)
{
	struct mvsw_pr_port *port = netdev_priv(dev);

	return &port->dl_port;
}
