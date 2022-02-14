/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2020 Marvell International Ltd. All rights reserved. */

#ifndef _PRESTERA_SWITCHDEV_H_
#define _PRESTERA_SWITCHDEV_H_

int prestera_switchdev_init(struct prestera_switch *sw);
void prestera_switchdev_fini(struct prestera_switch *sw);

int prestera_port_bridge_join(struct prestera_port *port,
			      struct net_device *brport_dev,
			      struct net_device *br_dev,
			      struct netlink_ext_ack *extack);

void prestera_port_bridge_leave(struct prestera_port *port,
				struct net_device *brport_dev,
				struct net_device *br_dev);

bool prestera_bridge_is_offloaded(const struct prestera_switch *sw,
				  const struct net_device *br_dev);

int prestera_bridge_port_down(struct prestera_port *port);

#endif /* _PRESTERA_SWITCHDEV_H_ */
