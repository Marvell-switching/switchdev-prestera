/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2020 Marvell International Ltd. All rights reserved. */

#ifndef _PRESTERA_DEVLINK_H_
#define _PRESTERA_DEVLINK_H_

#include "prestera.h"

struct mvsw_pr_switch *prestera_devlink_alloc(void);
void prestera_devlink_free(struct mvsw_pr_switch *sw);

int prestera_devlink_register(struct mvsw_pr_switch *sw);
void prestera_devlink_unregister(struct mvsw_pr_switch *sw);

int prestera_devlink_port_register(struct mvsw_pr_port *port);
void prestera_devlink_port_unregister(struct mvsw_pr_port *port);

void prestera_devlink_port_set(struct mvsw_pr_port *port);
void prestera_devlink_port_clear(struct mvsw_pr_port *port);

struct devlink_port *prestera_devlink_get_port(struct net_device *dev);

#endif /* _PRESTERA_DEVLINK_H_ */
