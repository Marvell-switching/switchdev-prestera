/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved. */

#ifndef __PRESTERA_ETHTOOL_H_
#define __PRESTERA_ETHTOOL_H_

#include <linux/ethtool.h>

#include "prestera.h"

extern const struct ethtool_ops prestera_ethtool_ops;

int prestera_port_link_mode_set(struct prestera_port *port,
				u32 speed, u8 duplex, u8 type);

#endif /* _PRESTERA_ETHTOOL_H_ */
