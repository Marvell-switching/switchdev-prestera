/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2022 Marvell International Ltd. All rights reserved. */

#ifndef _PRESTERA_DCB_H_
#define _PRESTERA_DCB_H_

#include <linux/types.h>

struct prestera_port;

int prestera_port_dcb_init(struct prestera_port *port);
void prestera_port_dcb_fini(struct prestera_port *port);

#endif /* _PRESTERA_DCB_H_ */
