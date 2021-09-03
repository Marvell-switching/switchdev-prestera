/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved. */

#ifndef _MVSW_PRESTERA_STORM_CONTROL_H_
#define _MVSW_PRESTERA_STORM_CONTROL_H_

#include "prestera.h"

int prestera_storm_control_init(struct prestera_switch *sw);
void prestera_storm_control_fini(struct prestera_switch *sw);

#endif /* _MVSW_PRESTERA_STORM_CONTROL_H_ */
