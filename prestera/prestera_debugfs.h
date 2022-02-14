/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved. */

#ifndef _MVSW_PRESTERA_DEBUGFS_H_
#define _MVSW_PRESTERA_DEBUGFS_H_

struct prestera_switch;

int prestera_debugfs_init(struct prestera_switch *sw);
void prestera_debugfs_fini(struct prestera_switch *sw);

#endif /* _MVSW_PRESTERA_DEBUGFS_H_ */
