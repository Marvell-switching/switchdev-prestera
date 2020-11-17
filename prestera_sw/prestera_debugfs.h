/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 *
 * Copyright (c) 2020 Marvell International Ltd. All rights reserved.
 *
 */
#ifndef _MVSW_PRESTERA_DEBUGFS_H_
#define _MVSW_PRESTERA_DEBUGFS_H_

struct mvsw_pr_switch;

int mvsw_pr_debugfs_init(struct mvsw_pr_switch *sw);
void mvsw_pr_debugfs_fini(struct mvsw_pr_switch *sw);

#endif /* _MVSW_PRESTERA_DEBUGFS_H_ */
