/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 *
 * Copyright (c) 2019-2020 Marvell International Ltd. All rights reserved.
 *
 */

#ifndef _MVSW_PRESTERA_FW_LOG_H_
#define _MVSW_PRESTERA_FW_LOG_H_

#include "prestera.h"

int  mvsw_pr_fw_log_init(struct mvsw_pr_switch *sw);
void mvsw_pr_fw_log_fini(struct mvsw_pr_switch *sw);

#endif /* _MVSW_PRESTERA_FW_LOG_H_ */
