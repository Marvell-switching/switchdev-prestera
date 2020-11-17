/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 *
 * Copyright (c) 2019-2020 Marvell International Ltd. All rights reserved.
 *
 */

#ifndef _MVSW_PRESTERA_RXTX_H_
#define _MVSW_PRESTERA_RXTX_H_

#include <linux/netdevice.h>

#define MVSW_PR_RXTX_CPU_CODE_MAX_NUM	256

struct mvsw_pr_switch;

struct mvsw_pr_rxtx_info {
	u32 port_id;
	u32 dev_id;
};

int mvsw_pr_rxtx_init(void);
void mvsw_pr_rxtx_fini(void);

int mvsw_pr_rxtx_switch_init(struct mvsw_pr_switch *sw);
void mvsw_pr_rxtx_switch_fini(struct mvsw_pr_switch *sw);

netdev_tx_t mvsw_pr_rxtx_xmit(struct sk_buff *skb,
			      struct mvsw_pr_rxtx_info *info);

u64 mvsw_pr_rxtx_get_cpu_code_stats(u8 cpu_code);

#endif /* _MVSW_PRESTERA_RXTX_H_ */
