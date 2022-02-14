/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved. */

#ifndef _MVSW_PRESTERA_RXTX_H_
#define _MVSW_PRESTERA_RXTX_H_

#include <linux/netdevice.h>

#define MVSW_PR_RXTX_CPU_CODE_MAX_NUM	256

struct prestera_switch;

int prestera_rxtx_switch_init(struct prestera_switch *sw);
void prestera_rxtx_switch_fini(struct prestera_switch *sw);

netdev_tx_t prestera_rxtx_xmit(struct sk_buff *skb, struct prestera_port *port);

u64 mvsw_pr_rxtx_get_cpu_code_stats(u8 cpu_code);

#endif /* _MVSW_PRESTERA_RXTX_H_ */
