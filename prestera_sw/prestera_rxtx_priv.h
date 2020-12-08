/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 *
 * Copyright (c) 2019-2020 Marvell International Ltd. All rights reserved.
 *
 */
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_device.h>

#include "prestera_rxtx.h"

struct mvsw_pr_rxtx;

struct mvsw_pr_rxtx_ops {
	int (*rxtx_init)(struct mvsw_pr_rxtx *rxtx);
	int (*rxtx_fini)(struct mvsw_pr_rxtx *rxtx);

	int (*rxtx_switch_init)(struct mvsw_pr_rxtx *rxtx,
				struct mvsw_pr_switch *sw);
	void (*rxtx_switch_fini)(struct mvsw_pr_rxtx *rxtx,
				 struct mvsw_pr_switch *sw);

	netdev_tx_t (*rxtx_xmit)(struct mvsw_pr_rxtx *rxtx,
				 struct sk_buff *skb);
};

struct mvsw_pr_rxtx {
	struct platform_device *pdev;
	struct device *dev;

	const struct mvsw_pr_rxtx_ops *ops;
	void *priv;
};

int mvsw_pr_rxtx_recv_skb(struct mvsw_pr_rxtx *rxtx, struct sk_buff *skb);

int mvsw_pr_rxtx_eth_init(struct mvsw_pr_rxtx *rxtx);
int mvsw_pr_rxtx_eth_fini(struct mvsw_pr_rxtx *rxtx);
netdev_tx_t mvsw_pr_rxtx_eth_xmit(struct mvsw_pr_rxtx *rxtx,
				  struct sk_buff *skb);

int mvsw_pr_rxtx_mvpp_init(struct mvsw_pr_rxtx *rxtx);
int mvsw_pr_rxtx_mvpp_fini(struct mvsw_pr_rxtx *rxtx);
int mvsw_pr_rxtx_eth_switch_init(struct mvsw_pr_rxtx *rxtx,
				 struct mvsw_pr_switch *sw);
void mvsw_pr_rxtx_eth_switch_fini(struct mvsw_pr_rxtx *rxtx,
				  struct mvsw_pr_switch *sw);
netdev_tx_t mvsw_pr_rxtx_mvpp_xmit(struct mvsw_pr_rxtx *rxtx,
				   struct sk_buff *skb);

int mvsw_pr_rxtx_sdma_init(struct mvsw_pr_rxtx *rxtx);
int mvsw_pr_rxtx_sdma_fini(struct mvsw_pr_rxtx *rxtx);
int mvsw_pr_rxtx_sdma_switch_init(struct mvsw_pr_rxtx *rxtx,
				  struct mvsw_pr_switch *sw);
void mvsw_pr_rxtx_sdma_switch_fini(struct mvsw_pr_rxtx *rxtx,
				   struct mvsw_pr_switch *sw);
netdev_tx_t mvsw_pr_rxtx_sdma_xmit(struct mvsw_pr_rxtx *rxtx,
				   struct sk_buff *skb);
