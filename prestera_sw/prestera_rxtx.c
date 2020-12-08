// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/*
 * Copyright (c) 2019-2020 Marvell International Ltd. All rights reserved.
 *
 */
#include "prestera.h"
#include "prestera_rxtx_priv.h"
#include "prestera_dsa.h"

#include <linux/if_vlan.h>
#include <net/ip.h>

#define MVSW_DSA_TAG_ARP_BROADCAST 5
#define MVSW_DSA_TAG_IPV4_BROADCAST 19
#define MVSW_DSA_TAG_IPV4_IPV6_LINK_LOCAL_MC_1 29
#define MVSW_DSA_TAG_IPV4_IPV6_LINK_LOCAL_MC_2 30
#define MVSW_DSA_TAG_UDP_BROADCAST 33
#define MVSW_DSA_TAG_ARP_BROADCAST_TO_ME 179

struct mvsw_pr_rxtx;

enum mvsw_pr_rxtx_type {
	MVSW_PR_RXTX_MVPP,
	MVSW_PR_RXTX_ETH,
	MVSW_PR_RXTX_SDMA,
};

static struct mvsw_pr_rxtx *rxtx_registered;

static u64 *cpu_code_stats;

netdev_tx_t mvsw_pr_rxtx_xmit(struct sk_buff *skb,
			      struct mvsw_pr_rxtx_info *info)
{
	struct mvsw_pr_dsa dsa;
	struct mvsw_pr_dsa_from_cpu *from_cpu;
	struct net_device *dev = skb->dev;
	struct mvsw_pr_port *port = netdev_priv(dev);
	size_t dsa_resize_len = MVSW_PR_DSA_HLEN;

	if (!rxtx_registered)
		return NET_XMIT_DROP;

	/* common DSA tag fill-up */
	memset(&dsa, 0, sizeof(dsa));
	dsa.dsa_cmd = MVSW_NET_DSA_CMD_FROM_CPU_E;

	from_cpu = &dsa.dsa_info.from_cpu;
	from_cpu->egr_filter_en = false;
	from_cpu->egr_filter_registered = false;
	from_cpu->dst_eport = port->hw_id;

	from_cpu->dst_iface.dev_port.port_num = port->hw_id;
	from_cpu->dst_iface.dev_port.hw_dev_num = port->dev_id;
	from_cpu->dst_iface.type = MVSW_IF_PORT_E;

	/* epmorary removing due to issue with vlan sub interface
	 * on 1.Q bridge
	 */
	/* If (skb->protocol == htons(ETH_P_8021Q)) { */
		/* 802.1q packet tag size is 4 bytes, so DSA len would
		 * need only allocation of MVSW_PR_DSA_HLEN - size of
		 * 802.1q tag
		 */
		/*dsa.common_params.vpt = skb_vlan_tag_get_prio(skb);
		 * dsa.common_params.cfi_bit = skb_vlan_tag_get_cfi(skb);
		 * dsa.common_params.vid = skb_vlan_tag_get_id(skb);
		 * dsa_resize_len -= VLAN_HLEN;
		 */
	/* } */


	if (skb_cow_head(skb, dsa_resize_len) < 0)
		return NET_XMIT_DROP;

	/* expects skb->data at mac header */
	skb_push(skb, dsa_resize_len);
	memmove(skb->data, skb->data + dsa_resize_len, 2 * ETH_ALEN);

	if (mvsw_pr_dsa_build(&dsa, skb->data + 2 * ETH_ALEN) != 0)
		return NET_XMIT_DROP;

	return rxtx_registered->ops->rxtx_xmit(rxtx_registered, skb);
}

int mvsw_pr_rxtx_recv_skb(struct mvsw_pr_rxtx *rxtx, struct sk_buff *skb)
{
	const struct mvsw_pr_port *port;
	struct mvsw_pr_dsa dsa;
	u32 hw_port, hw_id;
	int err;

	skb_pull(skb, ETH_HLEN);

	/* parse/process DSA tag
	 * ethertype field is part of the dsa header
	 */
	err = mvsw_pr_dsa_parse(skb->data - ETH_TLEN, &dsa);
	if (err)
		return err;

	/* get switch port */
	hw_port = dsa.dsa_info.to_cpu.iface.port_num;
	hw_id = dsa.dsa_info.to_cpu.hw_dev_num;
	port = mvsw_pr_port_find(hw_id, hw_port);
	if (unlikely(!port)) {
		pr_warn_ratelimited("prestera: received pkt for non-existent port(%u, %u)\n",
				    hw_id, hw_port);
		return -EEXIST;
	}

	if (unlikely(!pskb_may_pull(skb, MVSW_PR_DSA_HLEN)))
		return -EINVAL;

	/* remove DSA tag and update checksum */
	skb_pull_rcsum(skb, MVSW_PR_DSA_HLEN);

	memmove(skb->data - ETH_HLEN, skb->data - ETH_HLEN - MVSW_PR_DSA_HLEN,
		ETH_ALEN * 2);

	skb_push(skb, ETH_HLEN);

	skb->protocol = eth_type_trans(skb, port->net_dev);

	if (dsa.dsa_info.to_cpu.is_tagged) {
		u16 tci = dsa.common_params.vid & VLAN_VID_MASK;

		tci |= dsa.common_params.vpt << VLAN_PRIO_SHIFT;
		if (dsa.common_params.cfi_bit)
			tci |= VLAN_CFI_MASK;

		__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), tci);
	}

	switch (dsa.dsa_info.to_cpu.cpu_code) {
	case MVSW_DSA_TAG_ARP_BROADCAST:
	case MVSW_DSA_TAG_IPV4_BROADCAST:
	case MVSW_DSA_TAG_IPV4_IPV6_LINK_LOCAL_MC_1:
	case MVSW_DSA_TAG_IPV4_IPV6_LINK_LOCAL_MC_2:
	case MVSW_DSA_TAG_UDP_BROADCAST:
	case MVSW_DSA_TAG_ARP_BROADCAST_TO_ME:
		skb->offload_fwd_mark = 1;
	}
	++cpu_code_stats[dsa.dsa_info.to_cpu.cpu_code];

	return 0;
}

static struct mvsw_pr_rxtx_ops rxtx_driver_ops[] = {
	[MVSW_PR_RXTX_SDMA] = {
		.rxtx_init = mvsw_pr_rxtx_sdma_init,
		.rxtx_fini = mvsw_pr_rxtx_sdma_fini,
		.rxtx_switch_init = mvsw_pr_rxtx_sdma_switch_init,
		.rxtx_switch_fini = mvsw_pr_rxtx_sdma_switch_fini,
		.rxtx_xmit = mvsw_pr_rxtx_sdma_xmit,
	},
};

int mvsw_pr_rxtx_init(void)
{
	cpu_code_stats = kzalloc(sizeof(u64) * MVSW_PR_RXTX_CPU_CODE_MAX_NUM,
				 GFP_KERNEL);
	if (!cpu_code_stats)
		return -ENOMEM;

	rxtx_registered = kzalloc(sizeof(*rxtx_registered), GFP_KERNEL);
	if (!rxtx_registered) {
		kfree(cpu_code_stats);
		return -ENOMEM;
	}

	rxtx_registered->ops = &rxtx_driver_ops[MVSW_PR_RXTX_SDMA];

	if (rxtx_registered->ops->rxtx_init)
		return rxtx_registered->ops->rxtx_init(rxtx_registered);

	return 0;
}

void mvsw_pr_rxtx_fini(void)
{
	struct mvsw_pr_rxtx *rxtx = rxtx_registered;

	if (rxtx->ops->rxtx_fini)
		rxtx->ops->rxtx_fini(rxtx);

	kfree(rxtx_registered);
	rxtx_registered = NULL;
	kfree(cpu_code_stats);
}

int mvsw_pr_rxtx_switch_init(struct mvsw_pr_switch *sw)
{
	int err;

	if (!rxtx_registered) {
		pr_info("No RxTx driver registered");
		return 0;
	}

	if (!rxtx_registered->ops->rxtx_switch_init)
		return 0;

	err = rxtx_registered->ops->rxtx_switch_init(rxtx_registered, sw);
	if (err)
		return err;

	return 0;
}

void mvsw_pr_rxtx_switch_fini(struct mvsw_pr_switch *sw)
{
	if (!rxtx_registered || !rxtx_registered->ops->rxtx_switch_init)
		return;

	return rxtx_registered->ops->rxtx_switch_fini(rxtx_registered, sw);
}

u64 mvsw_pr_rxtx_get_cpu_code_stats(u8 cpu_code)
{
	return cpu_code_stats[cpu_code];
}
