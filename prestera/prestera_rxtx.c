// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/dmapool.h>
#include <linux/if_vlan.h>
#include <net/ip.h>

#include "prestera.h"
#include "prestera_hw.h"
#include "prestera_dsa.h"
#include "prestera_rxtx.h"
#include "prestera_devlink.h"

#define MVSW_DSA_TAG_ARP_BROADCAST 5
#define MVSW_DSA_TAG_IPV4_BROADCAST 19
#define MVSW_DSA_TAG_IPV4_IPV6_LINK_LOCAL_MC 16
#define MVSW_DSA_TAG_IPV4_IPV6_LINK_LOCAL_MC_1 29
#define MVSW_DSA_TAG_IPV4_IPV6_LINK_LOCAL_MC_2 30
#define MVSW_DSA_TAG_UDP_BROADCAST 33
#define MVSW_DSA_TAG_ARP_BROADCAST_TO_ME 179

struct mvsw_sdma_desc {
	__le32 word1;
	__le32 word2;
	__le32 buff;
	__le32 next;
} __packed __aligned(16);

#define SDMA_BUFF_SIZE_MAX	1544

#define SDMA_RX_DESC_PKT_LEN(desc) \
	((le32_to_cpu((desc)->word2) >> 16) & 0x3FFF)

#define SDMA_RX_DESC_OWNER(desc) \
	((le32_to_cpu((desc)->word1) & BIT(31)) >> 31)

#define SDMA_RX_DESC_CPU_OWN	0
#define SDMA_RX_DESC_DMA_OWN	1

#define SDMA_RX_QUEUE_NUM	8

#define SDMA_RX_DESC_PER_Q	1000

#define SDMA_TX_DESC_PER_Q	1000
#define SDMA_TX_MAX_BURST	32

#define SDMA_TX_DESC_OWNER(desc) \
	((le32_to_cpu((desc)->word1) & BIT(31)) >> 31)

#define SDMA_TX_DESC_CPU_OWN	0
#define SDMA_TX_DESC_DMA_OWN	1

#define SDMA_TX_DESC_IS_SENT(desc) \
	(SDMA_TX_DESC_OWNER(desc) == SDMA_TX_DESC_CPU_OWN)

#define SDMA_TX_DESC_LAST	BIT(20)
#define SDMA_TX_DESC_FIRST	BIT(21)
#define SDMA_TX_DESC_SINGLE	(SDMA_TX_DESC_FIRST | SDMA_TX_DESC_LAST)
#define SDMA_TX_DESC_CALC_CRC	BIT(12)

#define mvsw_reg_write(sw, reg, val) \
	writel(val, (sw)->dev->pp_regs + (reg))
#define mvsw_reg_read(sw, reg) \
	readl((sw)->dev->pp_regs + (reg))

#define SDMA_RX_INTR_MASK_REG		0x2814
#define SDMA_RX_QUEUE_STATUS_REG	0x2680
#define SDMA_RX_QUEUE_DESC_REG(n)	(0x260C + (n) * 16)

#define SDMA_TX_QUEUE_DESC_REG		0x26C0
#define SDMA_TX_QUEUE_START_REG		0x2868

struct mvsw_sdma_buf {
	struct mvsw_sdma_desc *desc;
	dma_addr_t desc_dma;
	struct sk_buff *skb;
	dma_addr_t buf_dma;
	bool is_used;
};

struct mvsw_sdma_rx_ring {
	struct mvsw_sdma_buf *bufs;
	int next_rx;
	int weight;
	int recvd;
};

struct mvsw_sdma_tx_ring {
	struct mvsw_sdma_buf *bufs;
	int next_tx;
	int max_burst;
	int burst;
};

struct mvsw_pr_rxtx_sdma {
	struct mvsw_sdma_rx_ring rx_ring[SDMA_RX_QUEUE_NUM];
	struct mvsw_sdma_tx_ring tx_ring;
	const struct prestera_switch *sw;
	struct dma_pool *desc_pool;
	struct work_struct tx_work;
	struct napi_struct rx_napi;
	int next_rxq;
	struct net_device napi_dev;
	/* protect SDMA with concurrrent access from multiple CPUs */
	spinlock_t tx_lock;
	u32 map_addr;
	u64 dma_mask;
	gfp_t dma_flags;
};

struct prestera_rxtx {
	struct mvsw_pr_rxtx_sdma sdma;
};

static int prestera_rx_weight_map[SDMA_RX_QUEUE_NUM] = {
	1, 2, 2, 2, 2, 4, 4, 8
};

static u64 *cpu_code_stats;

static int mvsw_sdma_buf_desc_alloc(struct mvsw_pr_rxtx_sdma *sdma,
				    struct mvsw_sdma_buf *buf)
{
	struct device *dma_dev = sdma->sw->dev->dev;
	struct mvsw_sdma_desc *desc;
	dma_addr_t dma;

	desc = dma_pool_alloc(sdma->desc_pool, sdma->dma_flags | GFP_KERNEL, &dma);
	if (!desc)
		return -ENOMEM;

	if (dma + sizeof(struct mvsw_sdma_desc) > sdma->dma_mask) {
		dev_err(dma_dev, "failed to alloc desc\n");
		dma_pool_free(sdma->desc_pool, desc, dma);
		return -ENOMEM;
	}

	buf->desc_dma = dma;
	buf->desc = desc;

	return 0;
}

static u32 mvsw_sdma_addr_phy(struct mvsw_pr_rxtx_sdma *sdma, dma_addr_t pa)
{
	return sdma->map_addr + pa;
}

static void mvsw_sdma_rx_desc_set_len(struct mvsw_sdma_desc *desc, size_t val)
{
	u32 word = le32_to_cpu(desc->word2);

	word = (word & ~GENMASK(15, 0)) | val;
	desc->word2 = cpu_to_le32(word);
}

static void mvsw_sdma_rx_desc_init(struct mvsw_pr_rxtx_sdma *sdma,
				   struct mvsw_sdma_desc *desc,
				   dma_addr_t buf)
{
	mvsw_sdma_rx_desc_set_len(desc, SDMA_BUFF_SIZE_MAX);
	desc->buff = cpu_to_le32(mvsw_sdma_addr_phy(sdma, buf));
	/* make sure buffer is set before reset the descriptor */
	wmb();
	desc->word1 = cpu_to_le32(0xA0000000);
}

static void mvsw_sdma_rx_desc_set_next(struct mvsw_pr_rxtx_sdma *sdma,
				       struct mvsw_sdma_desc *desc,
				       dma_addr_t next)
{
	desc->next = cpu_to_le32(mvsw_sdma_addr_phy(sdma, next));
}

static int mvsw_sdma_rx_dma_alloc(struct mvsw_pr_rxtx_sdma *sdma,
				  struct mvsw_sdma_buf *buf)
{
	struct device *dev = sdma->sw->dev->dev;

	buf->skb = alloc_skb(SDMA_BUFF_SIZE_MAX, sdma->dma_flags | GFP_ATOMIC);
	if (!buf->skb)
		return -ENOMEM;

	buf->buf_dma = dma_map_single(dev, buf->skb->data, SDMA_BUFF_SIZE_MAX,
				      DMA_FROM_DEVICE);

	if (dma_mapping_error(dev, buf->buf_dma))
		goto err_dma_map;
	if (buf->buf_dma + SDMA_BUFF_SIZE_MAX > sdma->dma_mask)
		goto err_dma_range;

	return 0;

err_dma_range:
	dma_unmap_single(dev, buf->buf_dma, SDMA_BUFF_SIZE_MAX,
			 DMA_FROM_DEVICE);
	buf->buf_dma = DMA_MAPPING_ERROR;
err_dma_map:
	kfree_skb(buf->skb);
	buf->skb = NULL;

	return -ENOMEM;
}

static struct sk_buff *mvsw_sdma_rx_buf_get(struct mvsw_pr_rxtx_sdma *sdma,
					    struct mvsw_sdma_buf *buf)
{
	struct sk_buff *skb_orig = buf->skb;
	dma_addr_t buf_dma = buf->buf_dma;
	u32 len = skb_orig->len;
	int err;

	err = mvsw_sdma_rx_dma_alloc(sdma, buf);
	if (err) {
		struct sk_buff *skb;

		buf->buf_dma = buf_dma;
		buf->skb = skb_orig;

		skb = alloc_skb(SDMA_BUFF_SIZE_MAX, GFP_ATOMIC);
		if (!skb)
			return NULL;

		skb_copy_from_linear_data(buf->skb, skb_put(skb, len), len);
		return skb;
	}

	return skb_orig;
}

static void mvsw_sdma_rx_set_next_queue(struct mvsw_pr_rxtx_sdma *sdma, int rxq)
{
	sdma->next_rxq = rxq % SDMA_RX_QUEUE_NUM;
}

static int mvsw_sdma_rx_pick_next_queue(struct mvsw_pr_rxtx_sdma *sdma)
{
	struct mvsw_sdma_rx_ring *ring = &sdma->rx_ring[sdma->next_rxq];

	if (ring->recvd >= ring->weight) {
		mvsw_sdma_rx_set_next_queue(sdma, sdma->next_rxq + 1);
		ring->recvd = 0;
	}

	return sdma->next_rxq;
}

static int mvsw_pr_sdma_recv_skb(struct sk_buff *skb)
{
	struct prestera_rxtx_stats *rxtx_stats;
	struct prestera_port *port;
	struct mvsw_pr_dsa dsa;
	u32 hw_port, hw_id;
	u8 cpu_code;
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
	port = prestera_port_find(hw_id, hw_port);
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

	cpu_code = dsa.dsa_info.to_cpu.cpu_code;

	prestera_devlink_trap_report(port, skb, cpu_code);

	switch (cpu_code) {
	case MVSW_DSA_TAG_ARP_BROADCAST:
	case MVSW_DSA_TAG_IPV4_BROADCAST:
	case MVSW_DSA_TAG_IPV4_IPV6_LINK_LOCAL_MC:
	case MVSW_DSA_TAG_IPV4_IPV6_LINK_LOCAL_MC_1:
	case MVSW_DSA_TAG_IPV4_IPV6_LINK_LOCAL_MC_2:
	case MVSW_DSA_TAG_UDP_BROADCAST:
	case MVSW_DSA_TAG_ARP_BROADCAST_TO_ME:
		skb->offload_fwd_mark = 1;
	}
	++cpu_code_stats[cpu_code];

	rxtx_stats = this_cpu_ptr(port->rxtx_stats);
	u64_stats_update_begin(&rxtx_stats->syncp);
	rxtx_stats->rx_packets++;
	rxtx_stats->rx_bytes += skb->len;
	u64_stats_update_end(&rxtx_stats->syncp);

	return 0;
}

static int mvsw_sdma_rx_poll(struct napi_struct *napi, int budget)
{
	unsigned int qmask = GENMASK(SDMA_RX_QUEUE_NUM - 1, 0);
	struct mvsw_pr_rxtx_sdma *sdma;
	unsigned int rxq_done_map = 0;
	struct list_head rx_list;
	int pkts_done = 0;

	INIT_LIST_HEAD(&rx_list);

	sdma = container_of(napi, struct mvsw_pr_rxtx_sdma, rx_napi);

	while (pkts_done < budget && rxq_done_map != qmask) {
		struct mvsw_sdma_rx_ring *ring;
		struct mvsw_sdma_desc *desc;
		struct mvsw_sdma_buf *buf;
		struct sk_buff *skb;
		int buf_idx;
		int rxq;

		rxq = mvsw_sdma_rx_pick_next_queue(sdma);
		ring = &sdma->rx_ring[rxq];

		buf_idx = ring->next_rx;
		buf = &ring->bufs[buf_idx];
		desc = buf->desc;

		if (SDMA_RX_DESC_OWNER(desc) != SDMA_RX_DESC_CPU_OWN) {
			mvsw_sdma_rx_set_next_queue(sdma, rxq + 1);
			rxq_done_map |= BIT(rxq);
			continue;
		} else {
			rxq_done_map &= ~BIT(rxq);
		}

		ring->recvd++;
		pkts_done++;

		__skb_trim(buf->skb, SDMA_RX_DESC_PKT_LEN(desc));

		skb = mvsw_sdma_rx_buf_get(sdma, buf);
		if (!skb)
			goto rx_reset_buf;

		if (unlikely(mvsw_pr_sdma_recv_skb(skb)))
			goto rx_reset_buf;

		list_add_tail(&skb->list, &rx_list);
rx_reset_buf:
		mvsw_sdma_rx_desc_init(sdma, buf->desc, buf->buf_dma);
		ring->next_rx = (buf_idx + 1) % SDMA_RX_DESC_PER_Q;
	}

	if (pkts_done < budget && napi_complete_done(napi, pkts_done))
		mvsw_reg_write(sdma->sw, SDMA_RX_INTR_MASK_REG,
			       (0xff << 2) | (0xff << 11));

	netif_receive_skb_list(&rx_list);

	return pkts_done;
}

static void mvsw_sdma_rx_fini(struct mvsw_pr_rxtx_sdma *sdma)
{
	int q, b;

	/* disable all rx queues */
	mvsw_reg_write(sdma->sw, SDMA_RX_QUEUE_STATUS_REG, 0xff00);

	for (q = 0; q < SDMA_RX_QUEUE_NUM; q++) {
		struct mvsw_sdma_rx_ring *ring = &sdma->rx_ring[q];

		if (!ring->bufs)
			break;

		for (b = 0; b < SDMA_RX_DESC_PER_Q; b++) {
			struct mvsw_sdma_buf *buf = &ring->bufs[b];

			if (buf->desc_dma)
				dma_pool_free(sdma->desc_pool, buf->desc,
					      buf->desc_dma);

			if (!buf->skb)
				continue;

			if (buf->buf_dma != DMA_MAPPING_ERROR)
				dma_unmap_single(sdma->sw->dev->dev,
						 buf->buf_dma,
						 SDMA_BUFF_SIZE_MAX,
						 DMA_FROM_DEVICE);
			kfree_skb(buf->skb);
		}
	}
}

static int mvsw_sdma_rx_init(struct mvsw_pr_rxtx_sdma *sdma)
{
	int q, b;
	int err;

	/* disable all rx queues */
	mvsw_reg_write(sdma->sw, SDMA_RX_QUEUE_STATUS_REG, 0xff00);

	for (q = 0; q < SDMA_RX_QUEUE_NUM; q++) {
		struct mvsw_sdma_rx_ring *ring = &sdma->rx_ring[q];
		struct mvsw_sdma_buf *head;

		ring->bufs = kmalloc_array(SDMA_RX_DESC_PER_Q, sizeof(*head),
					   GFP_KERNEL);
		if (!ring->bufs)
			return -ENOMEM;

		ring->weight = prestera_rx_weight_map[q];
		ring->recvd = 0;
		ring->next_rx = 0;

		head = &ring->bufs[0];

		for (b = 0; b < SDMA_RX_DESC_PER_Q; b++) {
			struct mvsw_sdma_buf *buf = &ring->bufs[b];

			err = mvsw_sdma_buf_desc_alloc(sdma, buf);
			if (err)
				return err;

			err = mvsw_sdma_rx_dma_alloc(sdma, buf);
			if (err)
				return err;

			mvsw_sdma_rx_desc_init(sdma, buf->desc, buf->buf_dma);

			if (b == 0)
				continue;

			mvsw_sdma_rx_desc_set_next(sdma, ring->bufs[b - 1].desc,
						   buf->desc_dma);

			if (b == SDMA_RX_DESC_PER_Q - 1)
				mvsw_sdma_rx_desc_set_next(sdma, buf->desc,
							   head->desc_dma);
		}

		mvsw_reg_write(sdma->sw, SDMA_RX_QUEUE_DESC_REG(q),
			       mvsw_sdma_addr_phy(sdma, head->desc_dma));
	}

	/* make sure all rx descs are filled before enabling all rx queues */
	wmb();
	mvsw_reg_write(sdma->sw, SDMA_RX_QUEUE_STATUS_REG, 0xff);

	return 0;
}

static void mvsw_sdma_tx_desc_init(struct mvsw_pr_rxtx_sdma *sdma,
				   struct mvsw_sdma_desc *desc)
{
	desc->word1 = cpu_to_le32(SDMA_TX_DESC_SINGLE | SDMA_TX_DESC_CALC_CRC);
	desc->word2 = 0;
}

static void mvsw_sdma_tx_desc_set_next(struct mvsw_pr_rxtx_sdma *sdma,
				       struct mvsw_sdma_desc *desc,
				       dma_addr_t next)
{
	desc->next = cpu_to_le32(mvsw_sdma_addr_phy(sdma, next));
}

static void mvsw_sdma_tx_desc_set_buf(struct mvsw_pr_rxtx_sdma *sdma,
				      struct mvsw_sdma_desc *desc,
				      dma_addr_t buf, size_t len)
{
	u32 word = le32_to_cpu(desc->word2);

	word = (word & ~GENMASK(30, 16)) | ((len + 4) << 16);

	desc->buff = cpu_to_le32(mvsw_sdma_addr_phy(sdma, buf));
	desc->word2 = cpu_to_le32(word);
}

static void mvsw_sdma_tx_desc_xmit(struct mvsw_sdma_desc *desc)
{
	u32 word = le32_to_cpu(desc->word1);

	word |= (SDMA_TX_DESC_DMA_OWN << 31);

	/* make sure everything is written before enable xmit */
	wmb();
	desc->word1 = cpu_to_le32(word);
}

static int mvsw_sdma_tx_buf_map(struct mvsw_pr_rxtx_sdma *sdma,
				struct mvsw_sdma_buf *buf,
				struct sk_buff *skb)
{
	struct device *dma_dev = sdma->sw->dev->dev;
	struct sk_buff *new_skb;
	size_t len = skb->len;
	dma_addr_t dma;

	dma = dma_map_single(dma_dev, skb->data, len, DMA_TO_DEVICE);
	if (!dma_mapping_error(dma_dev, dma) && dma + len <= sdma->dma_mask) {
		buf->buf_dma = dma;
		buf->skb = skb;
		return 0;
	}

	if (!dma_mapping_error(dma_dev, dma))
		dma_unmap_single(dma_dev, dma, len, DMA_TO_DEVICE);

	new_skb = alloc_skb(len, GFP_ATOMIC | sdma->dma_flags);
	if (!new_skb)
		goto err_alloc_skb;

	dma = dma_map_single(dma_dev, new_skb->data, len, DMA_TO_DEVICE);
	if (dma_mapping_error(dma_dev, dma))
		goto err_dma_map;
	if (dma + len > sdma->dma_mask)
		goto err_dma_range;

	skb_copy_from_linear_data(skb, skb_put(new_skb, len), len);

	dev_consume_skb_any(skb);

	buf->skb = new_skb;
	buf->buf_dma = dma;

	return 0;

err_dma_range:
	dma_unmap_single(dma_dev, dma, len, DMA_TO_DEVICE);
err_dma_map:
	dev_kfree_skb(new_skb);
err_alloc_skb:
	dev_kfree_skb(skb);

	return -ENOMEM;
}

static void mvsw_sdma_tx_buf_unmap(struct mvsw_pr_rxtx_sdma *sdma,
				   struct mvsw_sdma_buf *buf)
{
	struct device *dma_dev = sdma->sw->dev->dev;

	dma_unmap_single(dma_dev, buf->buf_dma, buf->skb->len, DMA_TO_DEVICE);
}

static void mvsw_sdma_tx_recycle_work_fn(struct work_struct *work)
{
	struct mvsw_sdma_tx_ring *tx_ring;
	struct mvsw_pr_rxtx_sdma *sdma;
	struct device *dma_dev;
	int b;

	sdma = container_of(work, struct mvsw_pr_rxtx_sdma, tx_work);

	dma_dev = sdma->sw->dev->dev;
	tx_ring = &sdma->tx_ring;

	for (b = 0; b < SDMA_TX_DESC_PER_Q; b++) {
		struct mvsw_sdma_buf *buf = &tx_ring->bufs[b];

		if (!buf->is_used)
			continue;

		if (!SDMA_TX_DESC_IS_SENT(buf->desc))
			continue;

		mvsw_sdma_tx_buf_unmap(sdma, buf);
		dev_consume_skb_any(buf->skb);
		buf->skb = NULL;

		/* make sure everything is cleaned up */
		wmb();

		buf->is_used = false;
	}
}

static int mvsw_sdma_tx_init(struct mvsw_pr_rxtx_sdma *sdma)
{
	struct mvsw_sdma_tx_ring *tx_ring = &sdma->tx_ring;
	struct mvsw_sdma_buf *head;
	int err;
	int b;

	spin_lock_init(&sdma->tx_lock);

	INIT_WORK(&sdma->tx_work, mvsw_sdma_tx_recycle_work_fn);

	tx_ring->bufs = kmalloc_array(SDMA_TX_DESC_PER_Q, sizeof(*head),
				      GFP_KERNEL);
	if (!tx_ring->bufs)
		return -ENOMEM;

	head = &tx_ring->bufs[0];

	tx_ring->max_burst = SDMA_TX_MAX_BURST;
	tx_ring->burst = tx_ring->max_burst;
	tx_ring->next_tx = 0;

	for (b = 0; b < SDMA_TX_DESC_PER_Q; b++) {
		struct mvsw_sdma_buf *buf = &tx_ring->bufs[b];

		err = mvsw_sdma_buf_desc_alloc(sdma, buf);
		if (err)
			return err;

		mvsw_sdma_tx_desc_init(sdma, buf->desc);

		buf->is_used = false;
		buf->skb = NULL;

		if (b == 0)
			continue;

		mvsw_sdma_tx_desc_set_next(sdma, tx_ring->bufs[b - 1].desc,
					   buf->desc_dma);

		if (b == SDMA_TX_DESC_PER_Q - 1)
			mvsw_sdma_tx_desc_set_next(sdma, buf->desc,
						   head->desc_dma);
	}

	/* make sure descriptors are written */
	wmb();
	mvsw_reg_write(sdma->sw, SDMA_TX_QUEUE_DESC_REG,
		       mvsw_sdma_addr_phy(sdma, head->desc_dma));

	return 0;
}

static void mvsw_sdma_tx_fini(struct mvsw_pr_rxtx_sdma *sdma)
{
	struct mvsw_sdma_tx_ring *ring = &sdma->tx_ring;
	int b;

	cancel_work_sync(&sdma->tx_work);

	if (!ring->bufs)
		return;

	for (b = 0; b < SDMA_TX_DESC_PER_Q; b++) {
		struct mvsw_sdma_buf *buf = &ring->bufs[b];

		if (buf->desc)
			dma_pool_free(sdma->desc_pool, buf->desc,
				      buf->desc_dma);

		if (!buf->skb)
			continue;

		dma_unmap_single(sdma->sw->dev->dev, buf->buf_dma,
				 buf->skb->len, DMA_TO_DEVICE);

		dev_consume_skb_any(buf->skb);
	}
}

static void mvsw_rxtx_handle_event(struct prestera_switch *sw,
				   struct prestera_event *evt, void *arg)
{
	struct mvsw_pr_rxtx_sdma *sdma = arg;

	if (evt->id != PRESTERA_RXTX_EVENT_RCV_PKT)
		return;

	mvsw_reg_write(sdma->sw, SDMA_RX_INTR_MASK_REG, 0);
	napi_schedule(&sdma->rx_napi);
}

int prestera_rxtx_switch_init(struct prestera_switch *sw)
{
	struct mvsw_pr_rxtx_sdma *sdma;
	int err;

	cpu_code_stats = kzalloc(sizeof(u64) *
				 MVSW_PR_RXTX_CPU_CODE_MAX_NUM, GFP_KERNEL);
	if (!cpu_code_stats)
		return -ENOMEM;

	sw->rxtx = kzalloc(sizeof(*sw->rxtx), GFP_KERNEL);
	if (!sw->rxtx) {
		err = -ENOMEM;
		goto err_rxtx_alloc;
	}

	sdma = &sw->rxtx->sdma;

	err = prestera_hw_rxtx_init(sw, true, &sdma->map_addr);
	if (err) {
		dev_err(sw->dev->dev, "failed to init rxtx by hw\n");
		goto err_hw_rxtx_init;
	}

	sdma->dma_flags = sw->dev->dma_flags;
	sdma->dma_mask = dma_get_mask(sw->dev->dev);
	sdma->sw = sw;

	sdma->desc_pool = dma_pool_create("desc_pool", sdma->sw->dev->dev,
					  sizeof(struct mvsw_sdma_desc), 16, 0);
	if (!sdma->desc_pool) {
		err = -ENOMEM;
		goto err_dma_pool;
	}

	err = mvsw_sdma_rx_init(sdma);
	if (err) {
		dev_err(sw->dev->dev, "failed to init rx ring\n");
		goto err_rx_init;
	}

	err = mvsw_sdma_tx_init(sdma);
	if (err) {
		dev_err(sw->dev->dev, "failed to init tx ring\n");
		goto err_tx_init;
	}

	err = prestera_hw_event_handler_register(sw, PRESTERA_EVENT_TYPE_RXTX,
						 mvsw_rxtx_handle_event, sdma);
	if (err)
		goto err_evt_register;

	init_dummy_netdev(&sdma->napi_dev);

	netif_napi_add(&sdma->napi_dev, &sdma->rx_napi, mvsw_sdma_rx_poll, 64);
	napi_enable(&sdma->rx_napi);

	return 0;

err_evt_register:
err_tx_init:
	mvsw_sdma_tx_fini(sdma);
err_rx_init:
	mvsw_sdma_rx_fini(sdma);

	dma_pool_destroy(sdma->desc_pool);
err_dma_pool:
err_hw_rxtx_init:
	kfree(sw->rxtx);
err_rxtx_alloc:
	kfree(cpu_code_stats);
	return err;
}

void prestera_rxtx_switch_fini(struct prestera_switch *sw)
{
	struct mvsw_pr_rxtx_sdma *sdma = &sw->rxtx->sdma;

	prestera_hw_event_handler_unregister(sw, PRESTERA_EVENT_TYPE_RXTX);
	napi_disable(&sdma->rx_napi);
	netif_napi_del(&sdma->rx_napi);
	mvsw_sdma_rx_fini(sdma);
	mvsw_sdma_tx_fini(sdma);
	dma_pool_destroy(sdma->desc_pool);
	kfree(sw->rxtx);
	sw->rxtx = NULL;
	kfree(cpu_code_stats);
}

static int mvsw_sdma_wait_tx(struct mvsw_pr_rxtx_sdma *sdma,
			     struct mvsw_sdma_tx_ring *tx_ring)
{
	int tx_retry_num = 10 * tx_ring->max_burst;

	while (--tx_retry_num) {
		if (!(mvsw_reg_read(sdma->sw, SDMA_TX_QUEUE_START_REG) & 1))
			return 0;

		udelay(5);
	}

	return -EBUSY;
}

static void mvsw_sdma_start_tx(struct mvsw_pr_rxtx_sdma *sdma)
{
	mvsw_reg_write(sdma->sw, SDMA_TX_QUEUE_START_REG, 1);
	schedule_work(&sdma->tx_work);
}

static int mvsw_pr_rxtx_sdma_xmit(struct prestera_rxtx *rxtx,
				  struct sk_buff *skb)
{
	struct mvsw_pr_rxtx_sdma *sdma = &rxtx->sdma;
	struct device *dma_dev = sdma->sw->dev->dev;
	struct mvsw_sdma_tx_ring *tx_ring;
	struct net_device *dev = skb->dev;
	struct mvsw_sdma_buf *buf;
	int err;

	spin_lock(&sdma->tx_lock);

	tx_ring = &sdma->tx_ring;

	buf = &tx_ring->bufs[tx_ring->next_tx];
	if (buf->is_used) {
		schedule_work(&sdma->tx_work);
		err = -EBUSY;
		goto drop_skb;
	}

	if (unlikely(skb_put_padto(skb, ETH_ZLEN))) {
		err = -ENOMEM;
		goto drop_skb;
	}

	err = mvsw_sdma_tx_buf_map(sdma, buf, skb);
	if (err)
		goto drop_skb;

	mvsw_sdma_tx_desc_set_buf(sdma, buf->desc, buf->buf_dma, skb->len);

	dma_sync_single_for_device(dma_dev, buf->buf_dma, skb->len,
				   DMA_TO_DEVICE);

	if (!tx_ring->burst--) {
		tx_ring->burst = tx_ring->max_burst;

		err = mvsw_sdma_wait_tx(sdma, tx_ring);
		if (err)
			goto drop_skb_unmap;
	}

	tx_ring->next_tx = (tx_ring->next_tx + 1) % SDMA_TX_DESC_PER_Q;
	mvsw_sdma_tx_desc_xmit(buf->desc);
	buf->is_used = true;

	mvsw_sdma_start_tx(sdma);

	goto tx_done;

drop_skb_unmap:
	mvsw_sdma_tx_buf_unmap(sdma, buf);
drop_skb:
	dev->stats.tx_dropped++;
tx_done:
	spin_unlock(&sdma->tx_lock);
	return err;
}

netdev_tx_t prestera_rxtx_xmit(struct sk_buff *skb, struct prestera_port *port)
{
	size_t dsa_resize_len = MVSW_PR_DSA_HLEN;
	struct prestera_rxtx_stats *rxtx_stats;
	struct mvsw_pr_dsa_from_cpu *from_cpu;
	struct mvsw_pr_dsa dsa;
	u64 skb_len = skb->len;

	if (unlikely(!port->sw || !port->sw->rxtx))
		goto tx_drop;

	/* common DSA tag fill-up */
	memset(&dsa, 0, sizeof(dsa));
	dsa.dsa_cmd = MVSW_NET_DSA_CMD_FROM_CPU_E;

	from_cpu = &dsa.dsa_info.from_cpu;
	from_cpu->egr_filter_en = false;
	from_cpu->egr_filter_registered = false;
	from_cpu->dst_eport = port->hw_id;

	from_cpu->dst_iface.dev_port.port_num = port->hw_id;
	from_cpu->dst_iface.dev_port.hw_dev_num = port->dev_id;
	from_cpu->dst_iface.type = PRESTERA_IF_PORT_E;

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
		goto tx_drop_stats_inc;

	/* expects skb->data at mac header */
	skb_push(skb, dsa_resize_len);
	memmove(skb->data, skb->data + dsa_resize_len, 2 * ETH_ALEN);

	if (mvsw_pr_dsa_build(&dsa, skb->data + 2 * ETH_ALEN) != 0)
		goto tx_drop_stats_inc;

	if (mvsw_pr_rxtx_sdma_xmit(port->sw->rxtx, skb))
		goto tx_drop_stats_inc;

	rxtx_stats = this_cpu_ptr(port->rxtx_stats);
	u64_stats_update_begin(&rxtx_stats->syncp);
	rxtx_stats->tx_packets++;
	rxtx_stats->tx_bytes += skb_len;
	u64_stats_update_end(&rxtx_stats->syncp);

	return NETDEV_TX_OK;

tx_drop_stats_inc:
	this_cpu_inc(port->rxtx_stats->tx_dropped);
tx_drop:
	dev_kfree_skb_any(skb);
	return NET_XMIT_DROP;
}

u64 mvsw_pr_rxtx_get_cpu_code_stats(u8 cpu_code)
{
	return cpu_code_stats[cpu_code];
}
