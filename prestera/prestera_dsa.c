// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include "prestera.h"
#include "prestera_dsa.h"

#include <linux/string.h>
#include <linux/bitops.h>
#include <linux/bitfield.h>
#include <linux/errno.h>

#define W0_MASK_IS_TAGGED	BIT(29)

/* TrgDev[4:0] = {Word0[28:24]} */
#define W0_MASK_HW_DEV_NUM	GENMASK(28, 24)

/* SrcPort/TrgPort extended to 8b
 * SrcPort/TrgPort[7:0] = {Word2[20], Word1[11:10], Word0[23:19]}
 */
#define W0_MASK_IFACE_PORT_NUM	GENMASK(23, 19)

/* bits 30:31 - TagCommand 1 = FROM_CPU */
#define W0_MASK_DSA_CMD		GENMASK(31, 30)

/* bits 13:15 -- UP */
#define W0_MASK_VPT		GENMASK(15, 13)

#define W0_MASK_EXT_BIT		BIT(12)
#define W0_MASK_OPCODE		GENMASK(18, 16)

/* bit 16 - CFI */
#define W0_MASK_CFI_BIT		BIT(16)

/* bits 0:11 -- VID */
#define W0_MASK_VID		GENMASK(11, 0)

#define W1_MASK_SRC_IS_TARNK	BIT(27)

/* SrcPort/TrgPort extended to 8b
 * SrcPort/TrgPort[7:0] = {Word2[20], Word1[11:10], Word0[23:19]}
 */
#define W1_MASK_IFACE_PORT_NUM	GENMASK(11, 10)

#define W1_MASK_EXT_BIT		BIT(31)
#define W1_MASK_CFI_BIT		BIT(30)

/* bit 30 -- EgressFilterEn */
#define W1_MASK_EGR_FILTER_EN	BIT(30)

/* bit 28 -- egrFilterRegistered */
#define W1_MASK_EGR_FILTER_REG	BIT(28)

/* bits 20-24 -- Src-ID */
#define W1_MASK_SRC_ID		GENMASK(24, 20)

/* bits 15-19 -- SrcDev */
#define W1_MASK_SRC_DEV		GENMASK(19, 15)

/* SrcTrunk is extended to 12b
 * SrcTrunk[11:0] = {Word2[14:3]
 */
#define W2_MASK_SRC_TRANK_ID	GENMASK(14, 3)

/* SRCePort[16:0]/TRGePort[16:0]/ = {Word2[19:3]} */
#define W2_MASK_IFACE_EPORT	GENMASK(19, 3)

/* SrcPort/TrgPort extended to 8b
 * SrcPort/TrgPort[7:0] = {Word2[20], Word1[11:10], Word0[23:19]}
 */
#define W2_MASK_IFACE_PORT_NUM	BIT(20)

#define W2_MASK_EXT_BIT		BIT(31)

/* 5b SrcID is extended to 12 bits
 * SrcID[11:0] = {Word2[27:21], Word1[24:20]}
 */
#define W2_MASK_SRC_ID		GENMASK(27, 21)

/* 5b SrcDev is extended to 12b
 * SrcDev[11:0] = {Word2[20:14], Word1[19:15]}
 */
#define W2_MASK_SRC_DEV		GENMASK(20, 14)

/* trgHwDev and trgPort
 * TrgDev[11:5] = {Word3[6:0]}
 */
#define W3_MASK_HW_DEV_NUM	GENMASK(6, 0)

/* bits 0-7 -- CpuCode */
#define W1_MASK_CPU_CODE	GENMASK(7, 0)

/* VID becomes 16b eVLAN. eVLAN[15:0] = {Word3[30:27], Word0[11:0]} */
#define W3_MASK_VID		GENMASK(30, 27)

/* TRGePort[16:0] = {Word3[23:7]} */
#define W3_MASK_DST_EPORT	GENMASK(23, 7)

#define DEV_NUM_MASK		GENMASK(11, 5)
#define VID_MASK		GENMASK(15, 12)

static int net_if_dsa_to_cpu_parse(const u32 *words_ptr,
				   struct mvsw_pr_dsa *dsa_info_ptr)
{
	u32 get_value;	/* used to get needed bits from the DSA */
	struct mvsw_pr_dsa_to_cpu *to_cpu_ptr;

	to_cpu_ptr = &dsa_info_ptr->dsa_info.to_cpu;
	to_cpu_ptr->is_tagged =
	    (bool)FIELD_GET(W0_MASK_IS_TAGGED, words_ptr[0]);
	to_cpu_ptr->hw_dev_num = FIELD_GET(W0_MASK_HW_DEV_NUM, words_ptr[0]);
	to_cpu_ptr->src_is_trunk =
	    (bool)FIELD_GET(W1_MASK_SRC_IS_TARNK, words_ptr[1]);

	/* set hw dev num */
	get_value = FIELD_GET(W3_MASK_HW_DEV_NUM, words_ptr[3]);
	to_cpu_ptr->hw_dev_num &= W3_MASK_HW_DEV_NUM;
	to_cpu_ptr->hw_dev_num |= FIELD_PREP(DEV_NUM_MASK, get_value);

	get_value = FIELD_GET(W1_MASK_CPU_CODE, words_ptr[1]);
	to_cpu_ptr->cpu_code = (u8)get_value;

	if (to_cpu_ptr->src_is_trunk) {
		to_cpu_ptr->iface.src_trunk_id =
		    (u16)FIELD_GET(W2_MASK_SRC_TRANK_ID, words_ptr[2]);
	} else {
		/* When to_cpu_ptr->is_egress_pipe = false:
		 *   this field indicates the source ePort number assigned by
		 *   the ingress device.
		 * When to_cpu_ptr->is_egress_pipe = true:
		 *   this field indicates the target ePort number assigned by
		 *   the ingress device.
		 */
		to_cpu_ptr->iface.eport =
		    FIELD_GET(W2_MASK_IFACE_EPORT, words_ptr[2]);
	}
	to_cpu_ptr->iface.port_num =
	    (FIELD_GET(W0_MASK_IFACE_PORT_NUM, words_ptr[0]) << 0) |
	    (FIELD_GET(W1_MASK_IFACE_PORT_NUM, words_ptr[1]) << 5) |
	    (FIELD_GET(W2_MASK_IFACE_PORT_NUM, words_ptr[2]) << 7);

	return 0;
}

int mvsw_pr_dsa_parse(const u8 *dsa_bytes_ptr, struct mvsw_pr_dsa *dsa_info_ptr)
{
	u32 get_value;		/* used to get needed bits from the DSA */
	u32 words_ptr[4] = { 0 };	/* DSA tag can be up to 4 words */
	u32 *dsa_words_ptr = (u32 *)dsa_bytes_ptr;

	/* sanity */
	if (unlikely(!dsa_info_ptr || !dsa_bytes_ptr))
		return -EINVAL;

	/* zero results */
	memset(dsa_info_ptr, 0, sizeof(struct mvsw_pr_dsa));

	/* copy the data of the first word */
	words_ptr[0] = ntohl((__force __be32)dsa_words_ptr[0]);

	/* set the common parameters */
	dsa_info_ptr->dsa_cmd =
	    (enum mvsw_pr_dsa_cmd)FIELD_GET(W0_MASK_DSA_CMD, words_ptr[0]);

	/* vid & vlan prio */
	dsa_info_ptr->common_params.vid =
	    (u16)FIELD_GET(W0_MASK_VID, words_ptr[0]);
	dsa_info_ptr->common_params.vpt =
	    (u8)FIELD_GET(W0_MASK_VPT, words_ptr[0]);

	/* only to CPU is supported */
	if (unlikely(dsa_info_ptr->dsa_cmd != MVSW_NET_DSA_CMD_TO_CPU_E))
		return -EINVAL;

	/* check extended bit */
	if (FIELD_GET(W0_MASK_EXT_BIT, words_ptr[0]) == 0)
		/* 1 words DSA tag is not supported */
		return -EINVAL;

	/* check that the "old" cpu opcode is set the 0xF
	 * (with the extended bit)
	 */
	if (FIELD_GET(W0_MASK_OPCODE, words_ptr[0]) != 0x07)
		return -EINVAL;

	/* copy the data of the second word */
	words_ptr[1] = ntohl((__force __be32)dsa_words_ptr[1]);

	/* check the extended bit */
	if (FIELD_GET(W1_MASK_EXT_BIT, words_ptr[1]) == 0)
		/* 2 words DSA tag is not supported */
		return -EINVAL;

	/* copy the data of the third word */
	words_ptr[2] = ntohl((__force __be32)dsa_words_ptr[2]);

	/* check the extended bit */
	if (FIELD_GET(W2_MASK_EXT_BIT, words_ptr[1]) == 0)
		/* 3 words DSA tag is not supported */
		return -EINVAL;

	/* copy the data of the forth word */
	words_ptr[3] = ntohl((__force __be32)dsa_words_ptr[3]);

	/* VID */
	get_value = FIELD_GET(W3_MASK_VID, words_ptr[3]);
	dsa_info_ptr->common_params.vid &= ~VID_MASK;
	dsa_info_ptr->common_params.vid |= FIELD_PREP(VID_MASK, get_value);

	dsa_info_ptr->common_params.cfi_bit =
	    (u8)FIELD_GET(W1_MASK_CFI_BIT, words_ptr[1]);

	return net_if_dsa_to_cpu_parse(words_ptr, dsa_info_ptr);
}

static int net_if_dsa_tag_from_cpu_build(const struct mvsw_pr_dsa *dsa_info_ptr,
					 u32 *words_ptr)
{
	u32 trg_hw_dev = 0;
	u32 trg_port = 0;
	const struct mvsw_pr_dsa_from_cpu *from_cpu_ptr =
	    &dsa_info_ptr->dsa_info.from_cpu;

	if (unlikely(from_cpu_ptr->dst_iface.type != PRESTERA_IF_PORT_E))
		/* only sending to port interface is supported */
		return -EINVAL;

	words_ptr[0] |=
	    FIELD_PREP(W0_MASK_DSA_CMD, MVSW_NET_DSA_CMD_FROM_CPU_E);

	trg_hw_dev = from_cpu_ptr->dst_iface.dev_port.hw_dev_num;
	trg_port = from_cpu_ptr->dst_iface.dev_port.port_num;

	if (trg_hw_dev >= BIT(12))
		return -EINVAL;

	if (trg_port >= BIT(8) || trg_port >= BIT(10))
		return -EINVAL;

	words_ptr[0] |= FIELD_PREP(W0_MASK_HW_DEV_NUM, trg_hw_dev);
	words_ptr[3] |= FIELD_PREP(W3_MASK_HW_DEV_NUM, (trg_hw_dev >> 5));

	if (dsa_info_ptr->common_params.cfi_bit == 1)
		words_ptr[0] |= FIELD_PREP(W0_MASK_CFI_BIT, 1);

	words_ptr[0] |= FIELD_PREP(W0_MASK_VPT,
				   dsa_info_ptr->common_params.vpt);
	words_ptr[0] |= FIELD_PREP(W0_MASK_VID,
				   dsa_info_ptr->common_params.vid);

	/* set extended bits */
	words_ptr[0] |= FIELD_PREP(W0_MASK_EXT_BIT, 1);
	words_ptr[1] |= FIELD_PREP(W1_MASK_EXT_BIT, 1);
	words_ptr[2] |= FIELD_PREP(W2_MASK_EXT_BIT, 1);

	if (from_cpu_ptr->egr_filter_en)
		words_ptr[1] |= FIELD_PREP(W1_MASK_EGR_FILTER_EN, 1);

	if (from_cpu_ptr->egr_filter_registered)
		words_ptr[1] |= FIELD_PREP(W1_MASK_EGR_FILTER_REG, 1);

	/* check src_id & src_hw_dev */
	if (from_cpu_ptr->src_id >= BIT(12) ||
	    from_cpu_ptr->src_hw_dev >= BIT(12)) {
		return -EINVAL;
	}

	words_ptr[1] |= FIELD_PREP(W1_MASK_SRC_ID, from_cpu_ptr->src_id);
	words_ptr[1] |= FIELD_PREP(W1_MASK_SRC_DEV, from_cpu_ptr->src_hw_dev);

	words_ptr[2] |= FIELD_PREP(W2_MASK_SRC_ID, from_cpu_ptr->src_id >> 5);
	words_ptr[2] |= FIELD_PREP(W2_MASK_SRC_DEV,
				   from_cpu_ptr->src_hw_dev >> 5);

	/* bits 0:9 -- reserved with value 0 */
	if (from_cpu_ptr->dst_eport >= BIT(17))
		return -EINVAL;

	words_ptr[3] |= FIELD_PREP(W3_MASK_DST_EPORT, from_cpu_ptr->dst_eport);
	words_ptr[3] |= FIELD_PREP(W3_MASK_VID,
				   (dsa_info_ptr->common_params.vid >> 12));

	return 0;
}

int mvsw_pr_dsa_build(const struct mvsw_pr_dsa *dsa_info_ptr,
		      u8 *dsa_bytes_ptr)
{
	int rc;
	u32 words_ptr[4] = { 0 };	/* 4 words of DSA tag */
	__be32 *dsa_words_ptr = (__be32 *)dsa_bytes_ptr;

	if (unlikely(!dsa_info_ptr || !dsa_bytes_ptr))
		return -EINVAL;

	if (dsa_info_ptr->common_params.cfi_bit >= BIT(1) ||
	    dsa_info_ptr->common_params.vpt >= BIT(3)) {
		return -EINVAL;
	}

	if (unlikely(dsa_info_ptr->dsa_cmd != MVSW_NET_DSA_CMD_FROM_CPU_E))
		return -EINVAL;

	/* build form CPU DSA tag */
	rc = net_if_dsa_tag_from_cpu_build(dsa_info_ptr, words_ptr);
	if (rc != 0)
		return rc;

	dsa_words_ptr[0] = htonl(words_ptr[0]);
	dsa_words_ptr[1] = htonl(words_ptr[1]);
	dsa_words_ptr[2] = htonl(words_ptr[2]);
	dsa_words_ptr[3] = htonl(words_ptr[3]);

	return 0;
}
