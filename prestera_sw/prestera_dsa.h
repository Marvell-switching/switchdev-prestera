/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved. */

#ifndef _MVSW_PRESTERA_DSA_H_
#define _MVSW_PRESTERA_DSA_H_

#include <linux/types.h>

#define MVSW_PR_DSA_HLEN	16

enum mvsw_pr_dsa_cmd {
	/* DSA command is "To CPU" */
	MVSW_NET_DSA_CMD_TO_CPU_E = 0,

	/* DSA command is "FROM CPU" */
	MVSW_NET_DSA_CMD_FROM_CPU_E,
};

struct mvsw_pr_dsa_common {
	/* the value vlan priority tag (APPLICABLE RANGES: 0..7) */
	u8 vpt;

	/* CFI bit of the vlan tag (APPLICABLE RANGES: 0..1) */
	u8 cfi_bit;

	/* Vlan id */
	u16 vid;
};

struct mvsw_pr_dsa_to_cpu {
	bool is_tagged;
	u32 hw_dev_num;
	bool src_is_trunk;
	u8 cpu_code;
	struct {
		u16 src_trunk_id;
		u32 port_num;
		u32 eport;
	} iface;
};

struct mvsw_pr_dsa_from_cpu {
	struct prestera_iface dst_iface;	/* vid/port */
	bool egr_filter_en;
	bool egr_filter_registered;
	u32 src_id;
	u32 src_hw_dev;
	u32 dst_eport;	/* for port but not for vid */
};

struct mvsw_pr_dsa {
	struct mvsw_pr_dsa_common common_params;
	enum mvsw_pr_dsa_cmd dsa_cmd;
	union {
		struct mvsw_pr_dsa_to_cpu to_cpu;
		struct mvsw_pr_dsa_from_cpu from_cpu;
	} dsa_info;
};

int mvsw_pr_dsa_parse(const u8 *dsa_bytes_ptr,
		      struct mvsw_pr_dsa *dsa_info_ptr);
int mvsw_pr_dsa_build(const struct mvsw_pr_dsa *dsa_info_ptr,
		      u8 *dsa_bytes_ptr);

#endif /* _MVSW_PRESTERA_DSA_H_ */
