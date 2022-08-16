/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#ifndef PRESTERA_FW_H
#define PRESTERA_FW_H_

#define PRESTERA_EVT_QNUM_MAX	4
#define PRESTERA_CMD_QNUM_MAX	4

struct prestera_fw_evtq_regs {
	u32 rd_idx;
	u32 pad1;
	u32 wr_idx;
	u32 pad2;
	u32 offs;
	u32 len;
};

struct prestera_fw_cmdq_regs {
	u32 cmd_req_ctl;
	u32 cmd_req_len;
	u32 cmd_rcv_ctl;
	u32 cmd_rcv_len;
	u32 offs;
	u32 len;
};

struct prestera_fw_regs {
	u32 fw_ready;
	u32 cmd_offs;
	u32 cmd_len;
	u32 cmd_qnum;
	u32 evt_offs;
	u32 evt_qnum;

	u32 fw_status;
	u32 rx_status;

	struct prestera_fw_cmdq_regs cmdq_list[PRESTERA_CMD_QNUM_MAX];
	struct prestera_fw_evtq_regs evtq_list[PRESTERA_EVT_QNUM_MAX];
};

#define prestera_wait(cond, waitms) \
({ \
	unsigned long __wait_end = jiffies + msecs_to_jiffies(waitms); \
	bool __wait_ret = false; \
	do { \
		if (cond) { \
			__wait_ret = true; \
			break; \
		} \
		cond_resched(); \
	} while (time_before(jiffies, __wait_end)); \
	__wait_ret; \
})

#define prestera_fw_dev(fw)	((fw)->dev.dev)

/* Firmware registers: */
#define PRESTERA_FW_REG_OFFSET(f)	offsetof(struct prestera_fw_regs, f)

#define PRESTERA_FW_STATUS_REG		PRESTERA_FW_REG_OFFSET(fw_status)
#define PRESTERA_RX_STATUS_REG		PRESTERA_FW_REG_OFFSET(rx_status)

#define prestera_fw_write(fw, reg, val)	writel(val, (fw)->hw_regs + (reg))
#define prestera_fw_read(fw, reg)	readl((fw)->hw_regs + (reg))

#define PRESTERA_SUPP_FW_MAJ_VER	3
#define PRESTERA_SUPP_FW_MIN_VER	2
#define PRESTERA_SUPP_FW_PATCH_VER	2

struct prestera_fw_evtq {
	u8 __iomem *addr;
	size_t len;
};

struct prestera_fw_cmdq {
	/* serialize access to dev->send_req */
	struct mutex cmd_mtx;
	u8 __iomem *addr;
	size_t len;
};

struct prestera_fw_header {
	__be32 magic_number;
	__be32 version_value;
	u8 reserved[8];
} __packed;

struct prestera_fw {
	struct workqueue_struct *wq;
	struct prestera_device dev;
	struct pci_dev *pci_dev;
	u8 __iomem *mem_addr;

	u8 __iomem *ldr_regs;
	u8 __iomem *hw_regs;

	u8 __iomem *ldr_ring_buf;
	u32 ldr_buf_len;
	u32 ldr_wr_idx;

	size_t cmd_mbox_len;
	u8 __iomem *cmd_mbox;
	struct prestera_fw_cmdq cmd_queue[PRESTERA_CMD_QNUM_MAX];
	u8 cmd_qnum;
	struct prestera_fw_evtq evt_queue[PRESTERA_EVT_QNUM_MAX];
	u8 evt_qnum;
	struct work_struct evt_work;
	u8 __iomem *evt_buf;
	u8 *evt_msg;
};

int prestera_fw_rev_check(struct prestera_fw *fw);
void prestera_fw_rev_parse_int(unsigned int firmware_version,
			       struct prestera_fw_rev *rev);
void prestera_fw_rev_parse(const struct prestera_fw_header *hdr,
			   struct prestera_fw_rev *rev);
void prestera_fw_uninit(struct prestera_fw *fw);
int prestera_fw_init(struct prestera_fw *fw);
int prestera_fw_send_req(struct prestera_device *dev, int qid,
			 u8 *in_msg, size_t in_size, u8 *out_msg,
			 size_t out_size, unsigned int wait);
void prestera_fw_handle_event(struct prestera_fw *fw);
void prestera_fw_queue_work(struct prestera_fw *fw);

#endif
