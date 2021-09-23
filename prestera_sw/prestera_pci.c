// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/circ_buf.h>
#include <linux/firmware.h>

#include "prestera.h"

#define PRESTERA_FW_DEFAULT_PATH	"marvell/mvsw_prestera_fw.img"
#define PRESTERA_FW_ARM64_PATH		"marvell/mvsw_prestera_fw_arm64.img"

#define PRESTERA_SUPP_FW_MAJ_VER	3
#define PRESTERA_SUPP_FW_MIN_VER	0
#define PRESTERA_SUPP_FW_PATCH_VER	1

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

#define PRESTERA_FW_HDR_MAGIC	0x351D9D06
#define PRESTERA_FW_DL_TIMEOUT	50000
#define PRESTERA_FW_BLK_SZ	1024

#define FW_VER_MAJ_MUL 1000000
#define FW_VER_MIN_MUL 1000

#define FW_VER_MAJ(v)	((v) / FW_VER_MAJ_MUL)

#define FW_VER_MIN(v) \
	(((v) - (FW_VER_MAJ(v) * FW_VER_MAJ_MUL)) / FW_VER_MIN_MUL)

#define FW_VER_PATCH(v) \
	(v - (FW_VER_MAJ(v) * FW_VER_MAJ_MUL) - (FW_VER_MIN(v) * FW_VER_MIN_MUL))

struct prestera_fw_header {
	__be32 magic_number;
	__be32 version_value;
	u8 reserved[8];
} __packed;

struct prestera_ldr_regs {
	u32 ldr_ready;
	u32 pad1;

	u32 ldr_img_size;
	u32 ldr_ctl_flags;

	u32 ldr_buf_offs;
	u32 ldr_buf_size;

	u32 ldr_buf_rd;
	u32 pad2;
	u32 ldr_buf_wr;

	u32 ldr_status;
} __packed __aligned(4);

#define PRESTERA_LDR_REG_OFFSET(f)	offsetof(struct prestera_ldr_regs, f)

#define PRESTERA_LDR_READY_MAGIC	0xf00dfeed

#define PRESTERA_LDR_STATUS_IMG_DL	BIT(0)
#define PRESTERA_LDR_STATUS_START_FW	BIT(1)
#define PRESTERA_LDR_STATUS_INVALID_IMG	BIT(2)
#define PRESTERA_LDR_STATUS_NOMEM	BIT(3)

#define prestera_ldr_write(fw, reg, val) \
	writel(val, (fw)->ldr_regs + (reg))
#define prestera_ldr_read(fw, reg)	\
	readl((fw)->ldr_regs + (reg))

/* fw loader registers */
#define PRESTERA_LDR_READY_REG		PRESTERA_LDR_REG_OFFSET(ldr_ready)
#define PRESTERA_LDR_IMG_SIZE_REG	PRESTERA_LDR_REG_OFFSET(ldr_img_size)
#define PRESTERA_LDR_CTL_REG		PRESTERA_LDR_REG_OFFSET(ldr_ctl_flags)
#define PRESTERA_LDR_BUF_SIZE_REG	PRESTERA_LDR_REG_OFFSET(ldr_buf_size)
#define PRESTERA_LDR_BUF_OFFS_REG	PRESTERA_LDR_REG_OFFSET(ldr_buf_offs)
#define PRESTERA_LDR_BUF_RD_REG		PRESTERA_LDR_REG_OFFSET(ldr_buf_rd)
#define PRESTERA_LDR_BUF_WR_REG		PRESTERA_LDR_REG_OFFSET(ldr_buf_wr)
#define PRESTERA_LDR_STATUS_REG		PRESTERA_LDR_REG_OFFSET(ldr_status)

#define PRESTERA_LDR_CTL_DL_START	BIT(0)

#define PRESTERA_LDR_WR_IDX_MOVE(fw, n) \
do { \
	typeof(fw) __fw = (fw); \
	(__fw)->ldr_wr_idx = ((__fw)->ldr_wr_idx + (n)) & \
				((__fw)->ldr_buf_len - 1); \
} while (0)

#define PRESTERA_LDR_WR_IDX_COMMIT(fw) \
({ \
	typeof(fw) __fw = (fw); \
	prestera_ldr_write((__fw), PRESTERA_LDR_BUF_WR_REG, \
			   (__fw)->ldr_wr_idx); \
})

#define PRESTERA_LDR_WR_PTR(fw) \
({ \
	typeof(fw) __fw = (fw); \
	((__fw)->ldr_ring_buf + (__fw)->ldr_wr_idx); \
})

#define PRESTERA_EVT_QNUM_MAX	4

struct prestera_fw_evtq_regs {
	u32 rd_idx;
	u32 pad1;
	u32 wr_idx;
	u32 pad2;
	u32 offs;
	u32 len;
};

#define PRESTERA_CMD_QNUM_MAX	4

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

#define PRESTERA_FW_REG_OFFSET(f)	offsetof(struct prestera_fw_regs, f)

#define PRESTERA_FW_READY_MAGIC	0xcafebabe

/* fw registers */
#define PRESTERA_FW_READY_REG		PRESTERA_FW_REG_OFFSET(fw_ready)

#define PRESTERA_CMDQ_REG_OFFSET(q, f)			\
	(PRESTERA_FW_REG_OFFSET(cmdq_list) +		\
	 (q) * sizeof(struct prestera_fw_cmdq_regs) +	\
	 offsetof(struct prestera_fw_cmdq_regs, f))

#define PRESTERA_CMD_BUF_OFFS_REG	PRESTERA_FW_REG_OFFSET(cmd_offs)
#define PRESTERA_CMD_BUF_LEN_REG	PRESTERA_FW_REG_OFFSET(cmd_len)
#define PRESTERA_CMD_QNUM_REG		PRESTERA_FW_REG_OFFSET(cmd_qnum)
#define PRESTERA_EVT_BUF_OFFS_REG	PRESTERA_FW_REG_OFFSET(evt_offs)
#define PRESTERA_EVT_QNUM_REG		PRESTERA_FW_REG_OFFSET(evt_qnum)

#define PRESTERA_CMDQ_REQ_CTL_REG(q)	PRESTERA_CMDQ_REG_OFFSET(q, cmd_req_ctl)
#define PRESTERA_CMDQ_REQ_LEN_REG(q)	PRESTERA_CMDQ_REG_OFFSET(q, cmd_req_len)
#define PRESTERA_CMDQ_RCV_CTL_REG(q)	PRESTERA_CMDQ_REG_OFFSET(q, cmd_rcv_ctl)
#define PRESTERA_CMDQ_RCV_LEN_REG(q)	PRESTERA_CMDQ_REG_OFFSET(q, cmd_rcv_len)
#define PRESTERA_CMDQ_OFFS_REG(q)	PRESTERA_CMDQ_REG_OFFSET(q, offs)
#define PRESTERA_CMDQ_LEN_REG(q)	PRESTERA_CMDQ_REG_OFFSET(q, len)

#define PRESTERA_FW_STATUS_REG		PRESTERA_FW_REG_OFFSET(fw_status)
#define PRESTERA_RX_STATUS_REG		PRESTERA_FW_REG_OFFSET(rx_status)

/* PRESTERA_CMDQ_REQ_CTL_REG flags */
#define PRESTERA_CMD_F_REQ_SENT		BIT(0)
#define PRESTERA_CMD_F_REPL_RCVD	BIT(1)

/* PRESTERA_CMDQ_RCV_CTL_REG flags */
#define PRESTERA_CMD_F_REPL_SENT	BIT(0)

/* PRESTERA_FW_STATUS_REG flags */
#define PRESTERA_STATUS_F_EVT_OFF	BIT(0)

#define PRESTERA_EVTQ_REG_OFFSET(q, f)			\
	(PRESTERA_FW_REG_OFFSET(evtq_list) +		\
	 (q) * sizeof(struct prestera_fw_evtq_regs) +	\
	 offsetof(struct prestera_fw_evtq_regs, f))

#define PRESTERA_EVTQ_RD_IDX_REG(q)	PRESTERA_EVTQ_REG_OFFSET(q, rd_idx)
#define PRESTERA_EVTQ_WR_IDX_REG(q)	PRESTERA_EVTQ_REG_OFFSET(q, wr_idx)
#define PRESTERA_EVTQ_OFFS_REG(q)	PRESTERA_EVTQ_REG_OFFSET(q, offs)
#define PRESTERA_EVTQ_LEN_REG(q)	PRESTERA_EVTQ_REG_OFFSET(q, len)

#define prestera_fw_write(fw, reg, val)	writel(val, (fw)->hw_regs + (reg))
#define prestera_fw_read(fw, reg)	readl((fw)->hw_regs + (reg))

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

#define prestera_fw_dev(fw)	((fw)->dev.dev)

#define PRESTERA_DEVICE(id) PCI_VDEVICE(MARVELL, (id))

#define PRESTERA_DEV_ID_AC3X_98DX_55	0xC804
#define PRESTERA_DEV_ID_AC3X_98DX_65	0xC80C
#define PRESTERA_DEV_ID_ALDRIN2		0xCC1E
#define PRESTERA_DEV_ID_ALDRIN3S	0x981F
#define PRESTERA_DEV_ID_98DX3500	0x9820

static struct prestera_pci_match {
	struct pci_driver driver;
	const struct pci_device_id id;
	bool registered;
} prestera_devices[] = {
	{
		.driver = { .name = "AC3x B2B 98DX3255", },
		.id = { PRESTERA_DEVICE(PRESTERA_DEV_ID_AC3X_98DX_55), 0 },
	},
	{
		.driver = { .name = "AC3x B2B 98DX3265", },
		.id = { PRESTERA_DEVICE(PRESTERA_DEV_ID_AC3X_98DX_65), 0 },
	},
	{
		.driver = { .name = "Aldrin2", },
		.id = { PRESTERA_DEVICE(PRESTERA_DEV_ID_ALDRIN2), 0 },
	},
	{
		.driver = { .name = "Aldrin3S", },
		.id = { PRESTERA_DEVICE(PRESTERA_DEV_ID_ALDRIN3S), 0 },
	},
	{
		.driver = { .name = "AC5X 98DX3500", },
		.id = { PRESTERA_DEVICE(PRESTERA_DEV_ID_98DX3500), 0 },
	},
	{{ }, }
};

static int prestera_fw_load(struct prestera_fw *fw);

static void prestera_fw_cmdq_lock(struct prestera_fw *fw, u8 qid)
{
	mutex_lock(&fw->cmd_queue[qid].cmd_mtx);
}

static void prestera_fw_cmdq_unlock(struct prestera_fw *fw, u8 qid)
{
	mutex_unlock(&fw->cmd_queue[qid].cmd_mtx);
}

static u32 prestera_fw_cmdq_len(struct prestera_fw *fw, u8 qid)
{
	return fw->cmd_queue[qid].len;
}

static u8 __iomem *prestera_fw_cmdq_buf(struct prestera_fw *fw, u8 qid)
{
	return fw->cmd_queue[qid].addr;
}

static u32 prestera_fw_evtq_len(struct prestera_fw *fw, u8 qid)
{
	return fw->evt_queue[qid].len;
}

static u32 prestera_fw_evtq_avail(struct prestera_fw *fw, u8 qid)
{
	u32 wr_idx = prestera_fw_read(fw, PRESTERA_EVTQ_WR_IDX_REG(qid));
	u32 rd_idx = prestera_fw_read(fw, PRESTERA_EVTQ_RD_IDX_REG(qid));

	return CIRC_CNT(wr_idx, rd_idx, prestera_fw_evtq_len(fw, qid));
}

static void prestera_fw_evtq_rd_set(struct prestera_fw *fw, u8 qid, u32 idx)
{
	u32 rd_idx = idx & (prestera_fw_evtq_len(fw, qid) - 1);

	prestera_fw_write(fw, PRESTERA_EVTQ_RD_IDX_REG(qid), rd_idx);
}

static u8 __iomem *prestera_fw_evtq_buf(struct prestera_fw *fw, u8 qid)
{
	return fw->evt_queue[qid].addr;
}

static u32 prestera_fw_evtq_read32(struct prestera_fw *fw, u8 qid)
{
	u32 rd_idx = prestera_fw_read(fw, PRESTERA_EVTQ_RD_IDX_REG(qid));
	u32 val;

	val = readl(prestera_fw_evtq_buf(fw, qid) + rd_idx);
	prestera_fw_evtq_rd_set(fw, qid, rd_idx + 4);
	return val;
}

static ssize_t prestera_fw_evtq_read_buf(struct prestera_fw *fw, u8 qid,
					 u8 *buf, size_t len)
{
	u32 idx = prestera_fw_read(fw, PRESTERA_EVTQ_RD_IDX_REG(qid));
	u8 __iomem *evtq_addr = prestera_fw_evtq_buf(fw, qid);
	u32 *buf32 = (u32 *)buf;
	int i;

	for (i = 0; i < len / 4; buf32++, i++) {
		*buf32 = readl_relaxed(evtq_addr + idx);
		idx = (idx + 4) & (prestera_fw_evtq_len(fw, qid) - 1);
	}

	prestera_fw_evtq_rd_set(fw, qid, idx);

	return i;
}

static u8 prestera_fw_evtq_pick(struct prestera_fw *fw)
{
	int qid;

	for (qid = 0; qid < fw->evt_qnum; qid++) {
		if (prestera_fw_evtq_avail(fw, qid) >= 4)
			return qid;
	}

	return PRESTERA_EVT_QNUM_MAX;
}

static void prestera_fw_status_set(struct prestera_fw *fw, unsigned int val)
{
	u32 status = prestera_fw_read(fw, PRESTERA_FW_STATUS_REG);

	status |= val;

	prestera_fw_write(fw, PRESTERA_FW_STATUS_REG, status);
}

static void prestera_fw_status_clear(struct prestera_fw *fw, u32 val)
{
	u32 status = prestera_fw_read(fw, PRESTERA_FW_STATUS_REG);

	status &= ~val;

	prestera_fw_write(fw, PRESTERA_FW_STATUS_REG, status);
}

static void prestera_fw_evt_work_fn(struct work_struct *work)
{
	struct prestera_fw *fw;
	u8 *msg;
	u8 qid;

	fw = container_of(work, struct prestera_fw, evt_work);
	msg = fw->evt_msg;

	prestera_fw_status_set(fw, PRESTERA_STATUS_F_EVT_OFF);

	while ((qid = prestera_fw_evtq_pick(fw)) < PRESTERA_EVT_QNUM_MAX) {
		u32 idx;
		u32 len;

		len = prestera_fw_evtq_read32(fw, qid);
		idx = prestera_fw_read(fw, PRESTERA_EVTQ_RD_IDX_REG(qid));

		WARN_ON(prestera_fw_evtq_avail(fw, qid) < len);

		if (WARN_ON(len > PRESTERA_MSG_MAX_SIZE)) {
			prestera_fw_evtq_rd_set(fw, qid, idx + len);
			continue;
		}

		prestera_fw_evtq_read_buf(fw, qid, msg, len);

		if (fw->dev.recv_msg)
			fw->dev.recv_msg(&fw->dev, msg, len);
	}

	prestera_fw_status_clear(fw, PRESTERA_STATUS_F_EVT_OFF);
}

static int prestera_fw_wait_reg32(struct prestera_fw *fw, u32 reg, u32 val,
				  unsigned int wait)
{
	if (prestera_wait(prestera_fw_read(fw, reg) == val || !fw->dev.running,
			  wait))
		return fw->dev.running ? 0 : -ENODEV;

	return -EBUSY;
}

static void prestera_pci_copy_to(u8 __iomem *dst, u8 *src, size_t len)
{
	u32 __iomem *dst32 = (u32 __iomem *)dst;
	u32 *src32 = (u32 *)src;
	int i;

	for (i = 0; i < (len / 4); dst32++, src32++, i++)
		writel_relaxed(*src32, dst32);
}

static void prestera_pci_copy_from(u8 *dst, u8 __iomem *src, size_t len)
{
	u32 *dst32 = (u32 *)dst;
	u32 __iomem *src32 = (u32 __iomem *)src;
	int i;

	for (i = 0; i < (len / 4); dst32++, src32++, i++)
		*dst32 = readl_relaxed(src32);
}

static int prestera_fw_cmd_send(struct prestera_fw *fw, int qid,
				u8 *in_msg, size_t in_size,
				u8 *out_msg, size_t out_size,
				unsigned int wait)
{
	u32 ret_size = 0;
	int err = 0;

	if (!wait)
		wait = 30000;

	if (ALIGN(in_size, 4) > prestera_fw_cmdq_len(fw, qid))
		return -EMSGSIZE;

	/* wait for finish previous reply from FW */
	err = prestera_fw_wait_reg32(fw, PRESTERA_CMDQ_RCV_CTL_REG(qid),
				     0, 1000);
	if (err) {
		dev_err(prestera_fw_dev(fw),
			"finish reply from FW is timed out\n");
		return err;
	}

	prestera_fw_write(fw, PRESTERA_CMDQ_REQ_LEN_REG(qid), in_size);
	prestera_pci_copy_to(prestera_fw_cmdq_buf(fw, qid), in_msg, in_size);

	prestera_fw_write(fw, PRESTERA_CMDQ_REQ_CTL_REG(qid),
			  PRESTERA_CMD_F_REQ_SENT);

	/* wait for reply from FW */
	err = prestera_fw_wait_reg32(fw, PRESTERA_CMDQ_RCV_CTL_REG(qid),
				     PRESTERA_CMD_F_REPL_SENT, wait);
	if (err) {
		dev_err(prestera_fw_dev(fw),
			"reply from FW is timed out\n");
		goto cmd_exit;
	}

	ret_size = prestera_fw_read(fw, PRESTERA_CMDQ_RCV_LEN_REG(qid));
	if (ret_size > out_size) {
		dev_err(prestera_fw_dev(fw), "ret_size (%u) > out_len(%zu)\n",
			ret_size, out_size);
		err = -EMSGSIZE;
		goto cmd_exit;
	}

	prestera_pci_copy_from(out_msg, prestera_fw_cmdq_buf(fw, qid) + in_size,
			       ret_size);

cmd_exit:
	prestera_fw_write(fw, PRESTERA_CMDQ_REQ_CTL_REG(qid),
			  PRESTERA_CMD_F_REPL_RCVD);
	return err;
}

static int prestera_fw_send_req(struct prestera_device *dev, int qid,
				u8 *in_msg, size_t in_size, u8 *out_msg,
				size_t out_size, unsigned int wait)
{
	struct prestera_fw *fw;
	ssize_t ret;

	fw = container_of(dev, struct prestera_fw, dev);

	if (!fw->dev.running)
		return -ENODEV;

	prestera_fw_cmdq_lock(fw, qid);
	ret = prestera_fw_cmd_send(fw, qid, in_msg, in_size, out_msg, out_size,
				   wait);
	prestera_fw_cmdq_unlock(fw, qid);

	return ret;
}

static int prestera_fw_init(struct prestera_fw *fw)
{
	u8 __iomem *base;
	int err;
	u8 qid;

	err = prestera_fw_load(fw);
	if (err)
		return err;

	err = prestera_fw_wait_reg32(fw, PRESTERA_FW_READY_REG,
				     PRESTERA_FW_READY_MAGIC, 20000);
	if (err) {
		dev_err(prestera_fw_dev(fw), "FW is failed to start\n");
		return err;
	}

	base = fw->mem_addr;

	fw->cmd_mbox = base + prestera_fw_read(fw, PRESTERA_CMD_BUF_OFFS_REG);
	fw->cmd_mbox_len = prestera_fw_read(fw, PRESTERA_CMD_BUF_LEN_REG);
	fw->cmd_qnum = prestera_fw_read(fw, PRESTERA_CMD_QNUM_REG);

	for (qid = 0; qid < fw->cmd_qnum; qid++) {
		u32 offs = prestera_fw_read(fw, PRESTERA_CMDQ_OFFS_REG(qid));
		struct prestera_fw_cmdq *cmdq = &fw->cmd_queue[qid];

		cmdq->len = prestera_fw_read(fw, PRESTERA_CMDQ_LEN_REG(qid));
		cmdq->addr = fw->cmd_mbox + offs;
		mutex_init(&cmdq->cmd_mtx);
	}

	fw->evt_buf = base + prestera_fw_read(fw, PRESTERA_EVT_BUF_OFFS_REG);
	fw->evt_qnum = prestera_fw_read(fw, PRESTERA_EVT_QNUM_REG);
	fw->evt_msg = kmalloc(PRESTERA_MSG_MAX_SIZE, GFP_KERNEL);
	if (!fw->evt_msg)
		return -ENOMEM;

	for (qid = 0; qid < fw->evt_qnum; qid++) {
		u32 offs = prestera_fw_read(fw, PRESTERA_EVTQ_OFFS_REG(qid));
		struct prestera_fw_evtq *evtq = &fw->evt_queue[qid];

		evtq->len = prestera_fw_read(fw, PRESTERA_EVTQ_LEN_REG(qid));
		evtq->addr = fw->evt_buf + offs;
	}

	return 0;
}

static void prestera_fw_uninit(struct prestera_fw *fw)
{
	kfree(fw->evt_msg);
}

static irqreturn_t prestera_irq_handler(int irq, void *dev_id)
{
	struct prestera_fw *fw = dev_id;

	if (prestera_fw_read(fw, PRESTERA_RX_STATUS_REG)) {
		if (fw->dev.recv_pkt) {
			prestera_fw_write(fw, PRESTERA_RX_STATUS_REG, 0);
			fw->dev.recv_pkt(&fw->dev);
		}
	}

	queue_work(fw->wq, &fw->evt_work);

	return IRQ_HANDLED;
}

static int prestera_ldr_wait_reg32(struct prestera_fw *fw, u32 reg, u32 val,
				   unsigned int wait)
{
	if (prestera_wait(prestera_ldr_read(fw, reg) == val, wait))
		return 0;

	return -EBUSY;
}

static u32 prestera_ldr_buf_avail(struct prestera_fw *fw)
{
	u32 rd_idx = prestera_ldr_read(fw, PRESTERA_LDR_BUF_RD_REG);

	return CIRC_SPACE(fw->ldr_wr_idx, rd_idx, fw->ldr_buf_len);
}

static int prestera_ldr_send_buf(struct prestera_fw *fw, const u8 *buf,
				 size_t len)
{
	int i;

	if (!prestera_wait(prestera_ldr_buf_avail(fw) >= len, 100)) {
		dev_err(prestera_fw_dev(fw),
			"failed wait for sending firmware\n");
		return -EBUSY;
	}

	for (i = 0; i < len; i += 4) {
		writel_relaxed(*(u32 *)(buf + i), PRESTERA_LDR_WR_PTR(fw));
		PRESTERA_LDR_WR_IDX_MOVE(fw, 4);
	}

	PRESTERA_LDR_WR_IDX_COMMIT(fw);
	return 0;
}

static int prestera_ldr_send(struct prestera_fw *fw, const char *img,
			     u32 fw_size)
{
	unsigned long mask;
	u32 status;
	u32 pos;
	int err;

	if (prestera_ldr_wait_reg32(fw, PRESTERA_LDR_STATUS_REG,
				    PRESTERA_LDR_STATUS_IMG_DL, 1000)) {
		dev_err(prestera_fw_dev(fw),
			"Loader is not ready to load image\n");
		return -EBUSY;
	}

	for (pos = 0; pos < fw_size; pos += PRESTERA_FW_BLK_SZ) {
		if (pos + PRESTERA_FW_BLK_SZ > fw_size)
			break;

		err = prestera_ldr_send_buf(fw, img + pos, PRESTERA_FW_BLK_SZ);
		if (err) {
			if (prestera_fw_read(fw, PRESTERA_LDR_STATUS_REG) ==
					     PRESTERA_LDR_STATUS_NOMEM) {
				dev_err(prestera_fw_dev(fw),
					"Fw image is too big or invalid\n");
				return -EINVAL;
			}
			return err;
		}
	}

	if (pos < fw_size) {
		err = prestera_ldr_send_buf(fw, img + pos, fw_size - pos);
		if (err)
			return err;
	}

	/* Waiting for status IMG_DOWNLOADING to change to something else */
	mask = ~(PRESTERA_LDR_STATUS_IMG_DL);

	if (!prestera_wait(prestera_ldr_read(fw, PRESTERA_LDR_STATUS_REG) &
			   mask, PRESTERA_FW_DL_TIMEOUT)) {
		dev_err(prestera_fw_dev(fw),
			"Timeout to load FW img [state=%d]",
			prestera_ldr_read(fw, PRESTERA_LDR_STATUS_REG));
		return -ETIMEDOUT;
	}

	status = prestera_ldr_read(fw, PRESTERA_LDR_STATUS_REG);
	if (status != PRESTERA_LDR_STATUS_START_FW) {
		switch (status) {
		case PRESTERA_LDR_STATUS_INVALID_IMG:
			dev_err(prestera_fw_dev(fw), "FW img has bad crc\n");
			return -EINVAL;
		case PRESTERA_LDR_STATUS_NOMEM:
			dev_err(prestera_fw_dev(fw),
				"Loader has no enough mem\n");
			return -ENOMEM;
		default:
			break;
		}
	}

	return 0;
}

static bool prestera_ldr_is_ready(struct prestera_fw *fw)
{
	return prestera_ldr_read(fw, PRESTERA_LDR_READY_REG) ==
				 PRESTERA_LDR_READY_MAGIC;
}

static void prestera_fw_rev_parse(const struct prestera_fw_header *hdr,
				  struct prestera_fw_rev *rev)
{
	u32 version = be32_to_cpu(hdr->version_value);

	rev->maj = FW_VER_MAJ(version);
	rev->min = FW_VER_MIN(version);
	rev->sub = FW_VER_PATCH(version);
}

static int prestera_fw_rev_check(struct prestera_fw *fw)
{
	struct prestera_fw_rev *rev = &fw->dev.fw_rev;

	if (rev->maj == PRESTERA_SUPP_FW_MAJ_VER &&
	    rev->min == PRESTERA_SUPP_FW_MIN_VER) {
		return 0;
	}

	return -EINVAL;
}

static int prestera_fw_hdr_parse(struct prestera_fw *fw,
				 const struct firmware *img)
{
	struct prestera_fw_header *hdr = (struct prestera_fw_header *)img->data;
	struct prestera_fw_rev *rev = &fw->dev.fw_rev;
	u32 magic;

	magic = be32_to_cpu(hdr->magic_number);
	if (magic != PRESTERA_FW_HDR_MAGIC) {
		dev_err(prestera_fw_dev(fw), "FW img type is invalid");
		return -EINVAL;
	}

	prestera_fw_rev_parse(hdr, rev);

	dev_info(prestera_fw_dev(fw), "FW version '%u.%u.%u'\n",
		 rev->maj, rev->min, rev->sub);
	dev_info(prestera_fw_dev(fw), "Driver version '%u.%u.%u'\n",
		 PRESTERA_SUPP_FW_MAJ_VER, PRESTERA_SUPP_FW_MIN_VER,
		 PRESTERA_SUPP_FW_PATCH_VER);

	if (prestera_fw_rev_check(fw)) {
		dev_err(prestera_fw_dev(fw),
			"Driver is incomatible with FW: version mismatch");
		return -EINVAL;
	}

	return 0;
}

static const char *prestera_fw_path_get(struct prestera_fw *fw)
{
	switch (fw->pci_dev->device) {
	case PRESTERA_DEV_ID_98DX3500:
		return PRESTERA_FW_ARM64_PATH;

	default:
		return PRESTERA_FW_DEFAULT_PATH;
	}
}

static int prestera_fw_load(struct prestera_fw *fw)
{
	size_t hlen = sizeof(struct prestera_fw_header);
	const char *fw_path = prestera_fw_path_get(fw);
	const struct firmware *f;
	bool has_ldr;
	int err;

	/* 10s delay is required for soft reset feature */
	has_ldr = prestera_wait(prestera_ldr_is_ready(fw), 15000);
	if (!has_ldr) {
		dev_err(prestera_fw_dev(fw),
			"waiting for FW loader is timed out");
		return -ETIMEDOUT;
	}

	fw->ldr_ring_buf = fw->ldr_regs +
		prestera_ldr_read(fw, PRESTERA_LDR_BUF_OFFS_REG);

	fw->ldr_buf_len = prestera_ldr_read(fw, PRESTERA_LDR_BUF_SIZE_REG);

	fw->ldr_wr_idx = 0;

	err = request_firmware_direct(&f, fw_path, &fw->pci_dev->dev);
	if (err) {
		dev_err(prestera_fw_dev(fw),
			"failed to request firmware file: %s\n", fw_path);
		return err;
	}

	if (!IS_ALIGNED(f->size, 4)) {
		dev_err(prestera_fw_dev(fw), "FW image file is not aligned");
		release_firmware(f);
		return -EINVAL;
	}

	err = prestera_fw_hdr_parse(fw, f);
	if (err) {
		dev_err(prestera_fw_dev(fw), "FW image is invalid\n");
		release_firmware(f);
		return err;
	}

	prestera_ldr_write(fw, PRESTERA_LDR_IMG_SIZE_REG, f->size - hlen);
	prestera_ldr_write(fw, PRESTERA_LDR_CTL_REG, PRESTERA_LDR_CTL_DL_START);

	dev_info(prestera_fw_dev(fw), "Loading prestera FW image ...");

	err = prestera_ldr_send(fw, f->data + hlen, f->size - hlen);

	release_firmware(f);
	return err;
}

static bool prestera_pci_pp_use_bar2(struct pci_dev *pdev)
{
	switch (pdev->device) {
	case PRESTERA_DEV_ID_ALDRIN3S:
	case PRESTERA_DEV_ID_98DX3500:
		return true;

	default:
		return false;
	}
}

static int prestera_pci_probe(struct pci_dev *pdev,
			      const struct pci_device_id *id)
{
	const char *driver_name = pdev->driver->name;
	u8 __iomem *mem_addr, *pp_addr = NULL;
	struct prestera_fw *fw;
	int err;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "pci_enable_device failed\n");
		goto err_pci_enable_device;
	}

	err = pci_request_regions(pdev, driver_name);
	if (err) {
		dev_err(&pdev->dev, "pci_request_regions failed\n");
		goto err_pci_request_regions;
	}

	if (dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(30))) {
		dev_err(&pdev->dev, "fail to set DMA mask\n");
		goto err_dma_mask;
	}

	mem_addr = pcim_iomap(pdev, 2, 0);
	if (!mem_addr) {
		dev_err(&pdev->dev, "pci mem ioremap failed\n");
		err = -EIO;
		goto err_mem_ioremap;
	}

	/* Aldrin3S uses second half of BAR2 */
	if (prestera_pci_pp_use_bar2(pdev)) {
		pp_addr = mem_addr + pci_resource_len(pdev, 2) / 2;
	} else {
		pp_addr = pcim_iomap(pdev, 4, 0);
		if (!pp_addr) {
			dev_err(&pdev->dev, "pp regs ioremap failed\n");
			err = -EIO;
			goto err_pp_ioremap;
		}
	}

	pci_set_master(pdev);

	fw = kzalloc(sizeof(*fw), GFP_KERNEL);
	if (!fw) {
		err = -ENOMEM;
		goto err_pci_dev_alloc;
	}

	fw->pci_dev = pdev;
	fw->dev.dev = &pdev->dev;
	fw->dev.send_req = prestera_fw_send_req;
	fw->dev.pp_regs = pp_addr;
	fw->dev.running = true;
	fw->mem_addr = mem_addr;
	fw->ldr_regs = mem_addr;
	fw->hw_regs = mem_addr;

	fw->wq = alloc_workqueue("prestera_fw_wq", WQ_HIGHPRI, 1);
	if (!fw->wq)
		goto err_wq_alloc;

	INIT_WORK(&fw->evt_work, prestera_fw_evt_work_fn);

	err = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSI);
	if (err < 0) {
		dev_err(&pdev->dev, "MSI IRQ init failed\n");
		goto err_irq_alloc;
	}

	pci_set_drvdata(pdev, fw);

	err = prestera_fw_init(fw);
	if (err)
		goto err_fw_init;

	err = request_irq(pci_irq_vector(pdev, 0), prestera_irq_handler,
			  0, driver_name, fw);
	if (err) {
		dev_err(&pdev->dev, "fail to request IRQ\n");
		goto err_request_irq;
	}

	dev_info(prestera_fw_dev(fw), "Prestera Switch FW is ready\n");

	err = prestera_device_register(&fw->dev);
	if (err)
		goto err_prestera_dev_register;

	return 0;

err_prestera_dev_register:
	free_irq(pci_irq_vector(pdev, 0), fw);
err_request_irq:
	prestera_fw_uninit(fw);
err_fw_init:
	pci_free_irq_vectors(pdev);
err_irq_alloc:
	destroy_workqueue(fw->wq);
err_wq_alloc:
	kfree(fw);
err_pci_dev_alloc:
err_pp_ioremap:
err_mem_ioremap:
err_dma_mask:
	pci_release_regions(pdev);
err_pci_request_regions:
	pci_disable_device(pdev);
err_pci_enable_device:
	return err;
}

static void prestera_pci_remove(struct pci_dev *pdev)
{
	struct prestera_fw *fw = pci_get_drvdata(pdev);

	free_irq(pci_irq_vector(pdev, 0), fw);
	pci_free_irq_vectors(pdev);
	prestera_device_unregister(&fw->dev);
	flush_workqueue(fw->wq);
	destroy_workqueue(fw->wq);
	prestera_fw_uninit(fw);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	kfree(fw);
}

static int __init prestera_pci_init(void)
{
	struct prestera_pci_match *match;
	int err = 0;

	for (match = prestera_devices; match->driver.name; match++) {
		match->driver.probe = prestera_pci_probe;
		match->driver.remove = prestera_pci_remove;
		match->driver.id_table = &match->id;

		err = pci_register_driver(&match->driver);
		if (err) {
			pr_err("prestera_pci: failed to register %s\n",
			       match->driver.name);
			break;
		}

		match->registered = true;
	}

	if (err) {
		for (match = prestera_devices; match->driver.name; match++) {
			if (!match->registered)
				break;

			pci_unregister_driver(&match->driver);
		}

		return err;
	}

	pr_info("prestera_pci: Registered Marvell Prestera PCI driver\n");
	return 0;
}

static void __exit prestera_pci_exit(void)
{
	struct prestera_pci_match *match;

	for (match = prestera_devices; match->driver.name; match++) {
		if (!match->registered)
			break;

		pci_unregister_driver(&match->driver);
	}

	pr_info("prestera_pci: Unregistered Marvell Prestera PCI driver\n");
}

module_init(prestera_pci_init);
module_exit(prestera_pci_exit);

MODULE_AUTHOR("Marvell Semi.");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Marvell Prestera switch PCI interface");
