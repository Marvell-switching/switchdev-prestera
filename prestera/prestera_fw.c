// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/circ_buf.h>

#include "prestera.h"
#include "prestera_fw.h"

#define PRESTERA_FW_READY_MAGIC	0xcafebabe

/* Firmware registers: */
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

#define FW_VER_MAJ_MUL 1000000
#define FW_VER_MIN_MUL 1000

static int fw_ver_maj(int v)
{
	return ((v) / FW_VER_MAJ_MUL);
}

static int fw_ver_min(int v)
{
	int vv = fw_ver_maj(v) * FW_VER_MAJ_MUL;

	return (((v) - vv) / FW_VER_MIN_MUL);
}

static int fw_ver_patch(int v)
{
	int vv, vvv;

	vv = (fw_ver_maj(v) * FW_VER_MAJ_MUL);
	vvv = (fw_ver_min(v) * FW_VER_MIN_MUL);
	return ((v) - vv - vvv);
}

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

void prestera_fw_handle_event(struct prestera_fw *fw)
{
	u8 *msg;
	u8 qid;

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
EXPORT_SYMBOL(prestera_fw_handle_event);

static void prestera_fw_evt_work_fn(struct work_struct *work)
{
	struct prestera_fw *fw;

	fw = container_of(work, struct prestera_fw, evt_work);

	prestera_fw_handle_event(fw);
}

void prestera_fw_queue_work(struct prestera_fw *fw)
{
	queue_work(fw->wq, &fw->evt_work);
}
EXPORT_SYMBOL(prestera_fw_queue_work);

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

int prestera_fw_send_req(struct prestera_device *pr_dev, int qid,
			 u8 *in_msg, size_t in_size, u8 *out_msg,
			 size_t out_size, unsigned int wait)
{
	struct prestera_fw *fw;
	ssize_t ret;

	fw = container_of(pr_dev, struct prestera_fw, dev);

	if (!fw->dev.running)
		return -ENODEV;

	prestera_fw_cmdq_lock(fw, qid);
	ret = prestera_fw_cmd_send(fw, qid, in_msg, in_size, out_msg, out_size,
				   wait);
	prestera_fw_cmdq_unlock(fw, qid);

	return ret;
}
EXPORT_SYMBOL_GPL(prestera_fw_send_req);

int prestera_fw_rev_check(struct prestera_fw *fw)
{
	struct prestera_fw_rev *rev = &fw->dev.fw_rev;

	dev_info(prestera_fw_dev(fw), "FW version '%u.%u.%u'\n",
		 rev->maj, rev->min, rev->sub);
	dev_info(prestera_fw_dev(fw), "Driver version '%u.%u.%u'\n",
		 PRESTERA_SUPP_FW_MAJ_VER, PRESTERA_SUPP_FW_MIN_VER,
		 PRESTERA_SUPP_FW_PATCH_VER);

	if (rev->maj == PRESTERA_SUPP_FW_MAJ_VER &&
	    rev->min == PRESTERA_SUPP_FW_MIN_VER) {
		return 0;
	}

	dev_err(prestera_fw_dev(fw),
		"Driver is incomatible with FW: version mismatch");

	return -EINVAL;
}
EXPORT_SYMBOL_GPL(prestera_fw_rev_check);

void prestera_fw_rev_parse(const struct prestera_fw_header *hdr,
			   struct prestera_fw_rev *rev)
{
	u32 version = be32_to_cpu(hdr->version_value);

	rev->maj = fw_ver_maj(version);
	rev->min = fw_ver_min(version);
	rev->sub = fw_ver_patch(version);
}
EXPORT_SYMBOL_GPL(prestera_fw_rev_parse);

void prestera_fw_rev_parse_int(unsigned int firmware_version,
			       struct prestera_fw_rev *rev)
{
	u32 version = firmware_version;

	rev->maj = fw_ver_maj(version);
	rev->min = fw_ver_min(version);
	rev->sub = fw_ver_patch(version);
}
EXPORT_SYMBOL_GPL(prestera_fw_rev_parse_int);

int prestera_fw_init(struct prestera_fw *fw)
{
	u8 __iomem *base;
	int err;
	u8 qid;

	err = prestera_fw_wait_reg32(fw, PRESTERA_FW_READY_REG,
				     PRESTERA_FW_READY_MAGIC, 20000);
	if (err) {
		dev_err(prestera_fw_dev(fw), "FW failed to start\n");
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

	fw->wq = alloc_workqueue("prestera_fw_wq", WQ_HIGHPRI, 1);
	if (!fw->wq)
		goto err_wq_alloc;

	INIT_WORK(&fw->evt_work, prestera_fw_evt_work_fn);

	return 0;

err_wq_alloc:
	kfree(fw->evt_msg);
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(prestera_fw_init);

void prestera_fw_uninit(struct prestera_fw *fw)
{
	kfree(fw->evt_msg);
	flush_workqueue(fw->wq);
	destroy_workqueue(fw->wq);
}
EXPORT_SYMBOL_GPL(prestera_fw_uninit);

MODULE_AUTHOR("Marvell Semi.");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Marvell Prestera switch Firmware Agent interface");
