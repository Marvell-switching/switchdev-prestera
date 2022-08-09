// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/circ_buf.h>
#include <linux/firmware.h>

#include "prestera.h"
#include "prestera_fw.h"

#define PRESTERA_FW_DEFAULT_PATH	"marvell/mvsw_prestera_fw.img"
#define PRESTERA_FW_ARM64_PATH		"marvell/mvsw_prestera_fw_arm64.img"

#define PRESTERA_FW_HDR_MAGIC	0x351D9D06
#define PRESTERA_FW_DL_TIMEOUT	50000
#define PRESTERA_FW_BLK_SZ	1024

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

#define PRESTERA_DEVICE(id) PCI_VDEVICE(MARVELL, (id))

#define PRESTERA_DEV_ID_AC3X_98DX_55	0xC804
#define PRESTERA_DEV_ID_AC3X_98DX_65	0xC80C
#define PRESTERA_DEV_ID_ALDRIN2		0xCC1E
#define PRESTERA_DEV_ID_ALDRIN3S	0x981F
#define PRESTERA_DEV_ID_98DX3500	0x9820
#define PRESTERA_DEV_ID_98DX3501	0x9826
#define PRESTERA_DEV_ID_98DX3510	0x9821
#define PRESTERA_DEV_ID_98DX3520	0x9822

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
	{
		.driver = { .name = "AC5X 98DX3501", },
		.id = { PRESTERA_DEVICE(PRESTERA_DEV_ID_98DX3501), 0 },
	},
	{
		.driver = { .name = "AC5X 98DX3510", },
		.id = { PRESTERA_DEVICE(PRESTERA_DEV_ID_98DX3510), 0 },
	},
	{
		.driver = { .name = "AC5X 98DX3520", },
		.id = { PRESTERA_DEVICE(PRESTERA_DEV_ID_98DX3520), 0 },
	},
	{{ }, }
};

static int prestera_fw_load(struct prestera_fw *fw);

static irqreturn_t prestera_irq_handler(int irq, void *dev_id)
{
	struct prestera_fw *fw = dev_id;

	if (prestera_fw_read(fw, PRESTERA_RX_STATUS_REG)) {
		if (fw->dev.recv_pkt) {
			prestera_fw_write(fw, PRESTERA_RX_STATUS_REG, 0);
			fw->dev.recv_pkt(&fw->dev);
		}
	}

	prestera_fw_queue_work(fw);

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

	return prestera_fw_rev_check(fw);
}

static const char *prestera_fw_path_get(struct prestera_fw *fw)
{
	switch (fw->pci_dev->device) {
	case PRESTERA_DEV_ID_98DX3500:
	case PRESTERA_DEV_ID_98DX3501:
	case PRESTERA_DEV_ID_98DX3510:
	case PRESTERA_DEV_ID_98DX3520:
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
	case PRESTERA_DEV_ID_98DX3501:
	case PRESTERA_DEV_ID_98DX3510:
	case PRESTERA_DEV_ID_98DX3520:
		return true;

	default:
		return false;
	}
}

static u32 prestera_pci_pp_bar2_offs(struct pci_dev *pdev)
{
	if (pci_resource_len(pdev, 2) == 0x1000000)
		return 0x0;
	else
		return (pci_resource_len(pdev, 2) / 2);
}

static u32 prestera_pci_fw_bar2_offs(struct pci_dev *pdev)
{
	if (pci_resource_len(pdev, 2) == 0x1000000)
		return 0x400000;
	else
		return 0x0;
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
		pp_addr = mem_addr + prestera_pci_pp_bar2_offs(pdev);
		mem_addr = mem_addr + prestera_pci_fw_bar2_offs(pdev);
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
	fw->dev.dma_flags = GFP_DMA;
	fw->dev.running = true;
	fw->mem_addr = mem_addr;
	fw->ldr_regs = mem_addr;
	fw->hw_regs = mem_addr;

	err = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSI);
	if (err < 0) {
		dev_err(&pdev->dev, "MSI IRQ init failed\n");
		goto err_irq_alloc;
	}

	pci_set_drvdata(pdev, fw);

	err = prestera_fw_load(fw);

	if (err)
		goto err_fw_init;

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
