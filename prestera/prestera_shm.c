// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/cdev.h>
#include <linux/platform_device.h>
#include <linux/kfifo.h>
#include <linux/if_arp.h>
#include <linux/mmu_context.h>

#include "prestera.h"
#include "prestera_fw.h"
#include "prestera_shm.h"

#define PRESTERA_SW_SHM_DEV_NAME "prestera_shm"
#define PRESTERA_SHM_FIFO_SZ 128

#define SIM_SDMA_RX_QUEUE_DESC_REG(n)	(0x260C + (n) * 16)
#define SIM_SDMA_TX_QUEUE_DESC_REG	0x26C0
#define SIM_REG(x) ((phys_addr_t *)((char *)shm_dev->fw.dev.pp_regs + (x)))
#define SIM_REG_DEREF(x) (*(SIM_REG(x)))

struct prestera_shm_msg {
	int command;
	long arg;
};

struct prestera_shm_dev {
	struct device *dev_ptr;
	atomic_t pending_intr_cntr;
	wait_queue_head_t shm_queue;
	struct task_struct *shm_kthread;
	struct page *alloc_pages;
	phys_addr_t addr_phys;
	size_t size;
	struct prestera_fw fw;
	void __iomem *shm_mmap_memory;
	dev_t shm_cdev_ids;
	struct cdev shm_cdev;
	struct class *shm_class;
	struct task_struct *sim_kthread;
	struct net_device *net_dev;
	int initialized;
};

/*  Needed so devlink_nl_put_handle() won't crash trying to write NL attributes for bus name: */
static struct bus_type prestera_shm_bus_type = {
	.name		= "prestera_shm_bus",
};

/* Interface netdev name for simulation mode. When specified, enables simulation mode */
static char *sim_devname;

static netdev_tx_t prestera_shm_sim_netdev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	int i = 0;
	phys_addr_t pa;
	unsigned int *ulptr;
	unsigned char *dst_buf;
	struct prestera_shm_dev **pp_dev;
	struct prestera_shm_dev *shm_dev;

	pp_dev = (struct prestera_shm_dev **)netdev_priv(dev);
	shm_dev = *pp_dev;

	pa = SIM_REG_DEREF(SIM_SDMA_RX_QUEUE_DESC_REG(0));
	if (!pa) {
		/*
		 * We can either return NETDEV_TX_BUSY which will cause
		 * constant requeueing and ksoftirqd running constantly
		 * at 100% CPU (which causes appDemo initialization to fail)
		 * or just free the SKB and return OK.
		 */
		dev_kfree_skb(skb);
		dev->stats.tx_errors++;
		return NETDEV_TX_OK;
	}

	ulptr = phys_to_virt(pa);

	for (i = 0; ((i < 1000) && (ulptr[3])); i++) {
		if (*ulptr & 0x80000000) {
			/* found a ready buffer descriptor */
			dst_buf = phys_to_virt(ulptr[2]);
			skb_copy_bits(skb, 0, dst_buf, skb->len);
			ulptr[1] = skb->len << 16;
			*ulptr = 0x0C000000;
			dev->stats.tx_packets++;
			dev->stats.tx_bytes += skb->len;
			dev_kfree_skb(skb);

			return NETDEV_TX_OK;
		}
		pa = ulptr[3];
		if (!pa)
			break;
		ulptr = phys_to_virt(pa);
	}
	dev->stats.tx_errors++;
	return NETDEV_TX_BUSY;
}

static int prestera_shm_sim_set_mac_addr(struct net_device *dev, void *addr)
{
	eth_commit_mac_addr_change(dev, addr);
	return 0;
}

static const struct net_device_ops shm_sim_netdev_ops = {
	.ndo_start_xmit         = prestera_shm_sim_netdev_xmit,
	.ndo_set_mac_address	= prestera_shm_sim_set_mac_addr,
};

static int prestera_shm_sim_sdma(void *data)
{
	int i = 0;
	phys_addr_t pa;
	unsigned int len;
	unsigned int *ulptr;
	unsigned char *dst_buf;
	struct sk_buff *new_skb;
	struct prestera_shm_dev *shm_dev = (struct prestera_shm_dev *)data;

	while (!kthread_should_stop()) {
		/* Simulate SDMA TX path */
		pa = SIM_REG_DEREF(SIM_SDMA_TX_QUEUE_DESC_REG);
		if (!pa) {
			msleep(20);
			continue;
		}

		ulptr = phys_to_virt(pa);

		for (i = 0; ((i < 1000) && (ulptr[3])); i++) {
			if (*ulptr & 0x80000000) {
			/* found a ready to send buffer descriptor */
				dst_buf = phys_to_virt(ulptr[2]);
				len = ulptr[1] >> 16;
				new_skb = alloc_skb(len, GFP_KERNEL);
				skb_copy_to_linear_data(new_skb, dst_buf, len);
				shm_dev->net_dev->stats.rx_packets++;
				shm_dev->net_dev->stats.rx_bytes += len;

				if (netif_receive_skb(new_skb) != NET_RX_SUCCESS)
					dev_kfree_skb(new_skb);

				*ulptr = 0x0300000;
			}

			pa = ulptr[3];
			if (!pa)
				break;

			ulptr = phys_to_virt(pa);
		}
		msleep(20);
	}

	return 0;
}

/* mmap() handler -
 * allocates kernel contiguous physical memory and map it to user-space
 * for shared memory IPC interface to user-space
 */

static int prestera_shm_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct prestera_shm_dev *dev = filp->private_data;
	void *vaddr;

	dev->size = MAX_ORDER_NR_PAGES * PAGE_SIZE;

	pr_err("%s: Entry. Size=%lu. VMA_size = %lu\n", __func__, dev->size,
	       vma->vm_end - vma->vm_start);

	dev->alloc_pages = alloc_pages(GFP_DMA, MAX_ORDER - 1);

	if (!dev->alloc_pages/*dev->shm_mmap_memory*/) {
		pr_err("%s: Failed allocating %lu bytes of memory.\n", __func__, dev->size);
		return -ENOMEM;
	}

	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

	dev->addr_phys = (page_to_pfn(dev->alloc_pages) << PAGE_SHIFT);

	vaddr = page_address(dev->alloc_pages);
	dev->shm_mmap_memory = vaddr;
	if (!dev->shm_mmap_memory) {
		pr_err("%s: Failed remap kernel vaddr, %lu bytes.\n", __func__, dev->size);
		return -ENOMEM;
	}

	/* In lieu of physical registers */
	dev->fw.hw_regs = (u8 __iomem *)dev->shm_mmap_memory;
	dev->fw.mem_addr = (u8 __iomem *)dev->shm_mmap_memory;
	pr_info("%s: memptr %p hw_regs %p mem_addr %p\n", __func__,
		dev->shm_mmap_memory, dev->fw.hw_regs,
		dev->fw.mem_addr);

	if (remap_pfn_range(vma, vma->vm_start,
			    dev->addr_phys >> PAGE_SHIFT,
			    vma->vm_end - vma->vm_start, vma->vm_page_prot) < 0) {
		pr_err("%s: failed remapping virt %lx phys %llx len %lu\n",
		       __func__, vma->vm_start, dev->addr_phys,
		       vma->vm_end - vma->vm_start);
		__free_pages(dev->alloc_pages, MAX_ORDER_NR_PAGES);
		return -EAGAIN;
	}

	pr_info("%s: remapped virt %lx phys %llx len %lu\n",
		__func__, vma->vm_start, dev->addr_phys,
		vma->vm_end - vma->vm_start);

	return 0;
}

static int prestera_shm_open(struct inode *inode, struct file *filp)
{
	struct prestera_shm_dev *dev;

	dev = container_of(inode->i_cdev, struct prestera_shm_dev, shm_cdev);

	if (!dev->initialized)
		return -ENODEV;

	filp->private_data = dev;

	return 0;
}

static int prestera_shm_release(struct inode *inode, struct file *filp)
{
	struct prestera_shm_dev *dev = filp->private_data;

	__free_pages(dev->alloc_pages, MAX_ORDER - 1);
	dev->alloc_pages = NULL;

	dev->shm_mmap_memory = NULL;
	filp->private_data = NULL;

	return 0;
}

static void prestera_shm_handle_interrupt(struct prestera_shm_dev *dev)
{
	if (prestera_fw_read(&dev->fw, PRESTERA_RX_STATUS_REG)) {
		prestera_fw_write(&dev->fw, PRESTERA_RX_STATUS_REG, 0);

		if (likely(dev->fw.dev.recv_pkt))
			dev->fw.dev.recv_pkt(&dev->fw.dev);
	}
}

static int prestera_shm_kthread(void *data)
{
	struct prestera_shm_dev *dev = (struct prestera_shm_dev *)data;

	sched_set_fifo(current);
	while (!kthread_should_stop()) {
		wait_event_interruptible(dev->shm_queue,
					 ((kthread_should_stop()) ||
					 (atomic_read(&dev->pending_intr_cntr) > 0)));

		if (kthread_should_stop()) {
			pr_err("%s: stopping...\n", __func__);
			break;
		}

		while (atomic_fetch_dec(&dev->pending_intr_cntr))
			prestera_fw_handle_event(&dev->fw);
	}
	return 0;
}

static int prestera_shm_ioctl_handle_one(struct prestera_shm_dev *dev,
					 struct prestera_shm_msg *msg)
{
	int err;
	struct prestera_fw_rev *rev = &dev->fw.dev.fw_rev;

	switch (msg->command) {
	case PRESTERA_SHM_INTERRUPT:
		prestera_shm_handle_interrupt(dev);
		atomic_inc(&dev->pending_intr_cntr);
		wake_up(&dev->shm_queue);
		return 0;

	case PRESTERA_SHM_INIT:

		if (!dev->shm_mmap_memory) {
			dev_err(dev->dev_ptr, "%s: userspace must call mmap() for this driver before calling ioctl() with PRESTERA_SHM_INIT!",
				__func__);
			return -ENXIO;
		}

		err = prestera_fw_init(&dev->fw);
		if (err)
			return err;

		prestera_fw_rev_parse_int(msg->arg, rev);
		if (prestera_fw_rev_check(&dev->fw))
			return -EINVAL;

		pr_info("Before Registering prestera device\n");
		err = prestera_device_register(&dev->fw.dev);
		pr_info("Registered prestera device (return code %d).\n", err);
		return err;
	}

	return -EINVAL;
}

/* Handle simulation of PCIe interrupt and firmware version number update
 */
static long prestera_shm_ioctl(struct file *filp, unsigned int command,
			       unsigned long arg)
{
	struct prestera_shm_dev *dev = filp->private_data;
	struct prestera_shm_msg msg;

	msg.command = command;
	msg.arg = arg;

	return prestera_shm_ioctl_handle_one(dev, &msg);
}

static const struct file_operations shm_file_operations = {
	.owner =	  THIS_MODULE,
	.unlocked_ioctl = prestera_shm_ioctl,
	.mmap =           prestera_shm_mmap,
	.open =		  prestera_shm_open,
	.release =	  prestera_shm_release,
};

/* Module device specific information initialization function -
 * Allocates character device for ioctl() and mmap() functionalities
 */

static int prestera_shm_dev_init(struct prestera_shm_dev *dev,
				 struct platform_device *pdev)
{
	int ret;
	struct resource *resource = NULL;
	void __iomem *base;
	struct prestera_shm_dev **pp_dev;
	unsigned char addr[ETH_ALEN];

	atomic_set(&dev->pending_intr_cntr, 0);
	init_waitqueue_head(&dev->shm_queue);
	dev->shm_kthread = kthread_run(prestera_shm_kthread, (void *)dev,
				       "prestera_shm_kthread");
	if (!dev->shm_kthread)
		return -ENOMEM;

	ret = alloc_chrdev_region(&dev->shm_cdev_ids, 0, 1, PRESTERA_SHM_DEVNAME);
	if (ret)
		goto err_chrdev_region;

	cdev_init(&dev->shm_cdev, &shm_file_operations);

	ret = cdev_add(&dev->shm_cdev, dev->shm_cdev_ids, 1);
	if (ret)
		goto err_cdev_add;

	dev->shm_class = class_create(THIS_MODULE, PRESTERA_SHM_DEVNAME);
	if (IS_ERR(dev->shm_class)) {
		ret = PTR_ERR(dev->shm_class);
		goto err_class_create;
	}

	dev->dev_ptr = device_create(dev->shm_class, NULL, dev->shm_cdev_ids,
				     NULL, PRESTERA_SHM_DEVNAME);

	dev->dev_ptr->bus = &prestera_shm_bus_type;
	if (IS_ERR(dev->dev_ptr)) {
		ret = PTR_ERR(dev->dev_ptr);
		goto err_dev_create;
	}

	if (!dev->dev_ptr->dma_mask) {
		pr_info("%s: Fixing dma_mask...\n", __func__);
		dev->dev_ptr->dma_mask = &dev->dev_ptr->coherent_dma_mask;
	}

	/*
	 * AC5X DDR starts at physical address 0x2_0000_0000,
	 * and can end at 0xff_ffff_ffff so we need a 40 bit
	 * mask for it ...
	 */
	ret = dma_set_mask_and_coherent(dev->dev_ptr, DMA_BIT_MASK(40));
	if (ret) {
		dev_err(dev->dev_ptr, "fail to set DMA mask, return code is: %d\n", ret);
		goto err_dma_mask;
	}
	dev->dev_ptr->bus_dma_limit = DMA_BIT_MASK(40);
	pr_info("%s: coherent_dma_mask %llx bus_dma_limit %llx\n", __func__,
		dev->dev_ptr->coherent_dma_mask, dev->dev_ptr->bus_dma_limit);
#if defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_DEVICE) || \
	defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU) || \
	defined(CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU_ALL)
	dev->dev_ptr->dma_coherent = true;
#endif
	if (!sim_devname) {
		dev->fw.dev.dma_flags = GFP_DMA;
		resource = platform_get_resource(pdev, IORESOURCE_MEM, 0);
		if (!resource || resource_size(resource) < PAGE_SIZE) {
			dev_err(dev->dev_ptr, "Failed getting valid IO resource from device tree!\n");
			goto err_dma_mask;
		}

		base = devm_ioremap_resource(dev->dev_ptr, resource);
		if (IS_ERR(base))
			goto err_dma_mask;

	} else {
		/* X86 does not really support GFP_DMA.
		 *  It translates into ISA lower 16MB in memory.
		 */
		dev->fw.dev.dma_flags = 0;

		/* Simulate MG SDMA area in software */
		base = kzalloc(0x10000, GFP_KERNEL);
		if (!base)
			goto err_dma_mask;

		dev->sim_kthread = kthread_run(prestera_shm_sim_sdma, dev, "sim_mg_sdma");

		if (!dev->sim_kthread) {
			kfree(base);
			goto err_dma_mask;
		}

		dev->net_dev = alloc_etherdev(sizeof(void *));

		if (!dev->net_dev) {
			kthread_stop(dev->sim_kthread);
			kfree(base);
			goto err_dma_mask;
		}

		pp_dev = (struct prestera_shm_dev **)netdev_priv(dev->net_dev);
		*pp_dev = dev;
		dev->net_dev->netdev_ops = &shm_sim_netdev_ops;
		SET_NETDEV_DEV(dev->net_dev, dev->dev_ptr);

		dev->net_dev->mtu = 1536;
		dev->net_dev->min_mtu = 64;
		dev->net_dev->max_mtu = 1536;
		dev->net_dev->type = ARPHRD_ETHER;
		dev->net_dev->addr_len = ETH_ALEN;

		strcpy(dev->net_dev->name, "sim%d");
		get_random_bytes(addr + 1, ETH_ALEN - 1);
		addr[0] = 0x0;
		memcpy(dev->net_dev->dev_addr, addr, ETH_ALEN);

		ret = register_netdev(dev->net_dev);

		if (ret) {
			pr_err("%s: failed registering network device %s with error number %d\n",
			       __func__, dev->net_dev->name, ret);
		} else {
			netif_carrier_on(dev->net_dev);
			pr_info("%s: ifindex %d ns %p netdev %p\n",
				__func__, dev->net_dev->ifindex,
				dev_net(dev->net_dev),
				__dev_get_by_index(dev_net(dev->net_dev),
						   dev->net_dev->ifindex));
		}
	}

	dev->fw.dev.dev = dev->dev_ptr;
	dev->fw.dev.send_req = prestera_fw_send_req;

	dev->fw.dev.pp_regs = base;
	if (resource)
		pr_info("%s: remmap %llx..%llx to %p...\n",
			__func__, resource->start, resource->end,
			dev->fw.dev.pp_regs);
	dev->fw.dev.running = true;

	pr_info("prestera_shm: Initialized Marvell Prestera shared memory device\n");
	dev->initialized = true;
	return ret;

err_dma_mask:
	device_destroy(dev->shm_class, dev->shm_cdev_ids);
err_dev_create:
	class_destroy(dev->shm_class);
err_class_create:
	cdev_del(&dev->shm_cdev);
err_cdev_add:
	unregister_chrdev_region(dev->shm_cdev_ids, 1);
err_chrdev_region:
	kthread_stop(dev->shm_kthread);
	return ret;
}

static int prestera_shm_probe(struct platform_device *pdev)
{
	struct prestera_shm_dev *dev;
	int ret;

	pr_info("prestera_shm: Probing Marvell Prestera shared memory driver...\n");
	dev = devm_kzalloc(&pdev->dev, sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	ret = prestera_shm_dev_init(dev, pdev);

	if (ret < 0)
		return ret;

	platform_set_drvdata(pdev, dev);

	pr_info("prestera_shm: Probed Marvell Prestera shared memory driver\n");
	return 0;
}

static void prestera_shm_dev_deinit(struct prestera_shm_dev *dev)
{
	kthread_stop(dev->shm_kthread);
	dev->fw.dev.running = false;
	prestera_device_unregister(&dev->fw.dev);
	prestera_fw_uninit(&dev->fw);
	cancel_delayed_work_sync(&dev->fw.dev.keepalive_wdog_work);

	if (sim_devname) {
		kthread_stop(dev->sim_kthread);
		unregister_netdev(dev->net_dev);
	}
	dev->dev_ptr->bus = NULL;
	if (dev->alloc_pages)
		__free_pages(dev->alloc_pages, MAX_ORDER - 1);

	device_destroy(dev->shm_class, dev->shm_cdev_ids);
	class_destroy(dev->shm_class);

	cdev_del(&dev->shm_cdev);
	unregister_chrdev_region(dev->shm_cdev_ids, 1);
	if (sim_devname)
		kfree(dev->fw.dev.pp_regs);
	pr_info("%s: Unregistered Marvell Prestera shared memory driver\n", __func__);
}

static int prestera_shm_remove(struct platform_device *pdev)
{
	struct prestera_shm_dev *dev = platform_get_drvdata(pdev);

	pr_info("%s: Unregistering Marvell Prestera shared memory driver.\n", __func__);
	prestera_shm_dev_deinit(dev);
	return 0;
}

static const struct of_device_id prestera_shm_of_match[] = {
	{ .compatible = "marvell,prestera", },
	{},
};
MODULE_DEVICE_TABLE(of, prestera_shm_of_match);

static struct platform_driver prestera_shm_driver = {
	.driver		= {
		.name	= PRESTERA_SW_SHM_DEV_NAME,
		.owner	= THIS_MODULE,
		.of_match_table = prestera_shm_of_match,
	},
	.probe		= prestera_shm_probe,
	.remove		= prestera_shm_remove,
};

#ifdef CONFIG_X86_64
struct platform_device *g_pdev;

static int __init prestera_shm_init(void)
{
	int ret;

	pr_info("Entry: %s\n", __func__);

	g_pdev = platform_device_alloc("prestera_shm", -1);

	if (!g_pdev)
		return -ENOMEM;

	return prestera_shm_probe(g_pdev);
}

/*
 * Exit function of our module.
 */
static void __exit prestera_shm_exit(void)
{
	pr_info("Exit: %s\n", __func__);

	prestera_shm_remove(g_pdev);
	platform_device_unregister(g_pdev);
}

module_init(prestera_shm_init);
module_exit(prestera_shm_exit);
#else

module_platform_driver(prestera_shm_driver);

#endif

MODULE_AUTHOR("Marvell Semi.");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Marvell Prestera switch shared memory interface");
module_param(sim_devname, charp, 0444);
MODULE_PARM_DESC(sim_devname, "Interface name for simulation mode. When specified, enables simulation mode.");
