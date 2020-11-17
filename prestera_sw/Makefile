# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Marvell Switch driver.
#

ccflags-$(CONFIG_MRVL_PRESTERA_USE_INTR_DRIVER)    += -DMRVL_PRESTERA_USE_INTR_DRIVER

obj-$(CONFIG_MRVL_PRESTERA_SW) += prestera_sw.o
prestera_sw-objs := prestera.o \
	prestera_hw.o prestera_switchdev.o prestera_devlink.o prestera_fw_log.o \
	prestera_rxtx.o prestera_rxtx_sdma.o prestera_dsa.o prestera_router.o \
	prestera_acl.o prestera_flower.o prestera_debugfs.o

prestera_sw-$(CONFIG_MRVL_PRESTERA_DEBUG) += prestera_log.o
ccflags-$(CONFIG_MRVL_PRESTERA_DEBUG) += -DCONFIG_MRVL_PRESTERA_DEBUG

obj-$(CONFIG_MRVL_PRESTERA_PCI) += prestera_pci.o