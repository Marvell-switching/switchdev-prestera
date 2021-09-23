# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the Marvell Switch driver.
#

obj-$(CONFIG_PRESTERA) += prestera.o
prestera-objs := prestera_main.o \
	prestera_hw.o prestera_switchdev.o prestera_devlink.o prestera_fw_log.o \
	prestera_rxtx.o prestera_dsa.o prestera_router.o \
	prestera_acl.o prestera_flow.o prestera_flower.o prestera_matchall.o prestera_debugfs.o \
	prestera_ct.o prestera_ethtool.o prestera_counter.o

prestera-$(CONFIG_PRESTERA_DEBUG) += prestera_log.o
ccflags-$(CONFIG_PRESTERA_DEBUG) += -DCONFIG_MRVL_PRESTERA_DEBUG

obj-$(CONFIG_PRESTERA_PCI) += prestera_pci.o
