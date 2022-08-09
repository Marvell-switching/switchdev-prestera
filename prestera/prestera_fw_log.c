// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include <linux/sysfs.h>
#include <linux/fs.h>
#include <linux/etherdevice.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>

#include "prestera.h"
#include "prestera_hw.h"
#include "prestera_log.h"
#include "prestera_fw_log.h"

#define FW_LOG_DBGFS_CFG_DIR	"mvsw_pr_fw_log"
#define FW_LOG_DBGFS_CFG_NAME	"cfg"
#define FW_LOG_DBGFS_MAX_STR_LEN	64
#define FW_LOG_PR_LOG_PREFIX	"[mvsw_pr_fw_log]"
#define FW_LOG_PR_LIB_SIZE	32
#define FW_LOG_PR_READ_BUF_SIZE	8192
#define MVSW_FW_LOG_INFO(fmt, ...)	\
	pr_info(fmt, ##__VA_ARGS__)

#define FW_LOG_READ_TABLE_FMT	"%-23s"

#define mvsw_dev(sw)		((sw)->dev->dev)

static void mvsw_pr_fw_log_evt_handler(struct prestera_switch *,
				       struct prestera_event *,
				       void *);
static ssize_t mvsw_pr_fw_log_debugfs_read(struct file *file,
					   char __user *ubuf,
					   size_t count, loff_t *ppos);
static ssize_t mvsw_pr_fw_log_debugfs_write(struct file *file,
					    const char __user *ubuf,
					    size_t count, loff_t *ppos);
static int mvsw_pr_fw_log_get_type_from_str(const char *str);
static int mvsw_pr_fw_log_get_lib_from_str(const char *str);

static int mvsw_pr_fw_log_event_handler_register(struct prestera_switch *sw);
static void mvsw_pr_fw_log_event_handler_unregister(struct prestera_switch *sw);

struct mvsw_pr_fw_log_prv_debugfs {
	struct dentry *cfg_dir;
	struct dentry *cfg;
	const struct file_operations cfg_fops;
	char *read_buf;
};

static u8 fw_log_lib_type_config[PRESTERA_FW_LOG_LIB_MAX] = { 0 };

static struct mvsw_pr_fw_log_prv_debugfs fw_log_debugfs_handle = {
	.cfg_dir = NULL,
	.cfg_fops = {
		.read = mvsw_pr_fw_log_debugfs_read,
		.write = mvsw_pr_fw_log_debugfs_write,
		.open = simple_open,
		.llseek = default_llseek,
	}
};

static const char *mvsw_pr_fw_log_lib_id2name[PRESTERA_FW_LOG_LIB_MAX] = {
	[PRESTERA_FW_LOG_LIB_ALL] =  "all",
	[PRESTERA_FW_LOG_LIB_BRIDGE] =  "bridge",
	[PRESTERA_FW_LOG_LIB_CNC] =  "cnc",
	[PRESTERA_FW_LOG_LIB_CONFIG] =  "config",
	[PRESTERA_FW_LOG_LIB_COS] =  "cos",
	[PRESTERA_FW_LOG_LIB_CSCD] =  "cscd",
	[PRESTERA_FW_LOG_LIB_CUT_THROUGH] =  "cut-through",
	[PRESTERA_FW_LOG_LIB_DIAG] =  "diag",
	[PRESTERA_FW_LOG_LIB_DRAGONITE] =  "dragonite",
	[PRESTERA_FW_LOG_LIB_EGRESS] =  "egress",
	[PRESTERA_FW_LOG_LIB_EXACT_MATCH] =  "exact-match",
	[PRESTERA_FW_LOG_LIB_FABRIC] =  "fabric",
	[PRESTERA_FW_LOG_LIB_BRIDGE_FDB_MANAGER] =  "fdb-manager",
	[PRESTERA_FW_LOG_LIB_FLOW_MANAGER] =  "flow-manager",
	[PRESTERA_FW_LOG_LIB_HW_INIT] =  "hw-init",
	[PRESTERA_FW_LOG_LIB_I2C] =  "i2c",
	[PRESTERA_FW_LOG_LIB_INGRESS] =  "ingress",
	[PRESTERA_FW_LOG_LIB_INIT] =  "init",
	[PRESTERA_FW_LOG_LIB_IPFIX] =  "ipfix",
	[PRESTERA_FW_LOG_LIB_IP] =  "ip",
	[PRESTERA_FW_LOG_LIB_IP_LPM] =  "ip-lpm",
	[PRESTERA_FW_LOG_LIB_L2_MLL] =  "l2-mll",
	[PRESTERA_FW_LOG_LIB_LATENCY_MONITORING] =  "latency-monitoring",
	[PRESTERA_FW_LOG_LIB_LOGICAL_TARGET] =  "logical-target",
	[PRESTERA_FW_LOG_LIB_LPM] =  "lpm",
	[PRESTERA_FW_LOG_LIB_MIRROR] =  "mirror",
	[PRESTERA_FW_LOG_LIB_MULTI_PORT_GROUP] =  "multi-port-group",
	[PRESTERA_FW_LOG_LIB_NETWORK_IF] =  "network-if",
	[PRESTERA_FW_LOG_LIB_NST] =  "nst",
	[PRESTERA_FW_LOG_LIB_OAM] =  "oam",
	[PRESTERA_FW_LOG_LIB_PACKET_ANALYZER] =  "packet-analyzer",
	[PRESTERA_FW_LOG_LIB_PCL] =  "pcl",
	[PRESTERA_FW_LOG_LIB_PHA] =  "pha",
	[PRESTERA_FW_LOG_LIB_PHY] =  "phy",
	[PRESTERA_FW_LOG_LIB_POLICER] =  "policer",
	[PRESTERA_FW_LOG_LIB_PROTECTION] =  "protection",
	[PRESTERA_FW_LOG_LIB_PTP] =  "ptp",
	[PRESTERA_FW_LOG_LIB_RESOURCE_MANAGER] =  "resource-manager",
	[PRESTERA_FW_LOG_LIB_SMI] =  "smi",
	[PRESTERA_FW_LOG_LIB_SYSTEM_RECOVERY] =  "system-recovery",
	[PRESTERA_FW_LOG_LIB_TAM] =  "tam",
	[PRESTERA_FW_LOG_LIB_TCAM] =  "tcam",
	[PRESTERA_FW_LOG_LIB_TM] =  "tm",
	[PRESTERA_FW_LOG_LIB_TM_GLUE] =  "tm-glue",
	[PRESTERA_FW_LOG_LIB_TRUNK] =  "trunk",
	[PRESTERA_FW_LOG_LIB_TTI] =  "tti",
	[PRESTERA_FW_LOG_LIB_TUNNEL] =  "tunnel",
	[PRESTERA_FW_LOG_LIB_VERSION] =  "version",
	[PRESTERA_FW_LOG_LIB_VIRTUAL_TCAM] =  "virtual-tcam",
	[PRESTERA_FW_LOG_LIB_VNT] =  "vnt",
	[PRESTERA_FW_LOG_LIB_PPU] = "ppu",
	[PRESTERA_FW_LOG_LIB_EXACT_MATCH_MANAGER] = "exact-match-manager",
	[PRESTERA_FW_LOG_LIB_MAC_SEC] = "mac-sec",
	[PRESTERA_FW_LOG_LIB_PTP_MANAGER] = "ptp-manager",
	[PRESTERA_FW_LOG_LIB_HSR_PRP] = "hsr-prp",
	[PRESTERA_FW_LOG_LIB_STREAM] = "stream",
	[PRESTERA_FW_LOG_LIB_IPFIX_MANAGER] = "ipfix_manager",
};

static const char *mvsw_pr_fw_log_prv_type_id2name[PRESTERA_FW_LOG_TYPE_MAX] = {
	[PRESTERA_FW_LOG_TYPE_INFO] = "info",
	[PRESTERA_FW_LOG_TYPE_ENTRY_LEVEL_FUNCTION] = "entry-level-function",
	[PRESTERA_FW_LOG_TYPE_ERROR] = "error",
	[PRESTERA_FW_LOG_TYPE_ALL] = "all",
	[PRESTERA_FW_LOG_TYPE_NONE]  = "none",
};

static void mvsw_pr_fw_log_evt_handler(struct prestera_switch *sw,
				       struct prestera_event *evt, void *arg)
{
	u32 log_len = evt->fw_log_evt.log_len;
	u8 *buf = evt->fw_log_evt.data;

	buf[log_len] = '\0';

	MVSW_FW_LOG_INFO(FW_LOG_PR_LOG_PREFIX "%s\n", buf);
}

static ssize_t mvsw_pr_fw_log_format_str(void)
{
	char *buf = fw_log_debugfs_handle.read_buf;
	int chars_written = 0;
	int lib, type;
	int ret;

	memset(buf, 0, FW_LOG_PR_READ_BUF_SIZE);

	ret = snprintf(buf, FW_LOG_PR_READ_BUF_SIZE, FW_LOG_READ_TABLE_FMT,
		       " ");
	if (ret < 0)
		return ret;

	chars_written += ret;

	for (type = 0; type < PRESTERA_FW_LOG_TYPE_MAX; ++type) {
		if (type == PRESTERA_FW_LOG_TYPE_NONE ||
		    type == PRESTERA_FW_LOG_TYPE_ALL)
			continue;

		ret = snprintf(buf + chars_written,
			       FW_LOG_PR_READ_BUF_SIZE - chars_written,
			       FW_LOG_READ_TABLE_FMT,
			       mvsw_pr_fw_log_prv_type_id2name[type]);
		if (ret < 0)
			return ret;

		chars_written += ret;
	}

	strcat(buf, "\n");
	++chars_written;

	for (lib = 0; lib < PRESTERA_FW_LOG_LIB_MAX; ++lib) {
		if (lib == PRESTERA_FW_LOG_LIB_ALL ||
		    !mvsw_pr_fw_log_lib_id2name[lib])
			continue;

		ret = snprintf(buf + chars_written,
			       FW_LOG_PR_READ_BUF_SIZE - chars_written,
			       FW_LOG_READ_TABLE_FMT,
			       mvsw_pr_fw_log_lib_id2name[lib]);
		if (ret < 0)
			return ret;

		chars_written += ret;

		for (type = 0; type < PRESTERA_FW_LOG_TYPE_MAX; ++type) {
			if (type == PRESTERA_FW_LOG_TYPE_NONE ||
			    type == PRESTERA_FW_LOG_TYPE_ALL)
				continue;

			ret = snprintf(buf + chars_written,
				       FW_LOG_PR_READ_BUF_SIZE - chars_written,
				       FW_LOG_READ_TABLE_FMT,
				       fw_log_lib_type_config[lib] & BIT(type)
						? "+" : "-");
			if (ret < 0)
				return ret;

			chars_written += ret;
		}
		strlcat(buf, "\n", FW_LOG_PR_READ_BUF_SIZE);
		++chars_written;
	}

	return chars_written;
}

static ssize_t mvsw_pr_fw_log_debugfs_read(struct file *file,
					   char __user *ubuf,
					   size_t count, loff_t *ppos)
{
	char *buf = fw_log_debugfs_handle.read_buf;

	return simple_read_from_buffer(ubuf, count, ppos, buf,
				       FW_LOG_PR_READ_BUF_SIZE);
}

static int mvsw_pr_fw_log_parse_usr_input(int *name, int *type,
					  const char __user *ubuf, size_t count)
{
	u8 tmp_buf[FW_LOG_DBGFS_MAX_STR_LEN] = { 0 };
	u8 lib_str[FW_LOG_PR_LIB_SIZE] = { 0 };
	u8 type_str[FW_LOG_PR_LIB_SIZE] = { 0 };
	ssize_t len_to_copy = count - 1;
	u8 *ppos_lib, *ppos_type;
	char *end = tmp_buf;
	int err;

	if (len_to_copy > FW_LOG_DBGFS_MAX_STR_LEN) {
		MVSW_LOG_ERROR("Len is > than max(%zu vs max possible %d)\n",
			       count, FW_LOG_DBGFS_MAX_STR_LEN);
		return -EMSGSIZE;
	}

	err = copy_from_user(tmp_buf, ubuf, len_to_copy);
	if (err)
		return -EINVAL;

	ppos_lib  = strsep(&end, " \t");
	ppos_type = strsep(&end, " \t\0");

	if (!ppos_lib || !ppos_type)
		return -EINVAL;

	strcpy(lib_str, ppos_lib);

	strcpy(type_str, ppos_type);

	if (iscntrl(lib_str[0]) || isspace(lib_str[0]) || lib_str[0] == '\0' ||
	    iscntrl(type_str[0]) || isspace(type_str[0]) ||
	    type_str[0] == '\0') {
		return -EINVAL;
	}

	*name = mvsw_pr_fw_log_get_lib_from_str(lib_str);
	*type = mvsw_pr_fw_log_get_type_from_str(type_str);

	if (*name >= PRESTERA_FW_LOG_LIB_MAX ||
	    *type >= PRESTERA_FW_LOG_TYPE_MAX ||
	    (*name != PRESTERA_FW_LOG_LIB_ALL &&
	     *type == PRESTERA_FW_LOG_TYPE_NONE))
		return -EINVAL;

	return 0;
}

static ssize_t mvsw_pr_fw_log_debugfs_write(struct file *file,
					    const char __user *ubuf,
					    size_t count, loff_t *ppos)
{
	struct prestera_switch *sw = file->private_data;
	int lib, type;
	int i, j;
	int err;

	err = mvsw_pr_fw_log_parse_usr_input(&lib, &type, ubuf, count);
	if (err)
		goto error;

	err = prestera_hw_fw_log_level_set(sw, lib, type);
	if (err) {
		dev_err(mvsw_dev(sw), "Failed to send request to firmware\n");
		return err;
	}

	/* specific lib and specific type */
	if (lib != PRESTERA_FW_LOG_LIB_ALL &&
	    type != PRESTERA_FW_LOG_TYPE_ALL) {
		/* special type 'NONE' to disable feature */
		if (type == PRESTERA_FW_LOG_TYPE_NONE)
			memset(fw_log_lib_type_config, 0,
			       sizeof(fw_log_lib_type_config));
		/* Actual type should be switched */
		else
			fw_log_lib_type_config[lib] ^= (1 << type);
	/* specific lib but all types */
	} else if (lib != PRESTERA_FW_LOG_LIB_ALL &&
		   type == PRESTERA_FW_LOG_TYPE_ALL) {
		for (j = 0; j < PRESTERA_FW_LOG_TYPE_ALL; ++j)
			fw_log_lib_type_config[lib] ^= (1 << j);
	/* specific type but all libs */
	} else if (lib == PRESTERA_FW_LOG_LIB_ALL &&
		   type != PRESTERA_FW_LOG_TYPE_ALL) {
		for (i = 0; i < PRESTERA_FW_LOG_LIB_ALL; ++i)
			fw_log_lib_type_config[i] |= (1 << type);
	/* all libs and all types */
	} else {
		for (i = 0; i < PRESTERA_FW_LOG_LIB_ALL; ++i) {
			for (j = 0; j < PRESTERA_FW_LOG_TYPE_ALL; ++j)
				fw_log_lib_type_config[i] |= (1 << j);
		}
	}

	err = mvsw_pr_fw_log_format_str();
	if (err <= 0) {
		dev_err(mvsw_dev(sw), "Failed to form output string\n");
		return err;
	}

	return count;

error:
	dev_warn(mvsw_dev(sw),
		 "Invalid str received, make sure request is valid\n");
	dev_warn(mvsw_dev(sw),
		 "Valid fmt consists of: \"lib type\" string, e.g:\n");
	dev_warn(mvsw_dev(sw),
		 "\"phy error\" for 'phy' lib 'error' logs enabled\n");

	return err;
}

static int mvsw_pr_fw_log_get_type_from_str(const char *str)
{
	int i;

	for (i = 0; i < PRESTERA_FW_LOG_TYPE_MAX; ++i) {
		if (!mvsw_pr_fw_log_prv_type_id2name[i])
			continue;

		if (strcmp(mvsw_pr_fw_log_prv_type_id2name[i], str) == 0)
			return i;
	}

	return PRESTERA_FW_LOG_TYPE_MAX;
}

static int mvsw_pr_fw_log_get_lib_from_str(const char *str)
{
	int i;

	for (i = 0; i < PRESTERA_FW_LOG_LIB_MAX; ++i) {
		if (!mvsw_pr_fw_log_lib_id2name[i])
			continue;

		if (strcmp(mvsw_pr_fw_log_lib_id2name[i], str) == 0)
			return i;
	}

	return PRESTERA_FW_LOG_LIB_MAX;
}

static int mvsw_pr_fw_log_event_handler_register(struct prestera_switch *sw)
{
	return prestera_hw_event_handler_register(sw,
						  PRESTERA_EVENT_TYPE_FW_LOG,
						  mvsw_pr_fw_log_evt_handler,
						  NULL);
}

static void mvsw_pr_fw_log_event_handler_unregister(struct prestera_switch *sw)
{
	prestera_hw_event_handler_unregister(sw, PRESTERA_EVENT_TYPE_FW_LOG);
}

int mvsw_pr_fw_log_init(struct prestera_switch *sw)
{
	fw_log_debugfs_handle.cfg_dir =
		debugfs_create_dir(FW_LOG_DBGFS_CFG_DIR, NULL);

	if (!fw_log_debugfs_handle.cfg_dir) {
		MVSW_LOG_ERROR("Failed to create debugfs dir entry");
		return -1;
	}

	fw_log_debugfs_handle.cfg =
		debugfs_create_file(FW_LOG_DBGFS_CFG_NAME, 0644,
				    fw_log_debugfs_handle.cfg_dir, sw,
				    &fw_log_debugfs_handle.cfg_fops);

	if (!fw_log_debugfs_handle.cfg) {
		MVSW_LOG_ERROR("Failed to create debugfs dir entry");
		debugfs_remove(fw_log_debugfs_handle.cfg_dir);
		return -1;
	}

	if (mvsw_pr_fw_log_event_handler_register(sw))
		goto error;

	fw_log_debugfs_handle.read_buf =
		kzalloc(FW_LOG_PR_READ_BUF_SIZE, GFP_KERNEL);

	if (!fw_log_debugfs_handle.read_buf)
		goto error;

	prestera_hw_fw_log_level_set(sw, PRESTERA_FW_LOG_LIB_ALL,
				     PRESTERA_FW_LOG_TYPE_NONE);
	mvsw_pr_fw_log_format_str();

	return 0;
error:
	debugfs_remove(fw_log_debugfs_handle.cfg);
	debugfs_remove(fw_log_debugfs_handle.cfg_dir);
	return -1;
}

void mvsw_pr_fw_log_fini(struct prestera_switch *sw)
{
	mvsw_pr_fw_log_event_handler_unregister(sw);

	kfree(fw_log_debugfs_handle.read_buf);

	debugfs_remove(fw_log_debugfs_handle.cfg);
	debugfs_remove(fw_log_debugfs_handle.cfg_dir);
}
