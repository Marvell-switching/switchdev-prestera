// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/debugfs.h>

#include "prestera_debugfs.h"
#include "prestera.h"
#include "prestera_log.h"
#include "prestera_fw_log.h"
#include "prestera_rxtx.h"
#include "prestera_hw.h"

#define PRESTERA_DEBUGFS_ROOTDIR	"prestera"

#define CPU_CODE_HW_CNT_SUBDIR_NAME	"hw_counters"
#define CPU_CODE_SW_CNT_SUBDIR_NAME	"sw_counters"

#define CPU_CODE_CNT_SUBDIR_TRAP_NAME	"traps"
#define CPU_CODE_CNT_SUBDIR_DROP_NAME	"drops"

#define CPU_CODE_CNT_BUF_MAX_SIZE	(MVSW_PR_RXTX_CPU_CODE_MAX_NUM * 32)

static ssize_t prestera_cnt_read(struct file *file, char __user *ubuf,
				 size_t count, loff_t *ppos);

struct prestera_debugfs {
	struct dentry *root_dir;
	const struct file_operations cpu_code_cnt_fops;
	char *cpu_code_cnt_buf;
	/* serialize access to cpu_code_cnt_buf */
	struct mutex cpu_code_cnt_buf_mtx;
	struct prestera_switch *sw;
};

struct prestera_cpu_code_data {
	union {
		long data;
		struct {
			u16 cpu_code;
			u8 cpu_code_cnt_type;
		} __packed __aligned(4);
	};
} __packed __aligned(4);

static struct prestera_debugfs prestera_debugfs = {
	.cpu_code_cnt_fops = {
		.read = prestera_cnt_read,
		.open = simple_open,
		.llseek = default_llseek,
	},
};

enum {
	CPU_CODE_CNT_TYPE_HW_DROP = PRESTERA_HW_CPU_CODE_CNT_TYPE_DROP,
	CPU_CODE_CNT_TYPE_HW_TRAP = PRESTERA_HW_CPU_CODE_CNT_TYPE_TRAP,
	CPU_CODE_CNT_TYPE_SW_TRAP = CPU_CODE_CNT_TYPE_HW_TRAP + 1,
};

int prestera_debugfs_init(struct prestera_switch *sw)
{
	struct prestera_debugfs *debugfs = &prestera_debugfs;
	struct dentry *cpu_code_hw_cnt_trap_subdir;
	struct dentry *cpu_code_hw_cnt_drop_subdir;
	struct dentry *cpu_code_sw_cnt_trap_subdir;
	struct dentry *cpu_code_sw_cnt_subdir;
	struct dentry *cpu_code_hw_counters_subdir;
	char file_name[] = "cpu_code_XXX_stats";
	const struct file_operations *fops =
		&prestera_debugfs.cpu_code_cnt_fops;
	struct prestera_cpu_code_data f_data;
	struct dentry *debugfs_file;
	int err;
	int i;

	mutex_init(&debugfs->cpu_code_cnt_buf_mtx);

	debugfs->sw = sw;

	debugfs->cpu_code_cnt_buf = kzalloc(CPU_CODE_CNT_BUF_MAX_SIZE,
					    GFP_KERNEL);
	if (!debugfs->cpu_code_cnt_buf)
		return -ENOMEM;

	err = mvsw_pr_fw_log_init(sw);
	if (err)
		goto err_fw_log_init;

	debugfs->root_dir = debugfs_create_dir(PRESTERA_DEBUGFS_ROOTDIR, NULL);
	if (PTR_ERR_OR_ZERO(debugfs->root_dir)) {
		err = (int)PTR_ERR(debugfs->root_dir);
		goto err_root_dir_alloc;
	}

	cpu_code_sw_cnt_subdir = debugfs_create_dir(CPU_CODE_SW_CNT_SUBDIR_NAME,
						    debugfs->root_dir);
	if (PTR_ERR_OR_ZERO(cpu_code_sw_cnt_subdir)) {
		err = (int)PTR_ERR(debugfs->root_dir);
		goto err_subdir_alloc;
	}

	cpu_code_sw_cnt_trap_subdir =
		debugfs_create_dir(CPU_CODE_CNT_SUBDIR_TRAP_NAME,
				   cpu_code_sw_cnt_subdir);
	if (PTR_ERR_OR_ZERO(cpu_code_sw_cnt_trap_subdir)) {
		err = (int)PTR_ERR(cpu_code_sw_cnt_trap_subdir);
		goto err_subdir_alloc;
	}

	cpu_code_hw_counters_subdir =
		debugfs_create_dir(CPU_CODE_HW_CNT_SUBDIR_NAME,
				   debugfs->root_dir);
	if (PTR_ERR_OR_ZERO(cpu_code_hw_counters_subdir)) {
		err = (int)PTR_ERR(cpu_code_hw_counters_subdir);
		goto err_subdir_alloc;
	}

	cpu_code_hw_cnt_trap_subdir =
		debugfs_create_dir(CPU_CODE_CNT_SUBDIR_TRAP_NAME,
				   cpu_code_hw_counters_subdir);
	if (PTR_ERR_OR_ZERO(cpu_code_hw_cnt_trap_subdir)) {
		err = (int)PTR_ERR(cpu_code_hw_cnt_trap_subdir);
		goto err_subdir_alloc;
	}

	cpu_code_hw_cnt_drop_subdir =
		debugfs_create_dir(CPU_CODE_CNT_SUBDIR_DROP_NAME,
				   cpu_code_hw_counters_subdir);
	if (PTR_ERR_OR_ZERO(cpu_code_hw_cnt_drop_subdir)) {
		err = (int)PTR_ERR(cpu_code_hw_cnt_trap_subdir);
		goto err_subdir_alloc;
	}

	for (i = 0; i < MVSW_PR_RXTX_CPU_CODE_MAX_NUM; ++i) {
		f_data.cpu_code = i;

		snprintf(file_name, sizeof(file_name), "cpu_code_%d_stats", i);

		f_data.cpu_code_cnt_type = CPU_CODE_CNT_TYPE_SW_TRAP;
		debugfs_file = debugfs_create_file(file_name, 0644,
						   cpu_code_sw_cnt_trap_subdir,
						   (void *)f_data.data,
						   fops);
		if (PTR_ERR_OR_ZERO(debugfs_file))
			goto err_single_file_creation;

		f_data.cpu_code_cnt_type = CPU_CODE_CNT_TYPE_HW_TRAP;
		debugfs_file = debugfs_create_file(file_name, 0644,
						   cpu_code_hw_cnt_trap_subdir,
						   (void *)f_data.data,
						   fops);
		if (PTR_ERR_OR_ZERO(debugfs_file))
			goto err_single_file_creation;

		f_data.cpu_code_cnt_type = CPU_CODE_CNT_TYPE_HW_DROP;
		debugfs_file = debugfs_create_file(file_name, 0644,
						   cpu_code_hw_cnt_drop_subdir,
						   (void *)f_data.data,
						   fops);
		if (PTR_ERR_OR_ZERO(debugfs_file))
			goto err_single_file_creation;
	}

	f_data.cpu_code = MVSW_PR_RXTX_CPU_CODE_MAX_NUM;
	f_data.cpu_code_cnt_type = CPU_CODE_CNT_TYPE_SW_TRAP;
	debugfs_file = debugfs_create_file("cpu_code_stats", 0644,
					   cpu_code_sw_cnt_trap_subdir,
					   (void *)f_data.data,
					   fops);
	if (PTR_ERR_OR_ZERO(debugfs_file))
		goto err_single_file_creation;

	f_data.cpu_code_cnt_type = CPU_CODE_CNT_TYPE_HW_TRAP;
	debugfs_file = debugfs_create_file("cpu_code_stats", 0644,
					   cpu_code_hw_cnt_trap_subdir,
					   (void *)f_data.data,
					   fops);
	if (PTR_ERR_OR_ZERO(debugfs_file))
		goto err_single_file_creation;

	f_data.cpu_code_cnt_type = CPU_CODE_CNT_TYPE_HW_DROP;
	debugfs_file = debugfs_create_file("cpu_code_stats", 0644,
					   cpu_code_hw_cnt_drop_subdir,
					   (void *)f_data.data,
					   fops);
	if (PTR_ERR_OR_ZERO(debugfs_file))
		goto err_single_file_creation;

	return 0;

err_single_file_creation:
	err = (int)PTR_ERR(debugfs_file);
err_subdir_alloc:
	/*
	 * Removing root directory would result in recursive
	 * subdirectories / files cleanup of all child nodes;
	 */
	debugfs_remove(debugfs->root_dir);
err_root_dir_alloc:
	mvsw_pr_fw_log_fini(sw);
err_fw_log_init:
	kfree(debugfs->cpu_code_cnt_buf);
	return err;
}

void prestera_debugfs_fini(struct prestera_switch *sw)
{
	mvsw_pr_fw_log_fini(sw);
	debugfs_remove(prestera_debugfs.root_dir);
	mutex_destroy(&prestera_debugfs.cpu_code_cnt_buf_mtx);
	kfree(prestera_debugfs.cpu_code_cnt_buf);
}

/*
 * Software: only TRAP counters are present
 * Hardware: counters can be either TRAP or drops
 */
static int prestera_cpu_code_cnt_get(u64 *stats, u8 cpu_code, u8 cnt_type)
{
	switch (cnt_type) {
	case CPU_CODE_CNT_TYPE_HW_DROP:
	case CPU_CODE_CNT_TYPE_HW_TRAP:
		/* fall through */
		return prestera_hw_cpu_code_counters_get(prestera_debugfs.sw,
							 cpu_code, cnt_type,
							 stats);
	case CPU_CODE_CNT_TYPE_SW_TRAP:
		*stats = mvsw_pr_rxtx_get_cpu_code_stats(cpu_code);
		return 0;
	default:
		return -EINVAL;
	}
}

static ssize_t prestera_cnt_read(struct file *file, char __user *ubuf,
				 size_t count, loff_t *ppos)
{
	char *buf = prestera_debugfs.cpu_code_cnt_buf;
	struct prestera_cpu_code_data f_data = {
		.data = (long)file->private_data,
	};
	u64 cpu_code_stats;
	/* as the snprintf doesn't count for \0, start with 1 */
	int buf_len = 1;
	int ret;

	mutex_lock(&prestera_debugfs.cpu_code_cnt_buf_mtx);

	if (f_data.cpu_code == MVSW_PR_RXTX_CPU_CODE_MAX_NUM) {
		int i;

		memset(buf, 0, CPU_CODE_CNT_BUF_MAX_SIZE);

		for (i = 0; i < MVSW_PR_RXTX_CPU_CODE_MAX_NUM; ++i) {
			ret = prestera_cpu_code_cnt_get
				(&cpu_code_stats, (u8)i,
				 f_data.cpu_code_cnt_type);
			if (ret)
				goto err_get_stats;

			if (!cpu_code_stats)
				continue;

			buf_len += snprintf(buf + buf_len,
					    CPU_CODE_CNT_BUF_MAX_SIZE - buf_len,
					    "%u:%llu\n", i, cpu_code_stats);
		}

	} else {
		ret = prestera_cpu_code_cnt_get(&cpu_code_stats,
						(u8)f_data.cpu_code,
						f_data.cpu_code_cnt_type);
		if (ret)
			goto err_get_stats;

		buf_len += sprintf(buf, "%llu\n", cpu_code_stats);
	}

	ret = simple_read_from_buffer(ubuf, count, ppos, buf, buf_len);

err_get_stats:
	mutex_unlock(&prestera_debugfs.cpu_code_cnt_buf_mtx);

	return ret;
}
