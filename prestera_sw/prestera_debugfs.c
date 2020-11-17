// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/*
 * Copyright (c) 2020 Marvell International Ltd. All rights reserved.
 *
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/debugfs.h>

#include "prestera_debugfs.h"
#include "prestera.h"
#include "prestera_log.h"
#include "prestera_fw_log.h"
#include "prestera_rxtx.h"

#define DEBUGFS_ROOTDIR	"prestera"

#define CPU_CODE_SUBDIR_NAME	"traps"
#define CPU_CODE_MAX_BUF_SIZE	(MVSW_PR_RXTX_CPU_CODE_MAX_NUM * 32)

static ssize_t cpu_code_stats_read(struct file *file,
				   char __user *ubuf,
				   size_t count, loff_t *ppos);

struct mvsw_pr_debugfs {
	struct dentry *root_dir;
	struct dentry *cpu_code_subdir;
	const struct file_operations cpu_code_stats_fops;
	char *cpu_code_stats_buf;
	/* serialize access to cpu_code_stats_buf */
	struct mutex cpu_code_stats_mtx;
};

static struct mvsw_pr_debugfs prestera_debugfs = {
	.cpu_code_stats_fops = {
		.read = cpu_code_stats_read,
		.open = simple_open,
		.llseek = default_llseek,
	},
};

int mvsw_pr_debugfs_init(struct mvsw_pr_switch *sw)
{
	const struct file_operations *fops =
		&prestera_debugfs.cpu_code_stats_fops;
	char file_name[] = "cpu_code_XXX_stats";
	int err;
	int i;

	mutex_init(&prestera_debugfs.cpu_code_stats_mtx);

	prestera_debugfs.cpu_code_stats_buf =
		kzalloc(CPU_CODE_MAX_BUF_SIZE, GFP_KERNEL);

	if (!prestera_debugfs.cpu_code_stats_buf)
		return -ENOMEM;

	err = mvsw_pr_fw_log_init(sw);
	if (err)
		return err;

	prestera_debugfs.root_dir = debugfs_create_dir(DEBUGFS_ROOTDIR, NULL);
	if (!prestera_debugfs.root_dir) {
		err = -ENOMEM;
		goto root_dir_alloc_failed;
	}

	prestera_debugfs.cpu_code_subdir =
		debugfs_create_dir(CPU_CODE_SUBDIR_NAME,
				   prestera_debugfs.root_dir);
	if (!prestera_debugfs.cpu_code_subdir) {
		err = -ENOMEM;
		goto cpu_code_subdir_alloc_failed;
	}

	for (i = 0; i < MVSW_PR_RXTX_CPU_CODE_MAX_NUM; ++i) {
		snprintf(file_name, sizeof(file_name), "cpu_code_%d_stats", i);
		if (!debugfs_create_file(file_name, 0644,
					 prestera_debugfs.cpu_code_subdir,
					 (void *)(long)i, fops)) {
			err = -ENOMEM;
			goto cpu_code_single_file_creation_failed;
		}
	}

	strncpy(file_name, "cpu_code_stats", sizeof(file_name));

	if (!debugfs_create_file(file_name, 0644,
				 prestera_debugfs.cpu_code_subdir,
				 (void *)(long)MVSW_PR_RXTX_CPU_CODE_MAX_NUM,
				 fops)) {
		err = -ENOMEM;
		goto cpu_code_single_file_creation_failed;
	}

	return 0;

cpu_code_single_file_creation_failed:
	debugfs_remove(prestera_debugfs.cpu_code_subdir);
cpu_code_subdir_alloc_failed:
	debugfs_remove(prestera_debugfs.root_dir);
root_dir_alloc_failed:
	mvsw_pr_fw_log_fini(sw);

	return err;
}

void mvsw_pr_debugfs_fini(struct mvsw_pr_switch *sw)
{
	mvsw_pr_fw_log_fini(sw);

	debugfs_remove(prestera_debugfs.cpu_code_subdir);
	debugfs_remove(prestera_debugfs.root_dir);

	mutex_destroy(&prestera_debugfs.cpu_code_stats_mtx);

	kfree(prestera_debugfs.cpu_code_stats_buf);
}

static ssize_t cpu_code_stats_read(struct file *file,
				   char __user *ubuf,
				   size_t count, loff_t *ppos)
{
	char *buf = prestera_debugfs.cpu_code_stats_buf;
	u16 cpu_code = (u16)(long)file->private_data;
	u64 cpu_code_stats;
	/* as the snprintf doesn't count for \0, start with 1 */
	int buf_len = 1;
	int ret;

	mutex_lock(&prestera_debugfs.cpu_code_stats_mtx);

	if (cpu_code == MVSW_PR_RXTX_CPU_CODE_MAX_NUM) {
		int i;

		memset(buf, 0, CPU_CODE_MAX_BUF_SIZE);

		for (i = 0; i < MVSW_PR_RXTX_CPU_CODE_MAX_NUM; ++i) {
			cpu_code_stats = mvsw_pr_rxtx_get_cpu_code_stats(i);

			if (!cpu_code_stats)
				continue;

			buf_len += snprintf(buf + buf_len,
					    CPU_CODE_MAX_BUF_SIZE - buf_len,
					    "%u:%llu\n", i, cpu_code_stats);
		}

	} else {
		cpu_code_stats = mvsw_pr_rxtx_get_cpu_code_stats((u8)cpu_code);

		buf_len += sprintf(buf, "%llu\n", cpu_code_stats);
	}

	ret = simple_read_from_buffer(ubuf, count, ppos, buf, buf_len);
	mutex_unlock(&prestera_debugfs.cpu_code_stats_mtx);

	return ret;
}
