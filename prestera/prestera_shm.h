/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#ifndef PRESTERA_SHM_H_
#define PRESTERA_SHM_H_

#define PRESTERA_SHM_INTERRUPT_IOC_MAGIC	's'
#define PRESTERA_SHM_INIT_IOC_MAGIC	'i'
#define PRESTERA_SHM_BARRIER_IOC_MAGIC	'b'

#define PRESTERA_SHM_INTERRUPT	_IOW(PRESTERA_SHM_INTERRUPT_IOC_MAGIC, 0, __u32)
#define PRESTERA_SHM_INIT _IOW(PRESTERA_SHM_INIT_IOC_MAGIC, 0, __u32)
#define PRESTERA_SHM_DEVNAME "prestera_shm"

#endif
