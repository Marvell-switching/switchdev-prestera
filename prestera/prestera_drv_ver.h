/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved. */

#ifndef _PRESTERA_DRV_VER_H_
#define _PRESTERA_DRV_VER_H_

#include <linux/stringify.h>

/* Prestera driver version */
#define PRESTERA_DRV_VER_MAJOR	2
#define PRESTERA_DRV_VER_MINOR	0
#define PRESTERA_DRV_VER_PATCH	0
#define PRESTERA_DRV_VER_EXTRA

#define PRESTERA_DRV_VER \
		__stringify(PRESTERA_DRV_VER_MAJOR)  "." \
		__stringify(PRESTERA_DRV_VER_MINOR)  "." \
		__stringify(PRESTERA_DRV_VER_PATCH)  \
		__stringify(PRESTERA_DRV_VER_EXTRA)

#endif  /* _PRESTERA_DRV_VER_H_ */
