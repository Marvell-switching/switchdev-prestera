/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved. */

#ifndef _MVSW_PRESTERA_LOG_H_
#define _MVSW_PRESTERA_LOG_H_

#ifdef CONFIG_MRVL_PRESTERA_DEBUG

#include <linux/netdevice.h>
#include <linux/version.h>
#include <net/switchdev.h>
#include <net/fib_notifier.h>
#include <net/netevent.h>
#include <net/pkt_cls.h>

#define DEF_ENUM_MAP(enum_name) \
static const char *enum_name##_map[]

#define DEF_ENUM_FUNC(enum_name, enum_min, enum_max) \
const char *enum_name##_to_name(enum enum_name val) \
{ \
	if (val < enum_min || val > enum_max) \
		return unknown; \
	return enum_name##_map[val]; \
}

#define DEC_ENUM_FUNC(enum_name) \
const char *enum_name##_to_name(enum enum_name)

#define ENUM_TO_NAME(enum_name, val) enum_name##_to_name(val)

#define MVSW_LOG_INFO(fmt, ...) \
	pr_info("%s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#define MVSW_LOG_ERROR(fmt, ...) \
	pr_err("%s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

DEC_ENUM_FUNC(netdev_cmd);
DEC_ENUM_FUNC(switchdev_notifier_type);
DEC_ENUM_FUNC(switchdev_attr_id);
DEC_ENUM_FUNC(switchdev_obj_id);
DEC_ENUM_FUNC(fib_event_type);
DEC_ENUM_FUNC(netevent_notif_type);
DEC_ENUM_FUNC(tc_setup_type);
DEC_ENUM_FUNC(flow_block_binder_type);
DEC_ENUM_FUNC(tc_matchall_command);
DEC_ENUM_FUNC(flow_cls_command);
DEC_ENUM_FUNC(flow_action_id);

#else /* CONFIG_MRVL_PRESTERA_DEBUG */
#define MVSW_LOG_INFO(...)
#define MVSW_LOG_ERROR(...)
#endif /* CONFIG_MRVL_PRESTERA_DEBUG */

#endif /* _MVSW_PRESTERA_LOG_H_ */
