/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 *
 * Copyright (c) 2019-2020 Marvell International Ltd. All rights reserved.
 *
 */
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/list.h>

#include "prestera_hw.h"
#include "prestera.h"
#include "prestera_log.h"
#include "prestera_fw_log.h"
#include "prestera_rxtx.h"

#define MVSW_PR_INIT_TIMEOUT 30000000	/* 30sec */
#define MVSW_PR_MIN_MTU 64
#define MVSW_PR_MSG_BUFF_CHUNK_SIZE	32	/* bytes */

enum mvsw_msg_type {
	MVSW_MSG_TYPE_SWITCH_INIT = 0x1,
	MVSW_MSG_TYPE_SWITCH_ATTR_SET = 0x2,

	MVSW_MSG_TYPE_PORT_ATTR_SET = 0x100,
	MVSW_MSG_TYPE_PORT_ATTR_GET = 0x101,
	MVSW_MSG_TYPE_PORT_INFO_GET = 0x110,

	MVSW_MSG_TYPE_VLAN_CREATE = 0x200,
	MVSW_MSG_TYPE_VLAN_DELETE = 0x201,
	MVSW_MSG_TYPE_VLAN_PORT_SET = 0x202,
	MVSW_MSG_TYPE_VLAN_PVID_SET = 0x203,

	MVSW_MSG_TYPE_FDB_ADD = 0x300,
	MVSW_MSG_TYPE_FDB_DELETE = 0x301,
	MVSW_MSG_TYPE_FDB_FLUSH_PORT = 0x310,
	MVSW_MSG_TYPE_FDB_FLUSH_VLAN = 0x311,
	MVSW_MSG_TYPE_FDB_FLUSH_PORT_VLAN = 0x312,
	MVSW_MSG_TYPE_FDB_MACVLAN_ADD = 0x320,
	MVSW_MSG_TYPE_FDB_MACVLAN_DEL = 0x321,

	MVSW_MSG_TYPE_LOG_LEVEL_SET,

	MVSW_MSG_TYPE_BRIDGE_CREATE = 0x400,
	MVSW_MSG_TYPE_BRIDGE_DELETE = 0x401,
	MVSW_MSG_TYPE_BRIDGE_PORT_ADD = 0x402,
	MVSW_MSG_TYPE_BRIDGE_PORT_DELETE = 0x403,

	MVSW_MSG_TYPE_ACL_RULE_ADD = 0x500,
	MVSW_MSG_TYPE_ACL_RULE_DELETE = 0x501,
	MVSW_MSG_TYPE_ACL_RULE_STATS_GET = 0x510,
	MVSW_MSG_TYPE_ACL_RULESET_CREATE = 0x520,
	MVSW_MSG_TYPE_ACL_RULESET_DELETE = 0x521,
	MVSW_MSG_TYPE_ACL_PORT_BIND = 0x530,
	MVSW_MSG_TYPE_ACL_PORT_UNBIND = 0x531,

	MVSW_MSG_TYPE_ROUTER_RIF_CREATE = 0x600,
	MVSW_MSG_TYPE_ROUTER_RIF_DELETE = 0x601,
	MVSW_MSG_TYPE_ROUTER_RIF_SET = 0x602,
	MVSW_MSG_TYPE_ROUTER_LPM_ADD = 0x610,
	MVSW_MSG_TYPE_ROUTER_LPM_DELETE = 0x611,
	MVSW_MSG_TYPE_ROUTER_NH_GRP_SET = 0x622,
	MVSW_MSG_TYPE_ROUTER_NH_GRP_GET = 0x644,
	MVSW_MSG_TYPE_ROUTER_NH_GRP_ADD = 0x623,
	MVSW_MSG_TYPE_ROUTER_NH_GRP_DELETE = 0x624,
	MVSW_MSG_TYPE_ROUTER_VR_CREATE = 0x630,
	MVSW_MSG_TYPE_ROUTER_VR_DELETE = 0x631,
	MVSW_MSG_TYPE_ROUTER_VR_ABORT = 0x632,
	MVSW_MSG_TYPE_ROUTER_MP_HASH_SET = 0x650,

	MVSW_MSG_TYPE_RXTX_INIT = 0x800,

	MVSW_MSG_TYPE_LAG_ADD = 0x900,
	MVSW_MSG_TYPE_LAG_DELETE = 0x901,
	MVSW_MSG_TYPE_LAG_ENABLE = 0x902,
	MVSW_MSG_TYPE_LAG_DISABLE = 0x903,
	MVSW_MSG_TYPE_LAG_ROUTER_LEAVE = 0x904,

	MVSW_MSG_TYPE_STP_PORT_SET = 0x1000,

	MVSW_MSG_TYPE_ACK = 0x10000,
	MVSW_MSG_TYPE_MAX
};

enum mvsw_msg_port_attr {
	MVSW_MSG_PORT_ATTR_ADMIN_STATE = 1,
	MVSW_MSG_PORT_ATTR_OPER_STATE = 2,
	MVSW_MSG_PORT_ATTR_MTU = 3,
	MVSW_MSG_PORT_ATTR_MAC = 4,
	MVSW_MSG_PORT_ATTR_SPEED = 5,
	MVSW_MSG_PORT_ATTR_ACCEPT_FRAME_TYPE = 6,
	MVSW_MSG_PORT_ATTR_LEARNING = 7,
	MVSW_MSG_PORT_ATTR_FLOOD = 8,
	MVSW_MSG_PORT_ATTR_CAPABILITY = 9,
	MVSW_MSG_PORT_ATTR_REMOTE_CAPABILITY = 10,
	MVSW_MSG_PORT_ATTR_REMOTE_FC = 11,
	MVSW_MSG_PORT_ATTR_LINK_MODE = 12,
	MVSW_MSG_PORT_ATTR_TYPE = 13,
	MVSW_MSG_PORT_ATTR_FEC = 14,
	MVSW_MSG_PORT_ATTR_AUTONEG = 15,
	MVSW_MSG_PORT_ATTR_DUPLEX = 16,
	MVSW_MSG_PORT_ATTR_STATS = 17,
	MVSW_MSG_PORT_ATTR_MDIX = 18,
	MVSW_MSG_PORT_ATTR_AUTONEG_RESTART = 19,
	MVSW_MSG_PORT_ATTR_MAX
};

enum mvsw_msg_switch_attr {
	MVSW_MSG_SWITCH_ATTR_MAC = 1,
	MVSW_MSG_SWITCH_ATTR_AGEING = 2,
	MVSW_MSG_SWITCH_ATTR_TRAP_POLICER = 3,
};

enum {
	MVSW_MSG_ACK_OK,
	MVSW_MSG_ACK_FAILED,
	MVSW_MSG_ACK_MAX
};

enum {
	MVSW_PORT_TP_NA,
	MVSW_PORT_TP_MDI,
	MVSW_PORT_TP_MDIX,
	MVSW_PORT_TP_AUTO
};

enum {
	MVSW_PORT_GOOD_OCTETS_RCV_CNT,
	MVSW_PORT_BAD_OCTETS_RCV_CNT,
	MVSW_PORT_MAC_TRANSMIT_ERR_CNT,
	MVSW_PORT_BRDC_PKTS_RCV_CNT,
	MVSW_PORT_MC_PKTS_RCV_CNT,
	MVSW_PORT_PKTS_64_OCTETS_CNT,
	MVSW_PORT_PKTS_65TO127_OCTETS_CNT,
	MVSW_PORT_PKTS_128TO255_OCTETS_CNT,
	MVSW_PORT_PKTS_256TO511_OCTETS_CNT,
	MVSW_PORT_PKTS_512TO1023_OCTETS_CNT,
	MVSW_PORT_PKTS_1024TOMAX_OCTETS_CNT,
	MVSW_PORT_EXCESSIVE_COLLISIONS_CNT,
	MVSW_PORT_MC_PKTS_SENT_CNT,
	MVSW_PORT_BRDC_PKTS_SENT_CNT,
	MVSW_PORT_FC_SENT_CNT,
	MVSW_PORT_GOOD_FC_RCV_CNT,
	MVSW_PORT_DROP_EVENTS_CNT,
	MVSW_PORT_UNDERSIZE_PKTS_CNT,
	MVSW_PORT_FRAGMENTS_PKTS_CNT,
	MVSW_PORT_OVERSIZE_PKTS_CNT,
	MVSW_PORT_JABBER_PKTS_CNT,
	MVSW_PORT_MAC_RCV_ERROR_CNT,
	MVSW_PORT_BAD_CRC_CNT,
	MVSW_PORT_COLLISIONS_CNT,
	MVSW_PORT_LATE_COLLISIONS_CNT,
	MVSW_PORT_GOOD_UC_PKTS_RCV_CNT,
	MVSW_PORT_GOOD_UC_PKTS_SENT_CNT,
	MVSW_PORT_MULTIPLE_PKTS_SENT_CNT,
	MVSW_PORT_DEFERRED_PKTS_SENT_CNT,
	MVSW_PORT_GOOD_OCTETS_SENT_CNT,
	MVSW_PORT_CNT_MAX,
};

enum {
	MVSW_FC_NONE,
	MVSW_FC_SYMMETRIC,
	MVSW_FC_ASYMMETRIC,
	MVSW_FC_SYMM_ASYMM,
};

enum {
	MVSW_HW_FDB_ENTRY_TYPE_REG_PORT = 0,
	MVSW_HW_FDB_ENTRY_TYPE_LAG = 1,
	MVSW_HW_FDB_ENTRY_TYPE_MAX = 2,
};

enum {
	MVSW_PORT_FLOOD_TYPE_UC = 0,
	MVSW_PORT_FLOOD_TYPE_MC = 1,
	MVSW_PORT_FLOOD_TYPE_BC = 2,
};

struct mvsw_msg_buff {
	u32 free;
	u32 total;
	u32 used;
	void *data;
};

struct mvsw_msg_cmd {
	u32 type;
} __packed __aligned(4);

struct mvsw_msg_ret {
	struct mvsw_msg_cmd cmd;
	u32 status;
} __packed __aligned(4);

struct mvsw_msg_common_request {
	struct mvsw_msg_cmd cmd;
} __packed __aligned(4);

struct mvsw_msg_common_response {
	struct mvsw_msg_ret ret;
} __packed __aligned(4);

union mvsw_msg_switch_param {
	u32 ageing_timeout;
	u8  mac[ETH_ALEN];
	u32 trap_policer_profile;
};

struct mvsw_msg_switch_attr_cmd {
	struct mvsw_msg_cmd cmd;
	u32 attr;
	union mvsw_msg_switch_param param;
} __packed __aligned(4);

struct mvsw_msg_switch_init_ret {
	struct mvsw_msg_ret ret;
	u32 port_count;
	u32 mtu_max;
	u8  switch_id;
	u8  lag_max;
	u8  lag_member_max;
} __packed __aligned(4);

struct mvsw_msg_port_autoneg_param {
	u64 link_mode;
	u8  enable;
	u8  fec;
};

struct mvsw_msg_port_cap_param {
	u64 link_mode;
	u8  type;
	u8  fec;
	u8  transceiver;
};

struct mvsw_msg_port_mdix_param {
	u8 status;
	u8 admin_mode;
};

struct mvsw_msg_port_flood_param {
	u8 type;
	u8 enable;
};

union mvsw_msg_port_param {
	u8  admin_state;
	u8  oper_state;
	u32 mtu;
	u8  mac[ETH_ALEN];
	u8  accept_frm_type;
	u8  learning;
	u32 speed;
	u32 link_mode;
	u8  type;
	u8  duplex;
	u8  fec;
	u8  fc;
	struct mvsw_msg_port_mdix_param mdix;
	struct mvsw_msg_port_autoneg_param autoneg;
	struct mvsw_msg_port_cap_param cap;
	struct mvsw_msg_port_flood_param flood;
};

struct mvsw_msg_port_attr_cmd {
	struct mvsw_msg_cmd cmd;
	u32 attr;
	u32 port;
	u32 dev;
	union mvsw_msg_port_param param;
} __packed __aligned(4);

struct mvsw_msg_port_attr_ret {
	struct mvsw_msg_ret ret;
	union mvsw_msg_port_param param;
} __packed __aligned(4);

struct mvsw_msg_port_stats_ret {
	struct mvsw_msg_ret ret;
	u64 stats[MVSW_PORT_CNT_MAX];
} __packed __aligned(4);

struct mvsw_msg_port_info_cmd {
	struct mvsw_msg_cmd cmd;
	u32 port;
} __packed __aligned(4);

struct mvsw_msg_port_info_ret {
	struct mvsw_msg_ret ret;
	u32 hw_id;
	u32 dev_id;
	u16 fp_id;
} __packed __aligned(4);

struct mvsw_msg_vlan_cmd {
	struct mvsw_msg_cmd cmd;
	u32 port;
	u32 dev;
	u16 vid;
	u8  is_member;
	u8  is_tagged;
} __packed __aligned(4);

struct mvsw_msg_fdb_cmd {
	struct mvsw_msg_cmd cmd;
	u8 dest_type;
	union {
		struct {
			u32 port;
			u32 dev;
		};
		u16 lag_id;
	} dest;
	u8  mac[ETH_ALEN];
	u16 vid;
	u8  dynamic;
	u32 flush_mode;
} __packed __aligned(4);

struct mvsw_msg_log_lvl_set_cmd {
	struct mvsw_msg_cmd cmd;
	u32 lib;
	u32 type;
} __packed __aligned(4);

struct mvsw_msg_acl_rule_cmd {
	struct mvsw_msg_cmd cmd;
	u32 id;
	u16 ruleset_id;
} __packed __aligned(4);

struct mvsw_msg_acl_rule_ret {
	struct mvsw_msg_ret ret;
	u32 id;
} __packed __aligned(4);

struct mvsw_msg_acl_rule_stats_ret {
	struct mvsw_msg_ret ret;
	u64 packets;
	u64 bytes;
} __packed __aligned(4);

struct mvsw_msg_acl_ruleset_bind_cmd {
	struct mvsw_msg_cmd cmd;
	u32 port;
	u32 dev;
	u16 ruleset_id;
} __packed __aligned(4);

struct mvsw_msg_acl_ruleset_cmd {
	struct mvsw_msg_cmd cmd;
	u16 id;
} __packed __aligned(4);

struct mvsw_msg_acl_ruleset_ret {
	struct mvsw_msg_ret ret;
	u16 id;
} __packed __aligned(4);

struct mvsw_msg_event {
	u16 type;
	u16 id;
} __packed __aligned(4);

struct mvsw_msg_event_log {
	struct mvsw_msg_event id;
	u32 log_string_size;
	u8 log_string[0];
} __packed __aligned(4);

union mvsw_msg_event_fdb_param {
	u8 mac[ETH_ALEN];
};

struct mvsw_msg_event_fdb {
	struct mvsw_msg_event id;
	u8 dest_type;
	union {
		u32 port_id;
		u16 lag_id;
	} dest;
	u32 vid;
	union mvsw_msg_event_fdb_param param;
} __packed __aligned(4);

struct mvsw_msg_event_port_param {
	u8 oper_state;
	u8 duplex;
	u32 speed;
} __packed __aligned(4);

struct mvsw_msg_event_port {
	struct mvsw_msg_event id;
	u32 port_id;
	struct mvsw_msg_event_port_param param;
} __packed __aligned(4);

struct mvsw_msg_bridge_cmd {
	struct mvsw_msg_cmd cmd;
	u32 port;
	u32 dev;
	u16 bridge;
} __packed __aligned(4);

struct mvsw_msg_bridge_ret {
	struct mvsw_msg_ret ret;
	u16 bridge;
} __packed __aligned(4);

struct mvsw_msg_macvlan_cmd {
	struct mvsw_msg_cmd cmd;
	u16 vr_id;
	u8 mac[ETH_ALEN];
	u16 vid;
} __packed __aligned(4);

struct mvsw_msg_stp_cmd {
	struct mvsw_msg_cmd cmd;
	u32 port;
	u32 dev;
	u16 vid;
	u8  state;
} __packed __aligned(4);

struct mvsw_msg_iface {
	u8 type;
	u16 vid;
	u16 vr_id;
	union {
		struct {
			u32 dev;
			u32 port;
		};
		u16 lag_id;
	};
} __packed __aligned(4);

struct mvsw_msg_rif_cmd {
	struct mvsw_msg_cmd cmd;
	struct mvsw_msg_iface iif;
	u16 rif_id;
	u8 mac[ETH_ALEN];
	u32 mtu;
} __packed __aligned(4);

struct mvsw_msg_rif_ret {
	struct mvsw_msg_ret ret;
	u16 rif_id;
} __packed __aligned(4);

struct mvsw_msg_lpm_cmd {
	struct mvsw_msg_cmd cmd;
	u32 grp_id;
	__be32 dst;
	u32 dst_len;
	u16 vr_id;
} __packed __aligned(4);

struct mvsw_msg_nh {
	struct mvsw_msg_iface oif;
	u8 is_active;
	u32 hw_id;
	u8 mac[ETH_ALEN];
} __packed __aligned(4);

struct mvsw_msg_nh_cmd {
	struct mvsw_msg_cmd cmd;
	u32 size;
	u32 grp_id;
	struct mvsw_msg_nh nh[MVSW_PR_NHGR_SIZE_MAX];
} __packed __aligned(4);

struct mvsw_msg_nh_ret {
	struct mvsw_msg_ret ret;
	struct mvsw_msg_nh nh[MVSW_PR_NHGR_SIZE_MAX];
} __packed __aligned(4);

struct mvsw_msg_nh_grp_cmd {
	struct mvsw_msg_cmd cmd;
	u32 grp_id;
	u32 size;
} __packed __aligned(4);

struct mvsw_msg_nh_grp_ret {
	struct mvsw_msg_ret ret;
	u32 grp_id;
} __packed __aligned(4);

struct mvsw_msg_mp_cmd {
	struct mvsw_msg_cmd cmd;
	u8 hash_policy;
} __packed __aligned(4);

struct mvsw_msg_rxtx_cmd {
	struct mvsw_msg_cmd cmd;
	u8 use_sdma;
} __packed __aligned(4);

struct mvsw_msg_rxtx_ret {
	struct mvsw_msg_ret ret;
	u32 map_addr;
} __packed __aligned(4);

struct mvsw_msg_vr_cmd {
	struct mvsw_msg_cmd cmd;
	u16 vr_id;
} __packed __aligned(4);

struct mvsw_msg_vr_ret {
	struct mvsw_msg_ret ret;
	u16 vr_id;
} __packed __aligned(4);

struct mvsw_msg_lag_cmd {
	struct mvsw_msg_cmd cmd;
	u32 port;
	u32 dev;
	u16 lag_id;
	u16 vr_id;
} __packed __aligned(4);

#define fw_check_resp(_response)	\
({								\
	int __er = 0;						\
	typeof(_response) __r = (_response);			\
	if (__r->ret.cmd.type != MVSW_MSG_TYPE_ACK)		\
		__er = -EBADE;					\
	else if (__r->ret.status != MVSW_MSG_ACK_OK)		\
		__er = -EINVAL;					\
	(__er);							\
})

#define __fw_send_req_resp(_switch, _type, _req, _req_size,	\
_response, _wait)						\
({								\
	int __e;						\
	typeof(_switch) __sw = (_switch);			\
	typeof(_req) __req = (_req);				\
	typeof(_response) __resp = (_response);			\
	__req->cmd.type = (_type);				\
	__e = __sw->dev->send_req(__sw->dev,			\
		(u8 *)__req, _req_size,				\
		(u8 *)__resp, sizeof(*__resp),			\
		_wait);						\
	if (!__e)						\
		__e = fw_check_resp(__resp);			\
	(__e);							\
})

#define fw_send_nreq_resp(_sw, _t, _req, _req_size, _resp)	\
	__fw_send_req_resp(_sw, _t, _req, _req_size, _resp, 0)

#define fw_send_req_resp(_sw, _t, _req, _resp)	\
	__fw_send_req_resp(_sw, _t, _req, sizeof(*_req), _resp, 0)

#define fw_send_req_resp_wait(_sw, _t, _req, _resp, _wait)	\
	__fw_send_req_resp(_sw, _t, _req, sizeof(*_req), _resp, _wait)

#define fw_send_req(_sw, _t, _req)	\
({							\
	struct mvsw_msg_common_response __re;		\
	(fw_send_req_resp(_sw, _t, _req, &__re));	\
})

struct mvsw_fw_event_handler {
	struct list_head list;
	enum mvsw_pr_event_type type;
	void (*func)(struct mvsw_pr_switch *sw,
		     struct mvsw_pr_event *evt,
		     void *arg);
	void *arg;
};

static int fw_parse_port_evt(u8 *msg, struct mvsw_pr_event *evt)
{
	struct mvsw_msg_event_port *hw_evt = (struct mvsw_msg_event_port *)msg;

	evt->port_evt.port_id = hw_evt->port_id;

	if (evt->id == MVSW_PORT_EVENT_STATE_CHANGED) {
		evt->port_evt.data.oper_state = hw_evt->param.oper_state;
		evt->port_evt.data.duplex = hw_evt->param.duplex;
		evt->port_evt.data.speed = hw_evt->param.speed;
	} else {
		return -EINVAL;
	}
	return 0;
}

static int fw_parse_fdb_evt(u8 *msg, struct mvsw_pr_event *evt)
{
	struct mvsw_msg_event_fdb *hw_evt = (struct mvsw_msg_event_fdb *)msg;

	switch (hw_evt->dest_type) {
	case MVSW_HW_FDB_ENTRY_TYPE_REG_PORT:
		evt->fdb_evt.type = MVSW_PR_FDB_ENTRY_TYPE_REG_PORT;
		evt->fdb_evt.dest.port_id = hw_evt->dest.port_id;
		break;
	case MVSW_HW_FDB_ENTRY_TYPE_LAG:
		evt->fdb_evt.type = MVSW_PR_FDB_ENTRY_TYPE_LAG;
		evt->fdb_evt.dest.lag_id = hw_evt->dest.lag_id;
		break;
	default:
		return -EINVAL;
	}

	evt->fdb_evt.vid = hw_evt->vid;

	memcpy(&evt->fdb_evt.data, &hw_evt->param, sizeof(u8) * ETH_ALEN);

	return 0;
}

static int fw_parse_log_evt(u8 *msg, struct mvsw_pr_event *evt)
{
	struct mvsw_msg_event_log *hw_evt = (struct mvsw_msg_event_log *)msg;

	evt->fw_log_evt.log_len	= hw_evt->log_string_size;
	evt->fw_log_evt.data	= hw_evt->log_string;

	return 0;
}

struct mvsw_fw_evt_parser {
	int (*func)(u8 *msg, struct mvsw_pr_event *evt);
};

static struct mvsw_fw_evt_parser fw_event_parsers[MVSW_EVENT_TYPE_MAX] = {
	[MVSW_EVENT_TYPE_PORT] = {.func = fw_parse_port_evt},
	[MVSW_EVENT_TYPE_FDB] = {.func = fw_parse_fdb_evt},
	[MVSW_EVENT_TYPE_FW_LOG] = {.func = fw_parse_log_evt}
};

static struct mvsw_fw_event_handler *
__find_event_handler(const struct mvsw_pr_switch *sw,
		     enum mvsw_pr_event_type type)
{
	struct mvsw_fw_event_handler *eh;

	list_for_each_entry_rcu(eh, &sw->event_handlers, list) {
		if (eh->type == type)
			return eh;
	}

	return NULL;
}

static int mvsw_find_event_handler(const struct mvsw_pr_switch *sw,
				   enum mvsw_pr_event_type type,
				   struct mvsw_fw_event_handler *eh)
{
	struct mvsw_fw_event_handler *tmp;
	int err = 0;

	rcu_read_lock();
	tmp = __find_event_handler(sw, type);
	if (tmp)
		*eh = *tmp;
	else
		err = -EEXIST;
	rcu_read_unlock();

	return err;
}

static int fw_event_recv(struct prestera_device *dev, u8 *buf, size_t size)
{
	struct mvsw_msg_event *msg = (struct mvsw_msg_event *)buf;
	struct mvsw_pr_switch *sw = dev->priv;
	struct mvsw_fw_event_handler eh;
	struct mvsw_pr_event evt;
	int err;

	if (msg->type >= MVSW_EVENT_TYPE_MAX)
		return -EINVAL;

	err = mvsw_find_event_handler(sw, msg->type, &eh);

	if (err || !fw_event_parsers[msg->type].func)
		return 0;

	evt.id = msg->id;

	err = fw_event_parsers[msg->type].func(buf, &evt);
	if (!err)
		eh.func(sw, &evt, eh.arg);

	return err;
}

static void fw_pkt_recv(struct prestera_device *dev)
{
	struct mvsw_pr_switch *sw = dev->priv;
	struct mvsw_fw_event_handler eh;
	struct mvsw_pr_event ev;
	int err;

	ev.id = MVSW_RXTX_EVENT_RCV_PKT;

	err = mvsw_find_event_handler(sw, MVSW_EVENT_TYPE_RXTX, &eh);
	if (err)
		return;

	eh.func(sw, &ev, eh.arg);
}

static struct mvsw_msg_buff *mvsw_msg_buff_create(u16 head_size)
{
	struct mvsw_msg_buff *msg_buff;

	msg_buff = kzalloc(sizeof(*msg_buff), GFP_KERNEL);
	if (!msg_buff)
		return NULL;

	msg_buff->data = kzalloc(MVSW_PR_MSG_BUFF_CHUNK_SIZE + head_size,
				 GFP_KERNEL);
	if (!msg_buff->data) {
		kfree(msg_buff);
		return NULL;
	}

	msg_buff->total = MVSW_PR_MSG_BUFF_CHUNK_SIZE + head_size;
	msg_buff->free = MVSW_PR_MSG_BUFF_CHUNK_SIZE;
	msg_buff->used = head_size;

	return msg_buff;
}

static void *mvsw_msg_buff_data(struct mvsw_msg_buff *msg_buff)
{
	return msg_buff->data;
}

static u32 mvsw_msg_buff_size(const struct mvsw_msg_buff *msg_buff)
{
	return msg_buff->used;
}

static int mvsw_msg_buff_resize(struct mvsw_msg_buff *msg_buff)
{
	void *data;

	data = krealloc(msg_buff->data,
			msg_buff->total + MVSW_PR_MSG_BUFF_CHUNK_SIZE,
			GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	msg_buff->total += MVSW_PR_MSG_BUFF_CHUNK_SIZE;
	msg_buff->free += MVSW_PR_MSG_BUFF_CHUNK_SIZE;
	msg_buff->data = data;

	return 0;
}

static int mvsw_msg_buff_put(struct mvsw_msg_buff *msg_buff,
			     void *data, u16 size)
{
	void *data_ptr;
	int err;

	if (size > msg_buff->free) {
		err = mvsw_msg_buff_resize(msg_buff);
		if (err)
			return err;
	}
	/* point to unused data */
	data_ptr = msg_buff->data + msg_buff->used;

	/* set the data */
	memcpy(data_ptr, data, size);
	msg_buff->used += size;
	msg_buff->free -= size;

	return 0;
}

static int mvsw_msg_buff_terminate(struct mvsw_msg_buff *msg_buff)
{
	u16 padding_size;
	void *data_ptr;
	int err;

	/* the data should be aligned to 4 byte, so calculate
	 * the padding leaving at least one byte for termination
	 */
	padding_size = ALIGN(msg_buff->used + sizeof(u8),
			     sizeof(u32)) - msg_buff->used;
	if (msg_buff->free < padding_size) {
		err = mvsw_msg_buff_resize(msg_buff);
		if (err)
			return err;
	}
	/* point to unused data */
	data_ptr = msg_buff->data + msg_buff->used;

	/* terminate buffer by zero byte */
	memset(data_ptr, 0, padding_size);
	msg_buff->used += padding_size;
	msg_buff->free -= padding_size;
	data_ptr += padding_size;

	return 0;
}

static void mvsw_msg_buff_destroy(struct mvsw_msg_buff *msg_buff)
{
	kfree(msg_buff->data);
	kfree(msg_buff);
}

int mvsw_pr_hw_port_info_get(const struct mvsw_pr_port *port,
			     u16 *fp_id, u32 *hw_id, u32 *dev_id)
{
	struct mvsw_msg_port_info_ret resp;
	struct mvsw_msg_port_info_cmd req = {
		.port = port->id
	};
	int err;

	err = fw_send_req_resp(port->sw, MVSW_MSG_TYPE_PORT_INFO_GET,
			       &req, &resp);
	if (err)
		return err;

	*hw_id = resp.hw_id;
	*dev_id = resp.dev_id;
	*fp_id = resp.fp_id;

	return 0;
}

int mvsw_pr_hw_switch_init(struct mvsw_pr_switch *sw)
{
	struct mvsw_msg_switch_init_ret resp;
	struct mvsw_msg_common_request req;
	int err = 0;

	INIT_LIST_HEAD(&sw->event_handlers);

	err = fw_send_req_resp_wait(sw, MVSW_MSG_TYPE_SWITCH_INIT, &req, &resp,
				    MVSW_PR_INIT_TIMEOUT);
	if (err)
		return err;

	sw->id = resp.switch_id;
	sw->port_count = resp.port_count;
	sw->mtu_min = MVSW_PR_MIN_MTU;
	sw->mtu_max = resp.mtu_max;
	sw->lag_max = resp.lag_max;
	sw->lag_member_max = resp.lag_member_max;
	sw->dev->recv_msg = fw_event_recv;
	sw->dev->recv_pkt = fw_pkt_recv;

	return err;
}

int mvsw_pr_hw_switch_ageing_set(const struct mvsw_pr_switch *sw,
				 u32 ageing_time)
{
	struct mvsw_msg_switch_attr_cmd req = {
		.param = {.ageing_timeout = ageing_time},
		.attr = MVSW_MSG_SWITCH_ATTR_AGEING,
	};

	return fw_send_req(sw, MVSW_MSG_TYPE_SWITCH_ATTR_SET, &req);
}

int mvsw_pr_hw_switch_mac_set(const struct mvsw_pr_switch *sw, const u8 *mac)
{
	struct mvsw_msg_switch_attr_cmd req = {
		.attr = MVSW_MSG_SWITCH_ATTR_MAC,
	};

	memcpy(req.param.mac, mac, sizeof(req.param.mac));

	return fw_send_req(sw, MVSW_MSG_TYPE_SWITCH_ATTR_SET, &req);
}

int mvsw_pr_hw_switch_trap_policer_set(const struct mvsw_pr_switch *sw,
				       u8 profile)
{
	struct mvsw_msg_switch_attr_cmd req = {
		.param = {.trap_policer_profile = profile},
		.attr = MVSW_MSG_SWITCH_ATTR_TRAP_POLICER,
	};

	return fw_send_req(sw, MVSW_MSG_TYPE_SWITCH_ATTR_SET, &req);
}

int mvsw_pr_hw_port_state_set(const struct mvsw_pr_port *port,
			      bool admin_state)
{
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_ADMIN_STATE,
		.port = port->hw_id,
		.dev = port->dev_id,
		.param = {.admin_state = admin_state ? 1 : 0}
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_PORT_ATTR_SET, &req);
}

int mvsw_pr_hw_port_state_get(const struct mvsw_pr_port *port,
			      bool *admin_state, bool *oper_state)
{
	struct mvsw_msg_port_attr_ret resp;
	struct mvsw_msg_port_attr_cmd req = {
		.port = port->hw_id,
		.dev = port->dev_id
	};
	int err;

	if (admin_state) {
		req.attr = MVSW_MSG_PORT_ATTR_ADMIN_STATE;
		err = fw_send_req_resp(port->sw, MVSW_MSG_TYPE_PORT_ATTR_GET,
				       &req, &resp);
		if (err)
			return err;
		*admin_state = resp.param.admin_state != 0;
	}

	if (oper_state) {
		req.attr = MVSW_MSG_PORT_ATTR_OPER_STATE;
		err = fw_send_req_resp(port->sw, MVSW_MSG_TYPE_PORT_ATTR_GET,
				       &req, &resp);
		if (err)
			return err;
		*oper_state = resp.param.oper_state != 0;
	}

	return 0;
}

int mvsw_pr_hw_port_mtu_set(const struct mvsw_pr_port *port, u32 mtu)
{
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_MTU,
		.port = port->hw_id,
		.dev = port->dev_id,
		.param = {.mtu = mtu}
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_PORT_ATTR_SET, &req);
}

int mvsw_pr_hw_port_mtu_get(const struct mvsw_pr_port *port, u32 *mtu)
{
	struct mvsw_msg_port_attr_ret resp;
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_MTU,
		.port = port->hw_id,
		.dev = port->dev_id
	};
	int err;

	err = fw_send_req_resp(port->sw, MVSW_MSG_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	*mtu = resp.param.mtu;

	return err;
}

int mvsw_pr_hw_port_mac_set(const struct mvsw_pr_port *port, char *mac)
{
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_MAC,
		.port = port->hw_id,
		.dev = port->dev_id
	};
	memcpy(&req.param.mac, mac, sizeof(req.param.mac));

	return fw_send_req(port->sw, MVSW_MSG_TYPE_PORT_ATTR_SET, &req);
}

int mvsw_pr_hw_port_mac_get(const struct mvsw_pr_port *port, char *mac)
{
	struct mvsw_msg_port_attr_ret resp;
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_MAC,
		.port = port->hw_id,
		.dev = port->dev_id
	};
	int err;

	err = fw_send_req_resp(port->sw, MVSW_MSG_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	memcpy(mac, resp.param.mac, sizeof(resp.param.mac));

	return err;
}

int mvsw_pr_hw_port_accept_frame_type_set(const struct mvsw_pr_port *port,
					  enum mvsw_pr_accept_frame_type type)
{
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_ACCEPT_FRAME_TYPE,
		.port = port->hw_id,
		.dev = port->dev_id,
		.param = {.accept_frm_type = type}
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_PORT_ATTR_SET, &req);
}

int mvsw_pr_hw_port_learning_set(const struct mvsw_pr_port *port, bool enable)
{
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_LEARNING,
		.port = port->hw_id,
		.dev = port->dev_id,
		.param = {.learning = enable ? 1 : 0}
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_PORT_ATTR_SET, &req);
}

int mvsw_pr_hw_event_handler_register(struct mvsw_pr_switch *sw,
				      enum mvsw_pr_event_type type,
				      void (*cb)(struct mvsw_pr_switch *sw,
						 struct mvsw_pr_event *evt,
						 void *arg),
				      void *arg)
{
	struct mvsw_fw_event_handler *eh;

	eh = __find_event_handler(sw, type);
	if (eh)
		return -EEXIST;
	eh = kmalloc(sizeof(*eh), GFP_KERNEL);
	if (!eh)
		return -ENOMEM;

	eh->type = type;
	eh->func = cb;
	eh->arg = arg;

	INIT_LIST_HEAD(&eh->list);

	list_add_rcu(&eh->list, &sw->event_handlers);

	return 0;
}

void mvsw_pr_hw_event_handler_unregister(struct mvsw_pr_switch *sw,
					 enum mvsw_pr_event_type type)
{
	struct mvsw_fw_event_handler *eh;

	eh = __find_event_handler(sw, type);
	if (!eh)
		return;

	list_del_rcu(&eh->list);
	synchronize_rcu();
	kfree(eh);
}

int mvsw_pr_hw_vlan_create(const struct mvsw_pr_switch *sw, u16 vid)
{
	struct mvsw_msg_vlan_cmd req = {
		.vid = vid,
	};

	return fw_send_req(sw, MVSW_MSG_TYPE_VLAN_CREATE, &req);
}

int mvsw_pr_hw_vlan_delete(const struct mvsw_pr_switch *sw, u16 vid)
{
	struct mvsw_msg_vlan_cmd req = {
		.vid = vid,
	};

	return fw_send_req(sw, MVSW_MSG_TYPE_VLAN_DELETE, &req);
}

int mvsw_pr_hw_vlan_port_set(const struct mvsw_pr_port *port,
			     u16 vid, bool is_member, bool untagged)
{
	struct mvsw_msg_vlan_cmd req = {
		.port = port->hw_id,
		.dev = port->dev_id,
		.vid = vid,
		.is_member = is_member ? 1 : 0,
		.is_tagged = untagged ? 0 : 1
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_VLAN_PORT_SET, &req);
}

int mvsw_pr_hw_vlan_port_vid_set(const struct mvsw_pr_port *port, u16 vid)
{
	struct mvsw_msg_vlan_cmd req = {
		.port = port->hw_id,
		.dev = port->dev_id,
		.vid = vid
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_VLAN_PVID_SET, &req);
}

int mvsw_pr_hw_port_vid_stp_set(struct mvsw_pr_port *port, u16 vid, u8 state)
{
	struct mvsw_msg_stp_cmd req = {
		.port = port->hw_id,
		.dev = port->dev_id,
		.vid = vid,
		.state = state
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_STP_PORT_SET, &req);
}

int mvsw_pr_hw_port_speed_get(const struct mvsw_pr_port *port, u32 *speed)
{
	struct mvsw_msg_port_attr_ret resp;
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_SPEED,
		.port = port->hw_id,
		.dev = port->dev_id
	};
	int err;

	err = fw_send_req_resp(port->sw, MVSW_MSG_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	*speed = resp.param.speed;

	return err;
}

int mvsw_pr_hw_port_uc_flood_set(const struct mvsw_pr_port *port, bool flood)
{
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_FLOOD,
		.port = port->hw_id,
		.dev = port->dev_id,
		.param = {
			.flood = {
				.type = MVSW_PORT_FLOOD_TYPE_UC,
				.enable = flood ? 1 : 0,
			}
		}
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_PORT_ATTR_SET, &req);
}

int mvsw_pr_hw_port_mc_flood_set(const struct mvsw_pr_port *port, bool flood)
{
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_FLOOD,
		.port = port->hw_id,
		.dev = port->dev_id,
		.param = {
			.flood = {
				.type = MVSW_PORT_FLOOD_TYPE_MC,
				.enable = flood ? 1 : 0,
			}
		}
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_PORT_ATTR_SET, &req);
}

int mvsw_pr_hw_fdb_add(const struct mvsw_pr_port *port,
		       const unsigned char *mac, u16 vid, bool dynamic)
{
	struct mvsw_msg_fdb_cmd req = {
		.dest_type = MVSW_HW_FDB_ENTRY_TYPE_REG_PORT,
		.dest = {
			.dev = port->dev_id,
			.port = port->hw_id,
		},
		.vid = vid,
		.dynamic = dynamic ? 1 : 0
	};

	memcpy(req.mac, mac, sizeof(req.mac));

	return fw_send_req(port->sw, MVSW_MSG_TYPE_FDB_ADD, &req);
}

int mvsw_pr_hw_lag_fdb_add(const struct mvsw_pr_switch *sw, u16 lag_id,
			   const unsigned char *mac, u16 vid, bool dynamic)
{
	struct mvsw_msg_fdb_cmd req = {
		.dest_type = MVSW_HW_FDB_ENTRY_TYPE_LAG,
		.dest = { .lag_id = lag_id },
		.vid = vid,
		.dynamic = dynamic
	};

	memcpy(req.mac, mac, sizeof(req.mac));

	return fw_send_req(sw, MVSW_MSG_TYPE_FDB_ADD, &req);
}

int mvsw_pr_hw_fdb_del(const struct mvsw_pr_port *port,
		       const unsigned char *mac, u16 vid)
{
	struct mvsw_msg_fdb_cmd req = {
		.dest_type = MVSW_HW_FDB_ENTRY_TYPE_REG_PORT,
		.dest = {
			.dev = port->dev_id,
			.port = port->hw_id,
		},
		.vid = vid
	};

	memcpy(req.mac, mac, sizeof(req.mac));

	return fw_send_req(port->sw, MVSW_MSG_TYPE_FDB_DELETE, &req);
}

int mvsw_pr_hw_lag_fdb_del(const struct mvsw_pr_switch *sw, u16 lag_id,
			   const unsigned char *mac, u16 vid)
{
	struct mvsw_msg_fdb_cmd req = {
		.dest_type = MVSW_HW_FDB_ENTRY_TYPE_LAG,
		.dest = { .lag_id = lag_id },
		.vid = vid
	};

	memcpy(req.mac, mac, sizeof(req.mac));

	return fw_send_req(sw, MVSW_MSG_TYPE_FDB_DELETE, &req);
}

int mvsw_pr_hw_port_cap_get(const struct mvsw_pr_port *port,
			    struct mvsw_pr_port_caps *caps)
{
	struct mvsw_msg_port_attr_ret resp;
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_CAPABILITY,
		.port = port->hw_id,
		.dev = port->dev_id
	};
	int err;

	err = fw_send_req_resp(port->sw, MVSW_MSG_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	caps->supp_link_modes = resp.param.cap.link_mode;
	caps->supp_fec = resp.param.cap.fec;
	caps->type = resp.param.cap.type;
	caps->transceiver = resp.param.cap.transceiver;

	return err;
}

int mvsw_pr_hw_port_remote_cap_get(const struct mvsw_pr_port *port,
				   u64 *link_mode_bitmap)
{
	struct mvsw_msg_port_attr_ret resp;
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_REMOTE_CAPABILITY,
		.port = port->hw_id,
		.dev = port->dev_id
	};
	int err;

	err = fw_send_req_resp(port->sw, MVSW_MSG_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	*link_mode_bitmap = resp.param.cap.link_mode;

	return err;
}

static u8 mvsw_mdix_to_eth(u8 mode)
{
	switch (mode) {
	case MVSW_PORT_TP_MDI:
		return ETH_TP_MDI;
	case MVSW_PORT_TP_MDIX:
		return ETH_TP_MDI_X;
	case MVSW_PORT_TP_AUTO:
		return ETH_TP_MDI_AUTO;
	}

	return ETH_TP_MDI_INVALID;
}

static u8 mvsw_mdix_from_eth(u8 mode)
{
	switch (mode) {
	case ETH_TP_MDI:
		return MVSW_PORT_TP_MDI;
	case ETH_TP_MDI_X:
		return MVSW_PORT_TP_MDIX;
	case ETH_TP_MDI_AUTO:
		return MVSW_PORT_TP_AUTO;
	}

	return MVSW_PORT_TP_NA;
}

int mvsw_pr_hw_port_mdix_get(const struct mvsw_pr_port *port, u8 *status,
			     u8 *admin_mode)
{
	struct mvsw_msg_port_attr_ret resp;
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_MDIX,
		.port = port->hw_id,
		.dev = port->dev_id
	};
	int err;

	err = fw_send_req_resp(port->sw, MVSW_MSG_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	*status = mvsw_mdix_to_eth(resp.param.mdix.status);
	*admin_mode = mvsw_mdix_to_eth(resp.param.mdix.admin_mode);

	return 0;
}

int mvsw_pr_hw_port_mdix_set(const struct mvsw_pr_port *port, u8 mode)
{
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_MDIX,
		.port = port->hw_id,
		.dev = port->dev_id
	};

	req.param.mdix.admin_mode = mvsw_mdix_from_eth(mode);

	return fw_send_req(port->sw, MVSW_MSG_TYPE_PORT_ATTR_SET, &req);
}

int mvsw_pr_hw_port_type_get(const struct mvsw_pr_port *port, u8 *type)
{
	struct mvsw_msg_port_attr_ret resp;
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_TYPE,
		.port = port->hw_id,
		.dev = port->dev_id
	};
	int err;

	err = fw_send_req_resp(port->sw, MVSW_MSG_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	*type = resp.param.type;

	return err;
}

int mvsw_pr_hw_port_fec_get(const struct mvsw_pr_port *port, u8 *fec)
{
	struct mvsw_msg_port_attr_ret resp;
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_FEC,
		.port = port->hw_id,
		.dev = port->dev_id
	};
	int err;

	err = fw_send_req_resp(port->sw, MVSW_MSG_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	*fec = resp.param.fec;

	return err;
}

int mvsw_pr_hw_port_fec_set(const struct mvsw_pr_port *port, u8 fec)
{
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_FEC,
		.port = port->hw_id,
		.dev = port->dev_id,
		.param = {.fec = fec}
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_PORT_ATTR_SET, &req);
}

int mvsw_pr_hw_fw_log_level_set(const struct mvsw_pr_switch *sw,
				u32 lib, u32 type)
{
	struct mvsw_msg_log_lvl_set_cmd req = {
		.lib = lib,
		.type = type
	};
	int err;

	err = fw_send_req(sw, MVSW_MSG_TYPE_LOG_LEVEL_SET, &req);
	if (err)
		return err;

	return 0;
}

int mvsw_pr_hw_port_autoneg_set(const struct mvsw_pr_port *port,
				bool autoneg, u64 link_modes, u8 fec)
{
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_AUTONEG,
		.port = port->hw_id,
		.dev = port->dev_id,
		.param = {.autoneg = {.link_mode = link_modes,
				      .enable = autoneg ? 1 : 0,
				      .fec = fec}
		}
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_PORT_ATTR_SET, &req);
}

int mvsw_pr_hw_port_duplex_get(const struct mvsw_pr_port *port, u8 *duplex)
{
	struct mvsw_msg_port_attr_ret resp;
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_DUPLEX,
		.port = port->hw_id,
		.dev = port->dev_id
	};
	int err;

	err = fw_send_req_resp(port->sw, MVSW_MSG_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	*duplex = resp.param.duplex;

	return err;
}

int mvsw_pr_hw_port_stats_get(const struct mvsw_pr_port *port,
			      struct mvsw_pr_port_stats *stats)
{
	struct mvsw_msg_port_stats_ret resp;
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_STATS,
		.port = port->hw_id,
		.dev = port->dev_id
	};
	u64 *hw_val = resp.stats;
	int err;

	err = fw_send_req_resp(port->sw, MVSW_MSG_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	stats->good_octets_received = hw_val[MVSW_PORT_GOOD_OCTETS_RCV_CNT];
	stats->bad_octets_received = hw_val[MVSW_PORT_BAD_OCTETS_RCV_CNT];
	stats->mac_trans_error = hw_val[MVSW_PORT_MAC_TRANSMIT_ERR_CNT];
	stats->broadcast_frames_received = hw_val[MVSW_PORT_BRDC_PKTS_RCV_CNT];
	stats->multicast_frames_received = hw_val[MVSW_PORT_MC_PKTS_RCV_CNT];
	stats->frames_64_octets = hw_val[MVSW_PORT_PKTS_64_OCTETS_CNT];
	stats->frames_65_to_127_octets =
		hw_val[MVSW_PORT_PKTS_65TO127_OCTETS_CNT];
	stats->frames_128_to_255_octets =
		hw_val[MVSW_PORT_PKTS_128TO255_OCTETS_CNT];
	stats->frames_256_to_511_octets =
		hw_val[MVSW_PORT_PKTS_256TO511_OCTETS_CNT];
	stats->frames_512_to_1023_octets =
		hw_val[MVSW_PORT_PKTS_512TO1023_OCTETS_CNT];
	stats->frames_1024_to_max_octets =
		hw_val[MVSW_PORT_PKTS_1024TOMAX_OCTETS_CNT];
	stats->excessive_collision = hw_val[MVSW_PORT_EXCESSIVE_COLLISIONS_CNT];
	stats->multicast_frames_sent = hw_val[MVSW_PORT_MC_PKTS_SENT_CNT];
	stats->broadcast_frames_sent = hw_val[MVSW_PORT_BRDC_PKTS_SENT_CNT];
	stats->fc_sent = hw_val[MVSW_PORT_FC_SENT_CNT];
	stats->fc_received = hw_val[MVSW_PORT_GOOD_FC_RCV_CNT];
	stats->buffer_overrun = hw_val[MVSW_PORT_DROP_EVENTS_CNT];
	stats->undersize = hw_val[MVSW_PORT_UNDERSIZE_PKTS_CNT];
	stats->fragments = hw_val[MVSW_PORT_FRAGMENTS_PKTS_CNT];
	stats->oversize = hw_val[MVSW_PORT_OVERSIZE_PKTS_CNT];
	stats->jabber = hw_val[MVSW_PORT_JABBER_PKTS_CNT];
	stats->rx_error_frame_received = hw_val[MVSW_PORT_MAC_RCV_ERROR_CNT];
	stats->bad_crc = hw_val[MVSW_PORT_BAD_CRC_CNT];
	stats->collisions = hw_val[MVSW_PORT_COLLISIONS_CNT];
	stats->late_collision = hw_val[MVSW_PORT_LATE_COLLISIONS_CNT];
	stats->unicast_frames_received = hw_val[MVSW_PORT_GOOD_UC_PKTS_RCV_CNT];
	stats->unicast_frames_sent = hw_val[MVSW_PORT_GOOD_UC_PKTS_SENT_CNT];
	stats->sent_multiple = hw_val[MVSW_PORT_MULTIPLE_PKTS_SENT_CNT];
	stats->sent_deferred = hw_val[MVSW_PORT_DEFERRED_PKTS_SENT_CNT];
	stats->good_octets_sent = hw_val[MVSW_PORT_GOOD_OCTETS_SENT_CNT];

	return 0;
}

int mvsw_pr_hw_bridge_create(const struct mvsw_pr_switch *sw, u16 *bridge_id)
{
	struct mvsw_msg_bridge_cmd req;
	struct mvsw_msg_bridge_ret resp;
	int err;

	err = fw_send_req_resp(sw, MVSW_MSG_TYPE_BRIDGE_CREATE, &req, &resp);
	if (err)
		return err;

	*bridge_id = resp.bridge;
	return err;
}

int mvsw_pr_hw_bridge_delete(const struct mvsw_pr_switch *sw, u16 bridge_id)
{
	struct mvsw_msg_bridge_cmd req = {
		.bridge = bridge_id
	};

	return fw_send_req(sw, MVSW_MSG_TYPE_BRIDGE_DELETE, &req);
}

int mvsw_pr_hw_bridge_port_add(const struct mvsw_pr_port *port, u16 bridge_id)
{
	struct mvsw_msg_bridge_cmd req = {
		.bridge = bridge_id,
		.port = port->hw_id,
		.dev = port->dev_id
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_BRIDGE_PORT_ADD, &req);
}

int mvsw_pr_hw_bridge_port_delete(const struct mvsw_pr_port *port,
				  u16 bridge_id)
{
	struct mvsw_msg_bridge_cmd req = {
		.bridge = bridge_id,
		.port = port->hw_id,
		.dev = port->dev_id
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_BRIDGE_PORT_DELETE, &req);
}

int mvsw_pr_hw_macvlan_add(const struct mvsw_pr_switch *sw, u16 vr_id,
			   const u8 *mac, u16 vid)
{
	struct mvsw_msg_macvlan_cmd req = {
		.vr_id = vr_id,
		.vid = vid
	};

	memcpy(req.mac, mac, ETH_ALEN);

	return fw_send_req(sw, MVSW_MSG_TYPE_FDB_MACVLAN_ADD, &req);
}

int mvsw_pr_hw_macvlan_del(const struct mvsw_pr_switch *sw, u16 vr_id,
			   const u8 *mac, u16 vid)
{
	struct mvsw_msg_macvlan_cmd req = {
		.vr_id = vr_id,
		.vid = vid
	};

	memcpy(req.mac, mac, ETH_ALEN);

	return fw_send_req(sw, MVSW_MSG_TYPE_FDB_MACVLAN_DEL, &req);
}

int mvsw_pr_hw_fdb_flush_port(const struct mvsw_pr_port *port, u32 mode)
{
	struct mvsw_msg_fdb_cmd req = {
		.dest_type = MVSW_HW_FDB_ENTRY_TYPE_REG_PORT,
		.dest = {
			.dev = port->dev_id,
			.port = port->hw_id,
		},
		.flush_mode = mode,
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_FDB_FLUSH_PORT, &req);
}

int mvsw_pr_hw_fdb_flush_lag(const struct mvsw_pr_switch *sw, u16 lag_id,
			     u32 mode)
{
	struct mvsw_msg_fdb_cmd req = {
		.dest_type = MVSW_HW_FDB_ENTRY_TYPE_LAG,
		.dest = { .lag_id = lag_id },
		.flush_mode = mode,
	};

	return fw_send_req(sw, MVSW_MSG_TYPE_FDB_FLUSH_PORT, &req);
}

int mvsw_pr_hw_fdb_flush_vlan(const struct mvsw_pr_switch *sw, u16 vid,
			      u32 mode)
{
	struct mvsw_msg_fdb_cmd req = {
		.vid = vid,
		.flush_mode = mode,
	};

	return fw_send_req(sw, MVSW_MSG_TYPE_FDB_FLUSH_VLAN, &req);
}

int mvsw_pr_hw_fdb_flush_port_vlan(const struct mvsw_pr_port *port, u16 vid,
				   u32 mode)
{
	struct mvsw_msg_fdb_cmd req = {
		.dest_type = MVSW_HW_FDB_ENTRY_TYPE_REG_PORT,
		.dest = {
			.dev = port->dev_id,
			.port = port->hw_id,
		},
		.vid = vid,
		.flush_mode = mode,
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_FDB_FLUSH_PORT_VLAN, &req);
}

int mvsw_pr_hw_fdb_flush_lag_vlan(const struct mvsw_pr_switch *sw,
				  u16 lag_id, u16 vid, u32 mode)
{
	struct mvsw_msg_fdb_cmd req = {
		.dest_type = MVSW_HW_FDB_ENTRY_TYPE_LAG,
		.dest = { .lag_id = lag_id },
		.vid = vid,
		.flush_mode = mode,
	};

	return fw_send_req(sw, MVSW_MSG_TYPE_FDB_FLUSH_PORT_VLAN, &req);
}

int mvsw_pr_hw_port_link_mode_get(const struct mvsw_pr_port *port,
				  u32 *mode)
{
	struct mvsw_msg_port_attr_ret resp;
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_LINK_MODE,
		.port = port->hw_id,
		.dev = port->dev_id
	};
	int err;

	err = fw_send_req_resp(port->sw, MVSW_MSG_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	*mode = resp.param.link_mode;

	return err;
}

int mvsw_pr_hw_port_link_mode_set(const struct mvsw_pr_port *port,
				  u32 mode)
{
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_LINK_MODE,
		.port = port->hw_id,
		.dev = port->dev_id,
		.param = {.link_mode = mode}
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_PORT_ATTR_SET, &req);
}

static int mvsw_pr_iface_to_msg(struct mvsw_pr_iface *iface,
				struct mvsw_msg_iface *msg_if)
{
	switch (iface->type) {
	case MVSW_IF_PORT_E:
	case MVSW_IF_VID_E:
		msg_if->port = iface->dev_port.port_num;
		msg_if->dev = iface->dev_port.hw_dev_num;
		break;
	case MVSW_IF_LAG_E:
		msg_if->lag_id = iface->lag_id;
		break;
	default:
		return -ENOTSUPP;
	}

	msg_if->vr_id = iface->vr_id;
	msg_if->vid = iface->vlan_id;
	msg_if->type = iface->type;
	return 0;
}

int mvsw_pr_hw_rif_create(const struct mvsw_pr_switch *sw,
			  struct mvsw_pr_iface *iif, u8 *mac, u16 *rif_id)
{
	struct mvsw_msg_rif_cmd req;
	struct mvsw_msg_rif_ret resp;
	int err;

	memcpy(req.mac, mac, ETH_ALEN);

	err = mvsw_pr_iface_to_msg(iif, &req.iif);
	if (err)
		return err;

	err = fw_send_req_resp(sw, MVSW_MSG_TYPE_ROUTER_RIF_CREATE,
			       &req, &resp);
	if (err)
		return err;

	*rif_id = resp.rif_id;
	return err;
}

int mvsw_pr_hw_rif_delete(const struct mvsw_pr_switch *sw, u16 rif_id,
			  struct mvsw_pr_iface *iif)
{
	struct mvsw_msg_rif_cmd req = {
		.rif_id = rif_id,
	};
	int err;

	err = mvsw_pr_iface_to_msg(iif, &req.iif);
	if (err)
		return err;

	return fw_send_req(sw, MVSW_MSG_TYPE_ROUTER_RIF_DELETE, &req);
}

int mvsw_pr_hw_rif_set(const struct mvsw_pr_switch *sw, u16 *rif_id,
		       struct mvsw_pr_iface *iif, u8 *mac)
{
	struct mvsw_msg_rif_ret resp;
	struct mvsw_msg_rif_cmd req = {
		.rif_id = *rif_id,
	};
	int err;

	memcpy(req.mac, mac, ETH_ALEN);

	err = mvsw_pr_iface_to_msg(iif, &req.iif);
	if (err)
		return err;

	err = fw_send_req_resp(sw, MVSW_MSG_TYPE_ROUTER_RIF_SET, &req, &resp);
	if (err)
		return err;

	*rif_id = resp.rif_id;
	return err;
}

int mvsw_pr_hw_vr_create(const struct mvsw_pr_switch *sw, u16 *vr_id)
{
	int err;
	struct mvsw_msg_vr_ret resp;
	struct mvsw_msg_vr_cmd req;

	err = fw_send_req_resp(sw, MVSW_MSG_TYPE_ROUTER_VR_CREATE, &req, &resp);
	if (err)
		return err;

	*vr_id = resp.vr_id;
	return err;
}

int mvsw_pr_hw_vr_delete(const struct mvsw_pr_switch *sw, u16 vr_id)
{
	struct mvsw_msg_vr_cmd req = {
		.vr_id = vr_id,
	};

	return fw_send_req(sw, MVSW_MSG_TYPE_ROUTER_VR_DELETE, &req);
}

int mvsw_pr_hw_vr_abort(const struct mvsw_pr_switch *sw, u16 vr_id)
{
	struct mvsw_msg_vr_cmd req = {
		.vr_id = vr_id,
	};

	return fw_send_req(sw, MVSW_MSG_TYPE_ROUTER_VR_ABORT, &req);
}

int mvsw_pr_hw_lpm_add(const struct mvsw_pr_switch *sw, u16 vr_id,
		       __be32 dst, u32 dst_len, u32 grp_id)
{
	struct mvsw_msg_lpm_cmd req = {
		.dst = dst,
		.dst_len = dst_len,
		.vr_id = vr_id,
		.grp_id = grp_id
	};

	return fw_send_req(sw, MVSW_MSG_TYPE_ROUTER_LPM_ADD, &req);
}

int mvsw_pr_hw_lpm_del(const struct mvsw_pr_switch *sw, u16 vr_id, __be32 dst,
		       u32 dst_len)
{
	struct mvsw_msg_lpm_cmd req = {
		.dst = dst,
		.dst_len = dst_len,
		.vr_id = vr_id,
	};

	return fw_send_req(sw, MVSW_MSG_TYPE_ROUTER_LPM_DELETE, &req);
}

int mvsw_pr_hw_nh_entries_set(const struct mvsw_pr_switch *sw, int count,
			      struct mvsw_pr_neigh_info *nhs, u32 grp_id)
{
	struct mvsw_msg_nh_cmd req = { .size = count, .grp_id = grp_id };
	int i, err;

	for (i = 0; i < count; i++) {
		req.nh[i].is_active = nhs[i].connected;
		memcpy(&req.nh[i].mac, nhs[i].ha, ETH_ALEN);
		err = mvsw_pr_iface_to_msg(&nhs[i].iface, &req.nh[i].oif);
		if (err)
			return err;
	}

	return fw_send_req(sw, MVSW_MSG_TYPE_ROUTER_NH_GRP_SET, &req);
}

/* TODO: more than one nh */
/* For now "count = 1" supported only */
int mvsw_pr_hw_nh_entries_get(const struct mvsw_pr_switch *sw, int count,
			      struct mvsw_pr_neigh_info *nhs, u32 grp_id)
{
	struct mvsw_msg_nh_cmd req = { .size = count, .grp_id = grp_id };
	struct mvsw_msg_nh_ret resp;
	int err, i;

	err = fw_send_req_resp(sw, MVSW_MSG_TYPE_ROUTER_NH_GRP_GET,
			       &req, &resp);
	if (err)
		return err;

	for (i = 0; i < count; i++)
		nhs[i].connected = resp.nh[i].is_active;

	return err;
}

int mvsw_pr_hw_nh_group_create(const struct mvsw_pr_switch *sw, u16 nh_count,
			       u32 *grp_id)
{
	struct mvsw_msg_nh_grp_cmd req = { .size = nh_count };
	struct mvsw_msg_nh_grp_ret resp;
	int err;

	err = fw_send_req_resp(sw, MVSW_MSG_TYPE_ROUTER_NH_GRP_ADD, &req,
			       &resp);
	if (err)
		return err;

	*grp_id = resp.grp_id;
	return err;
}

int mvsw_pr_hw_nh_group_delete(const struct mvsw_pr_switch *sw, u16 nh_count,
			       u32 grp_id)
{
	struct mvsw_msg_nh_grp_cmd req = {
	    .grp_id = grp_id,
	    .size = nh_count
	};

	return fw_send_req(sw, MVSW_MSG_TYPE_ROUTER_NH_GRP_DELETE, &req);
}

int mvsw_pr_hw_mp4_hash_set(const struct mvsw_pr_switch *sw, u8 hash_policy)
{
	struct mvsw_msg_mp_cmd req = { .hash_policy = hash_policy};

	return fw_send_req(sw, MVSW_MSG_TYPE_ROUTER_MP_HASH_SET, &req);
}

int mvsw_pr_hw_rxtx_init(const struct mvsw_pr_switch *sw, bool use_sdma,
			 u32 *map_addr)
{
	struct mvsw_msg_rxtx_ret resp;
	struct mvsw_msg_rxtx_cmd req;
	int err;

	req.use_sdma = use_sdma;

	err = fw_send_req_resp(sw, MVSW_MSG_TYPE_RXTX_INIT, &req, &resp);
	if (err)
		return err;

	if (map_addr)
		*map_addr = resp.map_addr;

	return 0;
}

int mvsw_pr_hw_port_autoneg_restart(struct mvsw_pr_port *port)
{
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_AUTONEG_RESTART,
		.port = port->hw_id,
		.dev = port->dev_id,
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_PORT_ATTR_SET, &req);
}

int mvsw_pr_hw_port_remote_fc_get(const struct mvsw_pr_port *port,
				  bool *pause, bool *asym_pause)
{
	struct mvsw_msg_port_attr_ret resp;
	struct mvsw_msg_port_attr_cmd req = {
		.attr = MVSW_MSG_PORT_ATTR_REMOTE_FC,
		.port = port->hw_id,
		.dev = port->dev_id
	};
	int err;

	err = fw_send_req_resp(port->sw, MVSW_MSG_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	switch (resp.param.fc) {
	case MVSW_FC_SYMMETRIC:
		*pause = true;
		*asym_pause = false;
		break;
	case MVSW_FC_ASYMMETRIC:
		*pause = false;
		*asym_pause = true;
		break;
	case MVSW_FC_SYMM_ASYMM:
		*pause = true;
		*asym_pause = true;
		break;
	default:
		*pause = false;
		*asym_pause = false;
	};

	return err;
}

/* ACL API */
int mvsw_pr_hw_acl_ruleset_create(const struct mvsw_pr_switch *sw,
				  u16 *ruleset_id)
{
	int err;
	struct mvsw_msg_acl_ruleset_ret resp;
	struct mvsw_msg_acl_ruleset_cmd req;

	err = fw_send_req_resp(sw, MVSW_MSG_TYPE_ACL_RULESET_CREATE,
			       &req, &resp);
	if (err)
		return err;

	*ruleset_id = resp.id;
	return 0;
}

int mvsw_pr_hw_acl_ruleset_del(const struct mvsw_pr_switch *sw,
			       u16 ruleset_id)
{
	struct mvsw_msg_acl_ruleset_cmd req = {
		.id = ruleset_id,
	};

	return fw_send_req(sw, MVSW_MSG_TYPE_ACL_RULESET_DELETE, &req);
}

static int acl_rule_add_put_actions(struct mvsw_msg_buff *msg,
				    struct prestera_acl_rule *rule)
{
	struct list_head *a_list = prestera_acl_rule_action_list_get(rule);
	u8 n_actions = prestera_acl_rule_action_len(rule);
	struct prestera_acl_rule_action_entry *a_entry;
	__be64 be64;
	int err;

	err = mvsw_msg_buff_put(msg, &n_actions, sizeof(n_actions));
	if (err)
		return err;

	list_for_each_entry(a_entry, a_list, list) {
		err = mvsw_msg_buff_put(msg, (u8 *)&a_entry->id, sizeof(u8));
		if (err)
			return err;

		switch (a_entry->id) {
		case MVSW_ACL_RULE_ACTION_ACCEPT:
		case MVSW_ACL_RULE_ACTION_DROP:
		case MVSW_ACL_RULE_ACTION_TRAP:
			/* just rule action id, no specific data */
			break;
		case MVSW_ACL_RULE_ACTION_POLICE:
			be64 = cpu_to_be64(a_entry->police.rate);
			err = mvsw_msg_buff_put(msg, &be64, sizeof(be64));
			be64 = cpu_to_be64(a_entry->police.burst);
			err = mvsw_msg_buff_put(msg, &be64, sizeof(be64));
			break;
		default:
			err = -EINVAL;
		}
		if (err)
			return err;
	}

	return 0;
}

static int acl_rule_add_put_matches(struct mvsw_msg_buff *msg,
				    struct prestera_acl_rule *rule)
{
	struct list_head *m_list = prestera_acl_rule_match_list_get(rule);
	struct prestera_acl_rule_match_entry *m_entry;
	int err;

	list_for_each_entry(m_entry, m_list, list) {
		err = mvsw_msg_buff_put(msg, (u8 *)&m_entry->type, sizeof(u8));
		if (err)
			return err;

		switch (m_entry->type) {
		case MVSW_ACL_RULE_MATCH_ENTRY_TYPE_ETH_TYPE:
		case MVSW_ACL_RULE_MATCH_ENTRY_TYPE_L4_PORT_SRC:
		case MVSW_ACL_RULE_MATCH_ENTRY_TYPE_L4_PORT_DST:
		case MVSW_ACL_RULE_MATCH_ENTRY_TYPE_VLAN_ID:
		case MVSW_ACL_RULE_MATCH_ENTRY_TYPE_VLAN_TPID:
			err = mvsw_msg_buff_put
				(msg, &m_entry->keymask.u16.key,
				 sizeof(m_entry->keymask.u16.key));
			err |= mvsw_msg_buff_put
				(msg, &m_entry->keymask.u16.mask,
				 sizeof(m_entry->keymask.u16.mask));
			break;
		case MVSW_ACL_RULE_MATCH_ENTRY_TYPE_ICMP_TYPE:
		case MVSW_ACL_RULE_MATCH_ENTRY_TYPE_ICMP_CODE:
		case MVSW_ACL_RULE_MATCH_ENTRY_TYPE_IP_PROTO:
			err = mvsw_msg_buff_put
				(msg, &m_entry->keymask.u8.key,
				 sizeof(m_entry->keymask.u8.key));
			err |= mvsw_msg_buff_put
				(msg, &m_entry->keymask.u8.mask,
				 sizeof(m_entry->keymask.u8.mask));
			break;
		case MVSW_ACL_RULE_MATCH_ENTRY_TYPE_ETH_SMAC:
		case MVSW_ACL_RULE_MATCH_ENTRY_TYPE_ETH_DMAC:
			err = mvsw_msg_buff_put
				(msg, &m_entry->keymask.mac.key,
				 sizeof(m_entry->keymask.mac.key));
			err |= mvsw_msg_buff_put
				(msg, &m_entry->keymask.mac.mask,
				 sizeof(m_entry->keymask.mac.mask));
			break;
		case MVSW_ACL_RULE_MATCH_ENTRY_TYPE_IP_SRC:
		case MVSW_ACL_RULE_MATCH_ENTRY_TYPE_IP_DST:
		case MVSW_ACL_RULE_MATCH_ENTRY_TYPE_L4_PORT_RANGE_SRC:
		case MVSW_ACL_RULE_MATCH_ENTRY_TYPE_L4_PORT_RANGE_DST:
			err = mvsw_msg_buff_put
				(msg, &m_entry->keymask.u32.key,
				 sizeof(m_entry->keymask.u32.key));
			err |= mvsw_msg_buff_put
				(msg, &m_entry->keymask.u32.mask,
				 sizeof(m_entry->keymask.u32.mask));
			break;
		case MVSW_ACL_RULE_MATCH_ENTRY_TYPE_PORT:
			err = mvsw_msg_buff_put
				(msg, &m_entry->keymask.u64.key,
				 sizeof(m_entry->keymask.u64.key));
			err |= mvsw_msg_buff_put
				(msg, &m_entry->keymask.u64.mask,
				 sizeof(m_entry->keymask.u64.mask));
			break;
		default:
			err = -EINVAL;
		}
		if (err)
			return err;
	}

	return 0;
}

int mvsw_pr_hw_acl_rule_add(const struct mvsw_pr_switch *sw,
			    struct prestera_acl_rule *rule,
			    u32 *rule_id)
{
	int err;
	struct mvsw_msg_acl_rule_ret resp;
	u8 hw_tc = prestera_acl_rule_hw_tc_get(rule);
	u32 priority = prestera_acl_rule_priority_get(rule);
	u16 ruleset_id = prestera_acl_rule_ruleset_id_get(rule);
	struct mvsw_msg_acl_rule_cmd *req;
	struct mvsw_msg_buff *msg;

	msg = mvsw_msg_buff_create(sizeof(*req));
	if (!msg)
		return -ENOMEM;

	/* put priority first */
	err = mvsw_msg_buff_put(msg, &priority, sizeof(priority));
	if (err)
		goto free_msg;

	/* put hw_tc into the message */
	err = mvsw_msg_buff_put(msg, &hw_tc, sizeof(hw_tc));
	if (err)
		goto free_msg;

	/* put acl actions into the message */
	err = acl_rule_add_put_actions(msg, rule);
	if (err)
		goto free_msg;

	/* put acl matches into the message */
	err = acl_rule_add_put_matches(msg, rule);
	if (err)
		goto free_msg;

	/* terminate message */
	err = mvsw_msg_buff_terminate(msg);
	if (err)
		goto free_msg;

	req = (struct mvsw_msg_acl_rule_cmd *)mvsw_msg_buff_data(msg);

	req->ruleset_id = ruleset_id;

	err = fw_send_nreq_resp(sw, MVSW_MSG_TYPE_ACL_RULE_ADD, req,
				mvsw_msg_buff_size(msg), &resp);
	if (err)
		goto free_msg;

	*rule_id = resp.id;
free_msg:
	mvsw_msg_buff_destroy(msg);
	return err;
}

int mvsw_pr_hw_acl_rule_del(const struct mvsw_pr_switch *sw, u32 rule_id)
{
	struct mvsw_msg_acl_rule_cmd req = {
		.id = rule_id
	};

	return fw_send_req(sw, MVSW_MSG_TYPE_ACL_RULE_DELETE, &req);
}

int mvsw_pr_hw_acl_rule_stats_get(const struct mvsw_pr_switch *sw, u32 rule_id,
				  u64 *packets, u64 *bytes)
{
	int err;
	struct mvsw_msg_acl_rule_stats_ret resp;
	struct mvsw_msg_acl_rule_cmd req = {
		.id = rule_id
	};

	err = fw_send_req_resp(sw, MVSW_MSG_TYPE_ACL_RULE_STATS_GET,
			       &req, &resp);
	if (err)
		return err;

	*packets = resp.packets;
	*bytes = resp.bytes;
	return 0;
}

int mvsw_pr_hw_acl_port_bind(const struct mvsw_pr_port *port, u16 ruleset_id)
{
	struct mvsw_msg_acl_ruleset_bind_cmd req = {
		.port = port->hw_id,
		.dev = port->dev_id,
		.ruleset_id = ruleset_id,
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_ACL_PORT_BIND, &req);
}

int mvsw_pr_hw_acl_port_unbind(const struct mvsw_pr_port *port, u16 ruleset_id)
{
	struct mvsw_msg_acl_ruleset_bind_cmd req = {
		.port = port->hw_id,
		.dev = port->dev_id,
		.ruleset_id = ruleset_id,
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_ACL_PORT_UNBIND, &req);
}

int mvsw_pr_hw_lag_member_add(struct mvsw_pr_port *port, u16 lag_id)
{
	struct mvsw_msg_lag_cmd req = {
		.port = port->hw_id,
		.dev = port->dev_id,
		.lag_id = lag_id
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_LAG_ADD, &req);
}

int mvsw_pr_hw_lag_member_del(struct mvsw_pr_port *port, u16 lag_id)
{
	struct mvsw_msg_lag_cmd req = {
		.port = port->hw_id,
		.dev = port->dev_id,
		.lag_id = lag_id
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_LAG_DELETE, &req);
}

int mvsw_pr_hw_lag_member_enable(struct mvsw_pr_port *port, u16 lag_id,
				 bool enable)
{
	u32 cmd;
	struct mvsw_msg_lag_cmd req = {
		.port = port->hw_id,
		.dev = port->dev_id,
		.lag_id = lag_id
	};

	cmd = enable ? MVSW_MSG_TYPE_LAG_ENABLE : MVSW_MSG_TYPE_LAG_DISABLE;
	return fw_send_req(port->sw, cmd, &req);
}

int mvsw_pr_hw_lag_member_rif_leave(const struct mvsw_pr_port *port,
				    u16 lag_id, u16 vr_id)
{
	struct mvsw_msg_lag_cmd req = {
		.port = port->hw_id,
		.dev = port->dev_id,
		.lag_id = lag_id,
		.vr_id = vr_id
	};

	return fw_send_req(port->sw, MVSW_MSG_TYPE_LAG_ROUTER_LEAVE, &req);
}
