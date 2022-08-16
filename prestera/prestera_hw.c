// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <net/dcbnl.h>

#include "prestera.h"
#include "prestera_hw.h"
#include "prestera_acl.h"
#include "prestera_log.h"
#include "prestera_fw_log.h"
#include "prestera_counter.h"
#include "prestera_rxtx.h"

#define PRESTERA_HW_INIT_TIMEOUT 30000000	/* 30sec */
#define PRESTERA_HW_MIN_MTU 64

#ifndef PRESTERA_FW_WD_KICK_TIMEOUT
#define PRESTERA_FW_WD_KICK_TIMEOUT		1000
#endif /* PRESTERA_FW_WD_KICK_TIMEOUT */

#ifndef PRESTERA_FW_KEEPALIVE_WD_MAX_KICKS
#define PRESTERA_FW_KEEPALIVE_WD_MAX_KICKS	15
#endif /* PRESTERA_FW_KEEPALIVE_WD_MAX_KICKS */

enum prestera_cmd_type_t {
	PRESTERA_CMD_TYPE_SWITCH_INIT = 0x1,
	PRESTERA_CMD_TYPE_SWITCH_ATTR_SET = 0x2,

	PRESTERA_CMD_TYPE_KEEPALIVE_INIT = 0x3,
	PRESTERA_CMD_TYPE_SWITCH_RESET = 0x4,

	PRESTERA_CMD_TYPE_SWITCH_SCT_RATELIMIT_SET = 0x5,
	PRESTERA_CMD_TYPE_SWITCH_SCT_RATELIMIT_GET = 0x6,

	PRESTERA_CMD_TYPE_IPG_GET = 0xFE,
	PRESTERA_CMD_TYPE_IPG_SET = 0xFF,

	PRESTERA_CMD_TYPE_PORT_ATTR_SET = 0x100,
	PRESTERA_CMD_TYPE_PORT_ATTR_GET = 0x101,
	PRESTERA_CMD_TYPE_PORT_INFO_GET = 0x110,
	PRESTERA_CMD_TYPE_PORT_RATE_LIMIT_MODE_SET = 0x111,

	PRESTERA_CMD_TYPE_VLAN_CREATE = 0x200,
	PRESTERA_CMD_TYPE_VLAN_DELETE = 0x201,
	PRESTERA_CMD_TYPE_VLAN_PORT_SET = 0x202,
	PRESTERA_CMD_TYPE_VLAN_PVID_SET = 0x203,

	PRESTERA_CMD_TYPE_FDB_ADD = 0x300,
	PRESTERA_CMD_TYPE_FDB_DELETE = 0x301,
	PRESTERA_CMD_TYPE_FDB_FLUSH_PORT = 0x310,
	PRESTERA_CMD_TYPE_FDB_FLUSH_VLAN = 0x311,
	PRESTERA_CMD_TYPE_FDB_FLUSH_PORT_VLAN = 0x312,
	PRESTERA_CMD_TYPE_FDB_MACVLAN_ADD = 0x320,
	PRESTERA_CMD_TYPE_FDB_MACVLAN_DEL = 0x321,
	PRESTERA_CMD_TYPE_FDB_ROUTED_ADD = 0x322,
	PRESTERA_CMD_TYPE_FDB_ROUTED_DEL = 0x323,

	PRESTERA_CMD_TYPE_LOG_LEVEL_SET,

	PRESTERA_CMD_TYPE_BRIDGE_CREATE = 0x400,
	PRESTERA_CMD_TYPE_BRIDGE_DELETE = 0x401,
	PRESTERA_CMD_TYPE_BRIDGE_PORT_ADD = 0x402,
	PRESTERA_CMD_TYPE_BRIDGE_PORT_DELETE = 0x403,

	PRESTERA_CMD_TYPE_COUNTER_GET = 0x510,
	PRESTERA_CMD_TYPE_COUNTER_ABORT = 0x511,
	PRESTERA_CMD_TYPE_COUNTER_TRIGGER = 0x512,
	PRESTERA_CMD_TYPE_COUNTER_BLOCK_GET = 0x513,
	PRESTERA_CMD_TYPE_COUNTER_BLOCK_RELEASE = 0x514,
	PRESTERA_CMD_TYPE_COUNTER_CLEAR = 0x515,

	PRESTERA_CMD_TYPE_VTCAM_CREATE = 0x540,
	PRESTERA_CMD_TYPE_VTCAM_DESTROY = 0x541,
	PRESTERA_CMD_TYPE_VTCAM_RULE_ADD = 0x550,
	PRESTERA_CMD_TYPE_VTCAM_RULE_DELETE = 0x551,
	PRESTERA_CMD_TYPE_VTCAM_IFACE_BIND = 0x560,
	PRESTERA_CMD_TYPE_VTCAM_IFACE_UNBIND = 0x561,

	PRESTERA_CMD_TYPE_ROUTER_RIF_CREATE = 0x600,
	PRESTERA_CMD_TYPE_ROUTER_RIF_DELETE = 0x601,
	PRESTERA_CMD_TYPE_ROUTER_RIF_SET = 0x602,
	PRESTERA_CMD_TYPE_ROUTER_LPM_ADD = 0x610,
	PRESTERA_CMD_TYPE_ROUTER_LPM_DELETE = 0x611,
	PRESTERA_CMD_TYPE_ROUTER_NH_GRP_SET = 0x622,
	PRESTERA_CMD_TYPE_ROUTER_NH_GRP_GET = 0x644,
	PRESTERA_CMD_TYPE_ROUTER_NH_GRP_BLK_GET = 0x645,
	PRESTERA_CMD_TYPE_ROUTER_NH_GRP_ADD = 0x623,
	PRESTERA_CMD_TYPE_ROUTER_NH_GRP_DELETE = 0x624,
	PRESTERA_CMD_TYPE_ROUTER_VR_CREATE = 0x630,
	PRESTERA_CMD_TYPE_ROUTER_VR_DELETE = 0x631,
	PRESTERA_CMD_TYPE_ROUTER_VR_ABORT = 0x632,
	PRESTERA_CMD_TYPE_ROUTER_MP_HASH_SET = 0x650,

	PRESTERA_CMD_TYPE_FLOOD_DOMAIN_CREATE = 0x700,
	PRESTERA_CMD_TYPE_FLOOD_DOMAIN_DESTROY = 0x701,
	PRESTERA_CMD_TYPE_FLOOD_DOMAIN_PORTS_SET = 0x702,
	PRESTERA_CMD_TYPE_FLOOD_DOMAIN_PORTS_RESET = 0x703,

	PRESTERA_CMD_TYPE_MDB_CREATE = 0x704,
	PRESTERA_CMD_TYPE_MDB_DESTROY = 0x705,

	PRESTERA_CMD_TYPE_RXTX_INIT = 0x800,

	PRESTERA_CMD_TYPE_LAG_ADD = 0x900,
	PRESTERA_CMD_TYPE_LAG_DELETE = 0x901,
	PRESTERA_CMD_TYPE_LAG_ENABLE = 0x902,
	PRESTERA_CMD_TYPE_LAG_DISABLE = 0x903,
	PRESTERA_CMD_TYPE_LAG_ROUTER_LEAVE = 0x904,

	PRESTERA_CMD_TYPE_STP_PORT_SET = 0x1000,

	PRESTERA_CMD_TYPE_SPAN_GET = 0X1100,
	PRESTERA_CMD_TYPE_SPAN_BIND = 0X1101,
	PRESTERA_CMD_TYPE_SPAN_UNBIND = 0X1102,
	PRESTERA_CMD_TYPE_SPAN_RELEASE = 0X1103,

	PRESTERA_CMD_TYPE_NAT_PORT_NEIGH_UPDATE = 0X1200,

	PRESTERA_CMD_TYPE_NAT_NH_MANGLE_ADD = 0X1211,
	PRESTERA_CMD_TYPE_NAT_NH_MANGLE_SET = 0X1212,
	PRESTERA_CMD_TYPE_NAT_NH_MANGLE_DEL = 0X1213,
	PRESTERA_CMD_TYPE_NAT_NH_MANGLE_GET = 0X1214,

	PRESTERA_CMD_TYPE_QOS_DSCP_PRIO_MAP_UPDATE = 0X1301,
	PRESTERA_CMD_TYPE_QOS_TRUST_MODE_SET = 0X1302,
	PRESTERA_CMD_TYPE_QOS_DEFAULT_PRIO_SET = 0X1303,

	PRESTERA_CMD_TYPE_SCHED_CREATE = 0X1401,
	PRESTERA_CMD_TYPE_SCHED_RELEASE = 0X1402,
	PRESTERA_CMD_TYPE_SCHED_SET = 0X1403,
	PRESTERA_CMD_TYPE_SCHED_PORT_SET = 0X1404,
	PRESTERA_CMD_TYPE_SCHED_PORT_GET = 0X1405,

	PRESTERA_CMD_TYPE_SHAPER_PORT_QUEUE_CONFIGURE = 0X1411,
	PRESTERA_CMD_TYPE_SHAPER_PORT_QUEUE_DISABLE = 0X1412,

	PRESTERA_CMD_TYPE_PORT_QUEUE_STATS_GET = 0X1421,

	PRESTERA_CMD_TYPE_WRED_PORT_QUEUE_ENABLE = 0X1431,
	PRESTERA_CMD_TYPE_WRED_PORT_QUEUE_DISABLE = 0X1432,

	PRESTERA_CMD_TYPE_CPU_CODE_COUNTERS_GET = 0x2000,

	PRESTERA_CMD_TYPE_ACK = 0x10000,
	PRESTERA_CMD_TYPE_MAX
};

enum {
	PRESTERA_CMD_PORT_ATTR_MTU = 3,
	PRESTERA_CMD_PORT_ATTR_MAC = 4,
	PRESTERA_CMD_PORT_ATTR_ACCEPT_FRAME_TYPE = 6,
	PRESTERA_CMD_PORT_ATTR_LEARNING = 7,
	PRESTERA_CMD_PORT_ATTR_FLOOD = 8,
	PRESTERA_CMD_PORT_ATTR_CAPABILITY = 9,
	PRESTERA_CMD_PORT_ATTR_PHY_MODE = 12,
	PRESTERA_CMD_PORT_ATTR_STATS = 17,
	PRESTERA_CMD_PORT_ATTR_MAC_AUTONEG_RESTART = 18,
	PRESTERA_CMD_PORT_ATTR_PHY_AUTONEG_RESTART = 19,
	PRESTERA_CMD_PORT_ATTR_SOURCE_ID_DEFAULT = 20,
	PRESTERA_CMD_PORT_ATTR_SOURCE_ID_FILTER = 21,
	PRESTERA_CMD_PORT_ATTR_MAC_MODE = 22,
	PRESTERA_CMD_PORT_ATTR_MAX
};

enum {
	PRESTERA_CMD_SWITCH_ATTR_MAC = 1,
	PRESTERA_CMD_SWITCH_ATTR_AGEING = 2,
	PRESTERA_CMD_SWITCH_ATTR_TRAP_POLICER = 3,
};

enum {
	PRESTERA_CMD_ACK_OK,
	PRESTERA_CMD_ACK_FAILED,
	PRESTERA_CMD_ACK_MAX
};

enum {
	PRESTERA_PORT_GOOD_OCTETS_RCV_CNT,
	PRESTERA_PORT_BAD_OCTETS_RCV_CNT,
	PRESTERA_PORT_MAC_TRANSMIT_ERR_CNT,
	PRESTERA_PORT_BRDC_PKTS_RCV_CNT,
	PRESTERA_PORT_MC_PKTS_RCV_CNT,
	PRESTERA_PORT_PKTS_64_OCTETS_CNT,
	PRESTERA_PORT_PKTS_65TO127_OCTETS_CNT,
	PRESTERA_PORT_PKTS_128TO255_OCTETS_CNT,
	PRESTERA_PORT_PKTS_256TO511_OCTETS_CNT,
	PRESTERA_PORT_PKTS_512TO1023_OCTETS_CNT,
	PRESTERA_PORT_PKTS_1024TOMAX_OCTETS_CNT,
	PRESTERA_PORT_EXCESSIVE_COLLISIONS_CNT,
	PRESTERA_PORT_MC_PKTS_SENT_CNT,
	PRESTERA_PORT_BRDC_PKTS_SENT_CNT,
	PRESTERA_PORT_FC_SENT_CNT,
	PRESTERA_PORT_GOOD_FC_RCV_CNT,
	PRESTERA_PORT_DROP_EVENTS_CNT,
	PRESTERA_PORT_UNDERSIZE_PKTS_CNT,
	PRESTERA_PORT_FRAGMENTS_PKTS_CNT,
	PRESTERA_PORT_OVERSIZE_PKTS_CNT,
	PRESTERA_PORT_JABBER_PKTS_CNT,
	PRESTERA_PORT_MAC_RCV_ERROR_CNT,
	PRESTERA_PORT_BAD_CRC_CNT,
	PRESTERA_PORT_COLLISIONS_CNT,
	PRESTERA_PORT_LATE_COLLISIONS_CNT,
	PRESTERA_PORT_GOOD_UC_PKTS_RCV_CNT,
	PRESTERA_PORT_GOOD_UC_PKTS_SENT_CNT,
	PRESTERA_PORT_MULTIPLE_PKTS_SENT_CNT,
	PRESTERA_PORT_DEFERRED_PKTS_SENT_CNT,
	PRESTERA_PORT_GOOD_OCTETS_SENT_CNT,
	PRESTERA_PORT_CNT_MAX,
};

enum {
	PRESTERA_FC_NONE,
	PRESTERA_FC_SYMMETRIC,
	PRESTERA_FC_ASYMMETRIC,
	PRESTERA_FC_SYMM_ASYMM,
};

enum {
	PRESTERA_PORT_TP_NA,
	PRESTERA_PORT_TP_MDI,
	PRESTERA_PORT_TP_MDIX,
	PRESTERA_PORT_TP_AUTO
};

enum {
	PRESTERA_HW_FDB_ENTRY_TYPE_REG_PORT = 0,
	PRESTERA_HW_FDB_ENTRY_TYPE_LAG = 1,
	PRESTERA_HW_FDB_ENTRY_TYPE_MAX = 2,
};

enum {
	PRESTERA_PORT_FLOOD_TYPE_UC = 0,
	PRESTERA_PORT_FLOOD_TYPE_MC = 1,
	PRESTERA_PORT_FLOOD_TYPE_BC = 2,
};

enum {
	PRESTERA_HW_FLOOD_DOMAIN_PORT_TYPE_REG_PORT = 0,
	PRESTERA_HW_FLOOD_DOMAIN_PORT_TYPE_LAG = 1,
	PRESTERA_HW_FLOOD_DOMAIN_PORT_TYPE_MAX = 2,
};

enum {
	PRESTERA_HW_SCHED_SP,
	PRESTERA_HW_SCHED_SDWRR
};

struct prestera_msg_cmd {
	__le32 type;
};

struct prestera_msg_ret {
	struct prestera_msg_cmd cmd;
	__le32 status;
};

struct prestera_msg_common_req {
	struct prestera_msg_cmd cmd;
};

struct prestera_msg_common_resp {
	struct prestera_msg_ret ret;
};

struct prestera_msg_switch_attr_req {
	struct prestera_msg_cmd cmd;
	__le32 attr;
	union {
		__le32 ageing_timeout_ms;
		__le32 trap_policer_profile;
		struct {
			u8 mac[ETH_ALEN];
			u8 __pad[2];
		};
	} param;
};

struct prestera_msg_switch_init_resp {
	struct prestera_msg_ret ret;
	__le32 port_count;
	__le32 mtu_max;
	__le32 size_tbl_router_nexthop;
	u8 switch_id;
	u8 lag_max;
	u8 lag_member_max;
};

struct prestera_msg_event_port_param {
	union {
		struct {
			__le32 mode;
			__le32 speed;
			u8 oper;
			u8 duplex;
			u8 fc;
			u8 fec;
		} __packed mac; /* make sure always 12 bytes size */
		struct {
			__le64 lmode_bmap;
			u8 mdix;
			u8 fc;
			u8 __pad[2];
		} __packed phy; /* make sure always 12 bytes size */
	};
};

struct prestera_msg_port_cap_param {
	__le64 link_mode;
	u8  type;
	u8  fec;
	u8  fc;
	u8  transceiver;
};

struct prestera_msg_port_flood_param {
	u8 type;
	u8 enable;
	u8 __pad[2];
};

union prestera_msg_port_param {
	__le32 source_id_default;
	__le32 source_id_filter;
	__le32 mtu;
	u8 oper_state;
	u8 mac[ETH_ALEN];
	u8 accept_frm_type;
	u8 learning;
	u8 type;
	union {
		struct {
			u8 admin;
			u8 fc;
			u8 ap_enable;
			u8 __reserved[5];
			union {
				struct {
					__le32 mode;
					__le32 speed;
					u8 inband;
					u8 duplex;
					u8 fec;
					u8 fec_supp;
				} reg_mode;
				struct {
					__le32 mode;
					__le32 speed;
					u8 fec;
					u8 fec_supp;
					u8 __pad[2];
				} ap_modes[PRESTERA_AP_PORT_MAX];
			};
		} mac;
		struct {
			__le64 modes;
			__le32 mode;
			u8 admin;
			u8 adv_enable;
			u8 mdix;
			u8 __pad;
		} phy;
	} link;

	struct prestera_msg_port_cap_param cap;
	struct prestera_msg_port_flood_param flood_ext;
	struct prestera_msg_event_port_param link_evt;
};

struct prestera_msg_port_attr_req {
	struct prestera_msg_cmd cmd;
	__le32 attr;
	__le32 port;
	__le32 dev;
	union prestera_msg_port_param param;
};

struct prestera_msg_port_attr_resp {
	struct prestera_msg_ret ret;
	union prestera_msg_port_param param;
};

struct prestera_msg_port_stats_resp {
	struct prestera_msg_ret ret;
	__le64 stats[PRESTERA_PORT_CNT_MAX];
};

struct prestera_msg_port_info_req {
	struct prestera_msg_cmd cmd;
	__le32 port;
};

struct prestera_msg_port_info_resp {
	struct prestera_msg_ret ret;
	__le32 hw_id;
	__le32 dev_id;
	__le16 fp_id;
	u8 pad[2];
};

struct prestera_msg_port_storm_control_cfg_set_req {
	struct prestera_msg_cmd cmd;
	__le32 port;
	__le32 dev;
	__le32 storm_type;
	__le32 kbyte_per_sec_rate;
};

struct prestera_msg_vlan_req {
	struct prestera_msg_cmd cmd;
	__le32 port;
	__le32 dev;
	__le16 vid;
	u8  is_member;
	u8  is_tagged;
};

struct prestera_msg_fdb_req {
	struct prestera_msg_cmd cmd;
	__le32 flush_mode;
	union {
		struct {
			__le32 port;
			__le32 dev;
		};
		__le16 lag_id;
	} dest;
	__le16 vid;
	u8 dest_type;
	u8 dynamic;
	u8 mac[ETH_ALEN];
	u8 __pad[2];
};

struct prestera_msg_log_lvl_set_req {
	struct prestera_msg_cmd cmd;
	__le32 lib;
	__le32 type;
};

struct prestera_msg_iface {
	union {
		struct {
			__le32 dev;
			__le32 port;
		};
		__le16 lag_id;
	};
	__le16 vr_id;
	__le16 vid;
	u8 type;
	u8 pad[3];
};

enum prestera_msg_ip_addr_v {
	PRESTERA_MSG_IPV4 = 0,
	PRESTERA_MSG_IPV6
};

struct prestera_msg_ip_addr {
	union {
		__be32 ipv6[4];
		__be32 ipv4;
	} u;
	u8 v; /* enum prestera_msg_ip_addr_v */
	u8 pad[3];
};

struct prestera_msg_nh {
	struct prestera_msg_iface oif;
	__le32 hw_id;
	u8 mac[ETH_ALEN];
	u8 is_active;
	u8 pad;
};

struct prestera_msg_nh_mangle_info {
	struct prestera_msg_nh nh;
	__be32 sip;
	__be32 dip;
	__be16 l4_src;
	__be16 l4_dst;
	u8 l4_src_valid:1;
	u8 l4_dst_valid:1;
	u8 sip_valid:1;
	u8 dip_valid:1;
	u8 pad[3];
};

struct prestera_msg_nh_mangle_req {
	struct prestera_msg_cmd cmd;
	struct prestera_msg_nh_mangle_info info;
	__le32 nh_id;
};

struct prestera_msg_nh_mangle_resp {
	struct prestera_msg_ret ret;
	struct prestera_msg_nh_mangle_info info;
	__le32 nh_id;
};

struct prestera_msg_acl_action {
	__le32 id;
	__le32 __reserved;
	union {
		struct {
			u8 hw_tc;
		} trap;
		struct {
			__le64 rate;
			__le64 burst;
		} police;
		struct {
			__le32 nh_id;
		} nh;
		struct {
			__be32 old_addr;
			__be32 new_addr;
			__le32 port;
			__le32 dev;
			__le32 flags;
			__le32 __pad;
		} nat;
		struct {
			__le32 index;
		} jump;
		struct {
			__le32 id;
		} count;
		struct {
			u32 dscp;
		} remark;
	};
};

struct prestera_msg_vtcam_create_req {
	struct prestera_msg_cmd cmd;
	__le32 keymask[__PRESTERA_ACL_RULE_MATCH_TYPE_MAX];
	u8 direction;
	u8 lookup;
	u8 pad[2];
};

struct prestera_msg_vtcam_destroy_req {
	struct prestera_msg_cmd cmd;
	__le32 vtcam_id;
};

struct prestera_msg_vtcam_rule_add_req {
	struct prestera_msg_cmd cmd;
	__le32 key[__PRESTERA_ACL_RULE_MATCH_TYPE_MAX];
	__le32 keymask[__PRESTERA_ACL_RULE_MATCH_TYPE_MAX];
	__le32 vtcam_id;
	__le32 prio;
	__le32 n_act;
};

struct prestera_msg_vtcam_rule_del_req {
	struct prestera_msg_cmd cmd;
	__le32 vtcam_id;
	__le32 id;
};

struct prestera_msg_vtcam_bind_req {
	struct prestera_msg_cmd cmd;
	union {
		struct {
			__le32 hw_id;
			__le32 dev_id;
		} port;
		__le32 index;
	};
	__le32 vtcam_id;
	__le16 pcl_id;
	__le16 type;
};

struct prestera_msg_vtcam_resp {
	struct prestera_msg_ret ret;
	__le32 vtcam_id;
	__le32 rule_id;
};

struct prestera_msg_counter_req {
	struct prestera_msg_cmd cmd;
	__le32 client;
	__le32 block_id;
	__le32 num_counters;
};

struct prestera_msg_counter_stats {
	__le64 packets;
	__le64 bytes;
};

struct prestera_msg_counter_resp {
	struct prestera_msg_ret ret;
	__le32 block_id;
	__le32 offset;
	__le32 num_counters;
	__le32 done;
	struct prestera_msg_counter_stats stats[0];
};

struct prestera_msg_nat_port_req {
	struct prestera_msg_cmd cmd;
	__le32 port;
	__le32 dev;
	u8 neigh_mac[ETH_ALEN];
	u8 __pad[2];
};

struct prestera_msg_span_req {
	struct prestera_msg_cmd cmd;
	__le32 port;
	__le32 dev;
	u8 id;
	u8 pad[3];
};

struct prestera_msg_span_resp {
	struct prestera_msg_ret ret;
	u8 id;
	u8 pad[3];
};

struct prestera_msg_event {
	__le16 type;
	__le16 id;
};

struct prestera_msg_event_log {
	struct prestera_msg_event id;
	__le32 log_string_size;
	u8 log_string[0];
};

union prestera_msg_event_fdb_param {
	u8 mac[ETH_ALEN];
};

struct prestera_msg_event_fdb {
	struct prestera_msg_event id;
	__le32 vid;
	union {
		__le32 port_id;
		__le16 lag_id;
	} dest;
	union prestera_msg_event_fdb_param param;
	u8 dest_type;
};

struct prestera_msg_event_port {
	struct prestera_msg_event id;
	__le32 port_id;
	struct prestera_msg_event_port_param param;
};

struct prestera_msg_bridge_req {
	struct prestera_msg_cmd cmd;
	__le32 port;
	__le32 dev;
	__le16 bridge;
	u8 pad[2];
};

struct prestera_msg_bridge_resp {
	struct prestera_msg_ret ret;
	__le16 bridge;
	u8 pad[2];
};

struct prestera_msg_macvlan_req {
	struct prestera_msg_cmd cmd;
	__le16 vr_id;
	__le16 vid;
	u8 mac[ETH_ALEN];
	u8 pad[2];
	/* iface will be removed as well as vr_id during fw logic migration
	 * For now it is necessary to calculate priv vid on fw side
	 */
	struct prestera_msg_iface iface;
};

struct prestera_msg_stp_req {
	struct prestera_msg_cmd cmd;
	__le32 port;
	__le32 dev;
	__le16 vid;
	u8  state;
	u8 __pad;
};

struct prestera_msg_rif_req {
	struct prestera_msg_cmd cmd;
	struct prestera_msg_iface iif;
	__le32 mtu;
	__le16 rif_id;
	__le16 __reserved;
	u8 mac[ETH_ALEN];
	u8 __pad[2];
};

struct prestera_msg_rif_resp {
	struct prestera_msg_ret ret;
	__le16 rif_id;
	__le16 __pad;
};

struct prestera_msg_lpm_req {
	struct prestera_msg_cmd cmd;
	struct prestera_msg_ip_addr dst;
	__le32 grp_id;
	__le32 dst_len;
	__le16 vr_id;
	__le16 __pad;
};

struct prestera_msg_nh_req {
	struct prestera_msg_cmd cmd;
	struct prestera_msg_nh nh[PRESTERA_NHGR_SIZE_MAX];
	__le32 size;
	__le32 grp_id;
};

struct prestera_msg_nh_resp {
	struct prestera_msg_ret ret;
	struct prestera_msg_nh nh[PRESTERA_NHGR_SIZE_MAX];
};

struct prestera_msg_nh_chunk_req {
	struct prestera_msg_cmd cmd;
	__le32 offset;
};

struct prestera_msg_nh_chunk_resp {
	struct prestera_msg_ret ret;
	u8 hw_state[PRESTERA_MSG_CHUNK_SIZE];
};

struct prestera_msg_nh_grp_req {
	struct prestera_msg_cmd cmd;
	__le32 grp_id;
	__le32 size;
};

struct prestera_msg_nh_grp_resp {
	struct prestera_msg_ret ret;
	__le32 grp_id;
};

struct prestera_msg_mp_req {
	struct prestera_msg_cmd cmd;
	u8 hash_policy;
	u8 __pad[3];
};

struct prestera_msg_rxtx_req {
	struct prestera_msg_cmd cmd;
	u8 use_sdma;
	u8 pad[3];
};

struct prestera_msg_rxtx_resp {
	struct prestera_msg_ret ret;
	__le32 map_addr;
};

struct prestera_msg_vr_req {
	struct prestera_msg_cmd cmd;
	__le16 vr_id;
	__le16 __pad;
};

struct prestera_msg_vr_resp {
	struct prestera_msg_ret ret;
	__le16 vr_id;
	__le16 __pad;
};

struct prestera_msg_lag_req {
	struct prestera_msg_cmd cmd;
	__le32 port;
	__le32 dev;
	__le16 lag_id;
	__le16 vr_id;
};

struct prestera_msg_keepalive_init_req {
	struct prestera_msg_cmd cmd;
	__le32 pulse_timeout_ms;
};

struct prestera_msg_cpu_code_counter_req {
	struct prestera_msg_cmd cmd;
	u8 counter_type;
	u8 code;
	u8 pad[2];
};

struct prestera_msg_cpu_code_counter_resp {
	struct prestera_msg_ret ret;
	__le64 packet_count;
};

struct prestera_msg_flood_domain_create_req {
	struct prestera_msg_cmd cmd;
};

struct prestera_msg_flood_domain_create_resp {
	struct prestera_msg_ret ret;
	__le32 flood_domain_idx;
};

struct prestera_msg_flood_domain_destroy_req {
	struct prestera_msg_cmd cmd;
	__le32 flood_domain_idx;
};

struct prestera_msg_flood_domain_ports_set_req {
	struct prestera_msg_cmd cmd;
	__le32 flood_domain_idx;
	__le32 ports_num;
};

struct prestera_msg_flood_domain_ports_reset_req {
	struct prestera_msg_cmd cmd;
	__le32 flood_domain_idx;
};

struct prestera_msg_flood_domain_port {
	union {
		struct {
			__le32 port_num;
			__le32 dev_num;
		};
		__le16 lag_id;
	};
	__le16 vid;
	__le16 port_type;
};

struct prestera_msg_mdb_create_req {
	struct prestera_msg_cmd cmd;
	__le32 flood_domain_idx;
	__le16 vid;
	u8 mac[ETH_ALEN];
};

struct prestera_msg_mdb_destroy_req {
	struct prestera_msg_cmd cmd;
	__le32 flood_domain_idx;
	__le16 vid;
	u8 mac[ETH_ALEN];
};

struct prestera_msg_qos_req {
	struct prestera_msg_cmd cmd;
	u32 port;
	u32 dev;
	u32 priority;
	u32 mode;
	u8  dscp[64];
};

struct prestera_msg_sched_req {
	struct prestera_msg_cmd cmd;
	__le32 dev;
	__le32 port;
	__le32 id;
};

struct prestera_msg_sched_resp {
	struct prestera_msg_ret ret;
	__le32 id;
};

struct prestera_msg_sched_attr_req {
	struct prestera_msg_cmd cmd;
	union {
		struct {
			__le32 weight;
		} sdwrr;
	};
	__le32 dev;
	__le32 port;
	__le32 id;
	u8 type;
	u8 tc;
};

struct prestera_msg_shaper_req {
	struct prestera_msg_cmd cmd;
	u32 port;
	u32 dev;
	u32 tc;
	u32 burst;
	u32 rate;
};

struct prestera_msg_shaper_stats_resp {
	struct prestera_msg_ret ret;
	u64 pkts;
	u64 bytes;
	u64 drops;
};

struct prestera_msg_wred_req {
	struct prestera_msg_cmd cmd;
	u32 port;
	u32 dev;
	u32 tc;
	u32 min;
	u32 max;
	u32 prob;
};

struct prestera_msg_sct_ratelimit_set_req {
	struct prestera_msg_cmd cmd;
	u32 rate_pps;
	u8 group;
};

struct prestera_msg_sct_ratelimit_get_req {
	struct prestera_msg_cmd cmd;
	u8 group;
};

struct prestera_msg_sct_ratelimit_get_resp {
	struct prestera_msg_ret ret;
	u32 rate_pps;
};

struct prestera_msg_ipg_set_req {
	struct prestera_msg_cmd cmd;
	u32 ipg;
} __packed __aligned(4);

struct prestera_msg_ipg_get_resp {
	struct prestera_msg_ret ret;
	u32 ipg;
} __packed __aligned(4);

static void prestera_hw_build_tests(void)
{
	/* check requests */
	BUILD_BUG_ON(sizeof(struct prestera_msg_common_req) != 4);
	BUILD_BUG_ON(sizeof(struct prestera_msg_switch_attr_req) != 16);
	BUILD_BUG_ON(sizeof(struct prestera_msg_port_attr_req) != 144);
	BUILD_BUG_ON(sizeof(struct prestera_msg_port_info_req) != 8);
	BUILD_BUG_ON(sizeof(struct prestera_msg_vlan_req) != 16);
	BUILD_BUG_ON(sizeof(struct prestera_msg_fdb_req) != 28);
	BUILD_BUG_ON(sizeof(struct prestera_msg_bridge_req) != 16);
	BUILD_BUG_ON(sizeof(struct prestera_msg_span_req) != 16);
	BUILD_BUG_ON(sizeof(struct prestera_msg_stp_req) != 16);
	BUILD_BUG_ON(sizeof(struct prestera_msg_rxtx_req) != 8);
	BUILD_BUG_ON(sizeof(struct prestera_msg_lag_req) != 16);
	BUILD_BUG_ON(sizeof(struct prestera_msg_cpu_code_counter_req) != 8);
	BUILD_BUG_ON(sizeof(struct prestera_msg_vtcam_create_req) != 88);
	BUILD_BUG_ON(sizeof(struct prestera_msg_vtcam_destroy_req) != 8);
	BUILD_BUG_ON(sizeof(struct prestera_msg_vtcam_rule_add_req) != 176);
	BUILD_BUG_ON(sizeof(struct prestera_msg_vtcam_rule_del_req) != 12);
	BUILD_BUG_ON(sizeof(struct prestera_msg_vtcam_bind_req) != 20);
	BUILD_BUG_ON(sizeof(struct prestera_msg_counter_req) != 16);
	BUILD_BUG_ON(sizeof(struct prestera_msg_counter_stats) != 16);
	BUILD_BUG_ON(sizeof(struct prestera_msg_nh_mangle_req) != 52);
	BUILD_BUG_ON(sizeof(struct prestera_msg_nat_port_req) != 20);
	BUILD_BUG_ON(sizeof(struct prestera_msg_macvlan_req) != 32);
	BUILD_BUG_ON(sizeof(struct prestera_msg_rif_req) != 36);
	BUILD_BUG_ON(sizeof(struct prestera_msg_lpm_req) != 36);
	BUILD_BUG_ON(sizeof(struct prestera_msg_nh_req) != 124);
	BUILD_BUG_ON(sizeof(struct prestera_msg_nh_chunk_req) != 8);
	BUILD_BUG_ON(sizeof(struct prestera_msg_nh_grp_req) != 12);
	BUILD_BUG_ON(sizeof(struct prestera_msg_mp_req) != 8);
	BUILD_BUG_ON(sizeof(struct prestera_msg_vr_req) != 8);
	BUILD_BUG_ON(sizeof(struct prestera_msg_keepalive_init_req) != 8);
	BUILD_BUG_ON(sizeof(struct prestera_msg_flood_domain_create_req) != 4);
	BUILD_BUG_ON(sizeof(struct prestera_msg_flood_domain_destroy_req) != 8);
	BUILD_BUG_ON(sizeof(struct prestera_msg_flood_domain_ports_set_req) != 12);
	BUILD_BUG_ON(sizeof(struct prestera_msg_flood_domain_ports_reset_req) != 8);
	BUILD_BUG_ON(sizeof(struct prestera_msg_mdb_create_req) != 16);
	BUILD_BUG_ON(sizeof(struct prestera_msg_mdb_destroy_req) != 16);
	BUILD_BUG_ON(sizeof(struct prestera_msg_qos_req) != 84);
	BUILD_BUG_ON(sizeof(struct prestera_msg_sched_req) != 16);
	BUILD_BUG_ON(sizeof(struct prestera_msg_sched_attr_req) != 24);
	BUILD_BUG_ON(sizeof(struct prestera_msg_shaper_req) != 24);
	BUILD_BUG_ON(sizeof(struct prestera_msg_wred_req) != 28);
	BUILD_BUG_ON(sizeof(struct prestera_msg_sct_ratelimit_set_req) != 12);
	BUILD_BUG_ON(sizeof(struct prestera_msg_sct_ratelimit_get_req) != 8);

	/* structure that are part of req/resp fw messages */
	BUILD_BUG_ON(sizeof(struct prestera_msg_acl_action) != 32);
	BUILD_BUG_ON(sizeof(struct prestera_msg_iface) != 16);
	BUILD_BUG_ON(sizeof(struct prestera_msg_ip_addr) != 20);
	BUILD_BUG_ON(sizeof(struct prestera_msg_nh) != 28);
	BUILD_BUG_ON(sizeof(struct prestera_msg_nh_mangle_info) != 44);
	BUILD_BUG_ON(sizeof(struct prestera_msg_flood_domain_port) != 12);

	/* check responses */
	BUILD_BUG_ON(sizeof(struct prestera_msg_common_resp) != 8);
	BUILD_BUG_ON(sizeof(struct prestera_msg_switch_init_resp) != 24);
	BUILD_BUG_ON(sizeof(struct prestera_msg_port_attr_resp) != 136);
	BUILD_BUG_ON(sizeof(struct prestera_msg_port_stats_resp) != 248);
	BUILD_BUG_ON(sizeof(struct prestera_msg_port_info_resp) != 20);
	BUILD_BUG_ON(sizeof(struct prestera_msg_bridge_resp) != 12);
	BUILD_BUG_ON(sizeof(struct prestera_msg_span_resp) != 12);
	BUILD_BUG_ON(sizeof(struct prestera_msg_rxtx_resp) != 12);
	BUILD_BUG_ON(sizeof(struct prestera_msg_vtcam_resp) != 16);
	BUILD_BUG_ON(sizeof(struct prestera_msg_counter_resp) != 24);
	BUILD_BUG_ON(sizeof(struct prestera_msg_nh_mangle_resp) != 56);
	BUILD_BUG_ON(sizeof(struct prestera_msg_rif_resp) != 12);
	BUILD_BUG_ON(sizeof(struct prestera_msg_nh_resp) != 120);
	BUILD_BUG_ON(sizeof(struct prestera_msg_nh_chunk_resp) != 1032);
	BUILD_BUG_ON(sizeof(struct prestera_msg_nh_grp_resp) != 12);
	BUILD_BUG_ON(sizeof(struct prestera_msg_vr_resp) != 12);
	BUILD_BUG_ON(sizeof(struct prestera_msg_flood_domain_create_resp) != 12);
	BUILD_BUG_ON(sizeof(struct prestera_msg_sched_resp) != 12);
	BUILD_BUG_ON(sizeof(struct prestera_msg_shaper_stats_resp) != 32);
	BUILD_BUG_ON(sizeof(struct prestera_msg_sct_ratelimit_get_resp) != 12);

	/* check events */
	BUILD_BUG_ON(sizeof(struct prestera_msg_event_port) != 20);
	BUILD_BUG_ON(sizeof(struct prestera_msg_event_fdb) != 20);
	BUILD_BUG_ON(sizeof(struct prestera_msg_event_log) != 8);
}

static void fw_reset_wdog(struct prestera_device *dev);

static int prestera_cmd_qid_by_req_type(enum prestera_cmd_type_t type)
{
	switch (type) {
	case PRESTERA_CMD_TYPE_COUNTER_GET:
	case PRESTERA_CMD_TYPE_COUNTER_ABORT:
	case PRESTERA_CMD_TYPE_COUNTER_TRIGGER:
	case PRESTERA_CMD_TYPE_COUNTER_BLOCK_GET:
	case PRESTERA_CMD_TYPE_COUNTER_BLOCK_RELEASE:
	case PRESTERA_CMD_TYPE_COUNTER_CLEAR:
		return 1;
	default:
		return 0;
	}
}

#define fw_check_resp(_response)							\
({											\
	int __er = 0;									\
	typeof(_response) __r = (_response);						\
	if (__r->ret.cmd.type != __cpu_to_le32((u32)PRESTERA_CMD_TYPE_ACK))		\
		__er = -EBADE;								\
	else if (__r->ret.status != __cpu_to_le32((u32)PRESTERA_CMD_ACK_OK))		\
		__er = -EINVAL;								\
	(__er);										\
})

#define __fw_send_req_resp(_switch, _type, _request, _req_size,	\
_response, _resp_size, _wait)					\
({								\
	int __e;						\
	typeof(_switch) __sw = (_switch);			\
	typeof(_request) __req = (_request);			\
	typeof(_response) __resp = (_response);			\
	typeof(_type) __type = (_type);				\
	__req->cmd.type = __cpu_to_le32(__type);			\
	__e = __sw->dev->send_req(__sw->dev,			\
	prestera_cmd_qid_by_req_type(__type),			\
		(u8 *)__req, _req_size,				\
		(u8 *)__resp, _resp_size,			\
		_wait);						\
	if (__e != -EBUSY && __e != -ENODEV)			\
		fw_reset_wdog(_switch->dev);			\
	if (!__e)						\
		__e = fw_check_resp(__resp);			\
	(__e);							\
})

#define fw_send_nreq_nresp(_sw, _t, _req, _req_size, _resp, _resp_size)	\
	__fw_send_req_resp(_sw, _t, _req, _req_size, _resp, _resp_size, 0)

#define fw_send_nreq_resp(_sw, _t, _req, _req_size, _resp)	\
({								\
	typeof(_resp) _res = (_resp);				\
	(__fw_send_req_resp(_sw, _t, _req, _req_size,		\
			    _res, sizeof(*_res), 0));		\
})

#define fw_send_req_resp(_sw, _t, _req, _resp)			\
({								\
	typeof(_req) _re = (_req);				\
	typeof(_resp) _res = (_resp);				\
	(__fw_send_req_resp(_sw, _t, _re, sizeof(*_re),		\
			    _res, sizeof(*_res), 0));		\
})

#define fw_send_req_resp_wait(_sw, _t, _req, _resp, _wait)	\
({								\
	typeof(_req) _re = (_req);				\
	typeof(_resp) _res = (_resp);				\
	(__fw_send_req_resp(_sw, _t, _re, sizeof(*_re),		\
			    _res, sizeof(*_res), _wait));	\
})

#define fw_send_req(_sw, _t, _req)	\
({							\
	struct prestera_msg_common_resp __re;		\
	(fw_send_req_resp(_sw, _t, _req, &__re));	\
})

struct prestera_fw_event_handler {
	struct list_head list;
	enum prestera_event_type type;
	void (*func)(struct prestera_switch *sw,
		     struct prestera_event *evt,
		     void *arg);
	void *arg;
};

static void prestera_hw_remote_fc_to_eth(u8 fc, bool *pause, bool *asym_pause);
static u8 prestera_hw_mdix_to_eth(u8 mode);
static int prestera_iface_to_msg(struct prestera_iface *iface,
				 struct prestera_msg_iface *msg_if);

static void prestera_fw_wdog_restart(struct prestera_device *dev)
{
	queue_delayed_work(system_long_wq,
			   &dev->keepalive_wdog_work,
			   msecs_to_jiffies(PRESTERA_FW_WD_KICK_TIMEOUT));
}

static void prestera_fw_keepalive_wd_work_fn(struct work_struct *work)
{
	struct delayed_work *dl_work =
		container_of(work, struct delayed_work, work);
	struct prestera_device *dev =
		container_of(dl_work, struct prestera_device,
			     keepalive_wdog_work);

	atomic_t *ctr = &dev->keepalive_wdog_counter;

	if (atomic_add_unless(ctr, 1, PRESTERA_FW_KEEPALIVE_WD_MAX_KICKS)) {
		prestera_fw_wdog_restart(dev);
		return;
	}

	pr_err("fw_keepalive_wdog: Fw is stuck and became non-operational\n");

	dev->running = false;
}

static int fw_parse_port_evt(u8 *msg, struct prestera_event *evt)
{
	struct prestera_msg_event_port *hw_evt;

	hw_evt = (struct prestera_msg_event_port *)msg;

	evt->port_evt.port_id = __le32_to_cpu(hw_evt->port_id);

	if (evt->id == PRESTERA_PORT_EVENT_MAC_STATE_CHANGED) {
		evt->port_evt.data.mac.oper = hw_evt->param.mac.oper;
		evt->port_evt.data.mac.mode = __le32_to_cpu(hw_evt->param.mac.mode);
		evt->port_evt.data.mac.speed = __le32_to_cpu(hw_evt->param.mac.speed);
		evt->port_evt.data.mac.duplex = hw_evt->param.mac.duplex;
		evt->port_evt.data.mac.fc = hw_evt->param.mac.fc;
		evt->port_evt.data.mac.fec = hw_evt->param.mac.fec;
	} else {
		return -EINVAL;
	}

	return 0;
}

static int fw_parse_fdb_evt(u8 *msg, struct prestera_event *evt)
{
	struct prestera_msg_event_fdb *hw_evt;

	hw_evt = (struct prestera_msg_event_fdb *)msg;

	switch (hw_evt->dest_type) {
	case PRESTERA_HW_FDB_ENTRY_TYPE_REG_PORT:
		evt->fdb_evt.type = PRESTERA_FDB_ENTRY_TYPE_REG_PORT;
		evt->fdb_evt.dest.port_id = __le32_to_cpu(hw_evt->dest.port_id);
		break;
	case PRESTERA_HW_FDB_ENTRY_TYPE_LAG:
		evt->fdb_evt.type = PRESTERA_FDB_ENTRY_TYPE_LAG;
		evt->fdb_evt.dest.lag_id = __le16_to_cpu(hw_evt->dest.lag_id);
		break;
	default:
		return -EINVAL;
	}

	evt->fdb_evt.vid = __le32_to_cpu(hw_evt->vid);

	memcpy(&evt->fdb_evt.data, &hw_evt->param, sizeof(u8) * ETH_ALEN);

	return 0;
}

static int fw_parse_log_evt(u8 *msg, struct prestera_event *evt)
{
	struct prestera_msg_event_log *hw_evt;

	hw_evt = (struct prestera_msg_event_log *)msg;

	evt->fw_log_evt.log_len	= __le32_to_cpu(hw_evt->log_string_size);
	evt->fw_log_evt.data	= hw_evt->log_string;

	return 0;
}

struct prestera_fw_evt_parser {
	int (*func)(u8 *msg, struct prestera_event *evt);
};

static struct prestera_fw_evt_parser fw_event_parsers[PRESTERA_EVENT_TYPE_MAX] = {
	[PRESTERA_EVENT_TYPE_PORT] = {.func = fw_parse_port_evt},
	[PRESTERA_EVENT_TYPE_FDB] = {.func = fw_parse_fdb_evt},
	[PRESTERA_EVENT_TYPE_FW_LOG] = {.func = fw_parse_log_evt}
};

static struct prestera_fw_event_handler *
__find_event_handler(const struct prestera_switch *sw,
		     enum prestera_event_type type)
{
	struct prestera_fw_event_handler *eh;

	list_for_each_entry_rcu(eh, &sw->event_handlers, list) {
		if (eh->type == type)
			return eh;
	}

	return NULL;
}

static int prestera_find_event_handler(const struct prestera_switch *sw,
				       enum prestera_event_type type,
				       struct prestera_fw_event_handler *eh)
{
	struct prestera_fw_event_handler *tmp;
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

static void fw_reset_wdog(struct prestera_device *dev)
{
	if (dev->running)
		atomic_set(&dev->keepalive_wdog_counter, 0);
}

static int fw_event_recv(struct prestera_device *dev, u8 *buf, size_t size)
{
	struct prestera_msg_event *msg = (struct prestera_msg_event *)buf;
	struct prestera_switch *sw = dev->priv;
	struct prestera_fw_event_handler eh;
	struct prestera_event evt;
	u16 msg_type;
	int err;

	fw_reset_wdog(dev);
	msg_type = __le16_to_cpu(msg->type);
	if (msg_type >= PRESTERA_EVENT_TYPE_MAX)
		return -EINVAL;
	if (!fw_event_parsers[msg_type].func)
		return -ENOENT;

	err = prestera_find_event_handler(sw, msg_type, &eh);

	if (err || !fw_event_parsers[msg_type].func)
		return 0;

	evt.id = __le16_to_cpu(msg->id);

	err = fw_event_parsers[msg_type].func(buf, &evt);
	if (!err)
		eh.func(sw, &evt, eh.arg);

	return err;
}

static void fw_pkt_recv(struct prestera_device *dev)
{
	struct prestera_switch *sw = dev->priv;
	struct prestera_fw_event_handler eh;
	struct prestera_event ev;
	int err;

	ev.id = PRESTERA_RXTX_EVENT_RCV_PKT;

	err = prestera_find_event_handler(sw, PRESTERA_EVENT_TYPE_RXTX, &eh);
	if (err)
		return;

	eh.func(sw, &ev, eh.arg);
}

int prestera_hw_port_info_get(const struct prestera_port *port,
			      u16 *fp_id, u32 *hw_id, u32 *dev_id)
{
	struct prestera_msg_port_info_resp resp;
	struct prestera_msg_port_info_req req = {
		.port = __cpu_to_le32(port->id)
	};
	int err;

	err = fw_send_req_resp(port->sw, PRESTERA_CMD_TYPE_PORT_INFO_GET,
			&req, &resp);

	if (err)
		return err;

	*hw_id = __le32_to_cpu(resp.hw_id);
	*dev_id = __le32_to_cpu(resp.dev_id);
	*fp_id = __le16_to_cpu(resp.fp_id);

	return 0;
}

int prestera_hw_switch_init(struct prestera_switch *sw)
{
	struct prestera_msg_keepalive_init_req keepalive_init_req = {
		.pulse_timeout_ms = __cpu_to_le32(PRESTERA_FW_WD_KICK_TIMEOUT)
	};
	struct prestera_msg_switch_init_resp resp;
	struct prestera_msg_common_req req;
	int err = 0;

	INIT_LIST_HEAD(&sw->event_handlers);

	prestera_hw_build_tests();

	err = fw_send_req_resp_wait(sw, PRESTERA_CMD_TYPE_SWITCH_INIT,
				    &req, &resp, PRESTERA_HW_INIT_TIMEOUT);
	if (err)
		return err;

	sw->id = resp.switch_id;
	sw->port_count = __le32_to_cpu(resp.port_count);
	sw->mtu_min = PRESTERA_HW_MIN_MTU;
	sw->mtu_max = __le32_to_cpu(resp.mtu_max);
	sw->lag_max = resp.lag_max;
	sw->lag_member_max = resp.lag_member_max;
	sw->size_tbl_router_nexthop = __le32_to_cpu(resp.size_tbl_router_nexthop);
	sw->dev->recv_msg = fw_event_recv;
	sw->dev->recv_pkt = fw_pkt_recv;

	err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_KEEPALIVE_INIT,
			       &keepalive_init_req, &resp);
	if (err)
		return err;

	INIT_DELAYED_WORK(&sw->dev->keepalive_wdog_work,
			  prestera_fw_keepalive_wd_work_fn);

	prestera_fw_wdog_restart(sw->dev);

	return err;
}

void prestera_hw_keepalive_fini(const struct prestera_switch *sw)
{
	if (sw->dev->running)
		cancel_delayed_work_sync(&sw->dev->keepalive_wdog_work);
}

int prestera_hw_switch_ageing_set(const struct prestera_switch *sw,
				  u32 ageing_time)
{
	struct prestera_msg_switch_attr_req req = {
		.param = {.ageing_timeout_ms = __cpu_to_le32(ageing_time)},
		.attr = __cpu_to_le32(PRESTERA_CMD_SWITCH_ATTR_AGEING),
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_SWITCH_ATTR_SET, &req);
}

int prestera_hw_switch_mac_set(const struct prestera_switch *sw, const u8 *mac)
{
	struct prestera_msg_switch_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_SWITCH_ATTR_MAC),
	};

	memcpy(req.param.mac, mac, sizeof(req.param.mac));

	return fw_send_req(sw, PRESTERA_CMD_TYPE_SWITCH_ATTR_SET, &req);
}

int prestera_hw_switch_trap_policer_set(const struct prestera_switch *sw,
					u8 profile)
{
	struct prestera_msg_switch_attr_req req = {
		.param = {.trap_policer_profile = __cpu_to_le32(profile)},
		.attr = __cpu_to_le32(PRESTERA_CMD_SWITCH_ATTR_TRAP_POLICER),
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_SWITCH_ATTR_SET, &req);
}

int prestera_hw_port_mtu_set(const struct prestera_port *port, u32 mtu)
{
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_MTU),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.param = {.mtu = __cpu_to_le32(mtu)}
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_SET, &req);
}

int prestera_hw_port_mtu_get(const struct prestera_port *port, u32 *mtu)
{
	struct prestera_msg_port_attr_resp resp;
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_MTU),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id)
	};
	int err;

	err = fw_send_req_resp(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	*mtu = __le32_to_cpu(resp.param.mtu);

	return err;
}

int prestera_hw_port_mac_set(const struct prestera_port *port, char *mac)
{
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_MAC),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id)
	};
	memcpy(&req.param.mac, mac, sizeof(req.param.mac));

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_SET, &req);
}

int prestera_hw_port_mac_get(const struct prestera_port *port, char *mac)
{
	struct prestera_msg_port_attr_resp resp;
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_MAC),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id)
	};
	int err;

	err = fw_send_req_resp(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	memcpy(mac, resp.param.mac, sizeof(resp.param.mac));

	return err;
}

int prestera_hw_port_accept_frame_type_set(const struct prestera_port *port,
					   enum prestera_accept_frame_type type)
{
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_ACCEPT_FRAME_TYPE),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.param = {.accept_frm_type = type}
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_SET, &req);
}

int prestera_hw_port_learning_set(const struct prestera_port *port, bool enable)
{
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_LEARNING),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.param = {.learning = enable ? 1 : 0}
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_SET, &req);
}

int prestera_hw_event_handler_register(struct prestera_switch *sw,
				       enum prestera_event_type type,
				       void (*cb)(struct prestera_switch *sw,
						  struct prestera_event *evt,
						  void *arg),
				       void *arg)
{
	struct prestera_fw_event_handler *eh;

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

void prestera_hw_event_handler_unregister(struct prestera_switch *sw,
					  enum prestera_event_type type)
{
	struct prestera_fw_event_handler *eh;

	eh = __find_event_handler(sw, type);
	if (!eh)
		return;

	list_del_rcu(&eh->list);
	synchronize_rcu();
	kfree(eh);
}

int prestera_hw_vlan_create(const struct prestera_switch *sw, u16 vid)
{
	struct prestera_msg_vlan_req req = {
		.vid = __cpu_to_le16(vid),
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_VLAN_CREATE, &req);
}

int prestera_hw_vlan_delete(const struct prestera_switch *sw, u16 vid)
{
	struct prestera_msg_vlan_req req = {
		.vid = __cpu_to_le16(vid),
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_VLAN_DELETE, &req);
}

int prestera_hw_vlan_port_set(const struct prestera_port *port,
			      u16 vid, bool is_member, bool untagged)
{
	struct prestera_msg_vlan_req req = {
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.vid = __cpu_to_le16(vid),
		.is_member = is_member ? 1 : 0,
		.is_tagged = untagged ? 0 : 1
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_VLAN_PORT_SET, &req);
}

int prestera_hw_vlan_port_vid_set(const struct prestera_port *port, u16 vid)
{
	struct prestera_msg_vlan_req req = {
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.vid = __cpu_to_le16(vid)
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_VLAN_PVID_SET, &req);
}

int prestera_hw_port_vid_stp_set(struct prestera_port *port, u16 vid, u8 state)
{
	struct prestera_msg_stp_req req = {
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.vid = __cpu_to_le16(vid),
		.state = state
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_STP_PORT_SET, &req);
}

int prestera_hw_port_uc_flood_set(const struct prestera_port *port, bool flood)
{
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_FLOOD),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.param = {
			.flood_ext = {
				.type = PRESTERA_PORT_FLOOD_TYPE_UC,
				.enable = flood,
			}
		}
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_SET, &req);
}

int prestera_hw_port_mc_flood_set(const struct prestera_port *port, bool flood)
{
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_FLOOD),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.param = {
			.flood_ext = {
				.type = PRESTERA_PORT_FLOOD_TYPE_MC,
				.enable = flood,
			}
		}
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_SET, &req);
}

int prestera_hw_port_srcid_default_set(const struct prestera_port *port,
				       u32 sourceid)
{
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_SOURCE_ID_DEFAULT),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.param = {
			.source_id_default = __cpu_to_le32(sourceid)
		}
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_SET, &req);
}

int prestera_hw_port_srcid_filter_set(const struct prestera_port *port,
				      u32 sourceid)
{
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_SOURCE_ID_FILTER),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.param = {
			.source_id_filter = __cpu_to_le32(sourceid)
		}
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_SET, &req);
}

int prestera_hw_fdb_add(const struct prestera_port *port,
			const unsigned char *mac, u16 vid, bool dynamic)
{
	struct prestera_msg_fdb_req req = {
		.dest_type = PRESTERA_HW_FDB_ENTRY_TYPE_REG_PORT,
		.dest = {
			.dev = __cpu_to_le32(port->dev_id),
			.port = __cpu_to_le32(port->hw_id),
		},
		.vid = __cpu_to_le16(vid),
		.dynamic = dynamic
	};

	memcpy(req.mac, mac, sizeof(req.mac));

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_FDB_ADD, &req);
}

int prestera_hw_lag_fdb_add(const struct prestera_switch *sw, u16 lag_id,
			    const unsigned char *mac, u16 vid, bool dynamic)
{
	struct prestera_msg_fdb_req req = {
		.dest_type = PRESTERA_HW_FDB_ENTRY_TYPE_LAG,
		.dest = { .lag_id = __cpu_to_le16(lag_id) },
		.vid = __cpu_to_le16(vid),
		.dynamic = dynamic
	};

	memcpy(req.mac, mac, sizeof(req.mac));

	return fw_send_req(sw, PRESTERA_CMD_TYPE_FDB_ADD, &req);
}

int prestera_hw_fdb_del(const struct prestera_port *port,
			const unsigned char *mac, u16 vid)
{
	struct prestera_msg_fdb_req req = {
		.dest_type = PRESTERA_HW_FDB_ENTRY_TYPE_REG_PORT,
		.dest = {
			.dev = __cpu_to_le32(port->dev_id),
			.port = __cpu_to_le32(port->hw_id),
		},
		.vid = __cpu_to_le16(vid)
	};

	memcpy(req.mac, mac, sizeof(req.mac));

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_FDB_DELETE, &req);
}

int prestera_hw_lag_fdb_del(const struct prestera_switch *sw, u16 lag_id,
			    const unsigned char *mac, u16 vid)
{
	struct prestera_msg_fdb_req req = {
		.dest_type = PRESTERA_HW_FDB_ENTRY_TYPE_LAG,
		.dest = { .lag_id = __cpu_to_le16(lag_id) },
		.vid = __cpu_to_le16(vid)
	};

	memcpy(req.mac, mac, sizeof(req.mac));

	return fw_send_req(sw, PRESTERA_CMD_TYPE_FDB_DELETE, &req);
}

int prestera_hw_port_cap_get(const struct prestera_port *port,
			     struct prestera_port_caps *caps)
{
	struct prestera_msg_port_attr_resp resp;
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_CAPABILITY),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id)
	};
	int err;

	err = fw_send_req_resp(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	caps->supp_link_modes = __le64_to_cpu(resp.param.cap.link_mode);
	caps->supp_fec = resp.param.cap.fec;
	caps->type = resp.param.cap.type;
	caps->transceiver = resp.param.cap.transceiver;

	return err;
}

static u8 prestera_hw_mdix_to_eth(u8 mode)
{
	switch (mode) {
	case PRESTERA_PORT_TP_MDI:
		return ETH_TP_MDI;
	case PRESTERA_PORT_TP_MDIX:
		return ETH_TP_MDI_X;
	case PRESTERA_PORT_TP_AUTO:
		return ETH_TP_MDI_AUTO;
	}

	return ETH_TP_MDI_INVALID;
}

static u8 prestera_hw_mdix_from_eth(u8 mode)
{
	switch (mode) {
	case ETH_TP_MDI:
		return PRESTERA_PORT_TP_MDI;
	case ETH_TP_MDI_X:
		return PRESTERA_PORT_TP_MDIX;
	case ETH_TP_MDI_AUTO:
		return PRESTERA_PORT_TP_AUTO;
	}

	return PRESTERA_PORT_TP_NA;
}

static void prestera_hw_remote_fc_to_eth(u8 fc, bool *pause, bool *asym_pause)
{
	switch (fc) {
	case PRESTERA_FC_SYMMETRIC:
		*pause = true;
		*asym_pause = false;
		break;
	case PRESTERA_FC_ASYMMETRIC:
		*pause = false;
		*asym_pause = true;
		break;
	case PRESTERA_FC_SYMM_ASYMM:
		*pause = true;
		*asym_pause = true;
		break;
	default:
		*pause = false;
		*asym_pause = false;
	};
}

int prestera_hw_fw_log_level_set(const struct prestera_switch *sw,
				 u32 lib, u32 type)
{
	struct prestera_msg_log_lvl_set_req req = {
		.lib = __cpu_to_le32(lib),
		.type = __cpu_to_le32(type)
	};
	int err;

	err = fw_send_req(sw, PRESTERA_CMD_TYPE_LOG_LEVEL_SET, &req);
	if (err)
		return err;

	return 0;
}

int prestera_hw_port_stats_get(const struct prestera_port *port,
			       struct prestera_port_stats *stats)
{
	struct prestera_msg_port_stats_resp resp;
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_STATS),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id)
	};
	int err;
	__le64 *hw_val = resp.stats;

	err = fw_send_req_resp(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	stats->good_octets_received = __le64_to_cpu(hw_val[PRESTERA_PORT_GOOD_OCTETS_RCV_CNT]);
	stats->bad_octets_received = __le64_to_cpu(hw_val[PRESTERA_PORT_BAD_OCTETS_RCV_CNT]);
	stats->mac_trans_error = __le64_to_cpu(hw_val[PRESTERA_PORT_MAC_TRANSMIT_ERR_CNT]);
	stats->broadcast_frames_received =
		__le64_to_cpu(hw_val[PRESTERA_PORT_BRDC_PKTS_RCV_CNT]);
	stats->multicast_frames_received =
		__le64_to_cpu(hw_val[PRESTERA_PORT_MC_PKTS_RCV_CNT]);
	stats->frames_64_octets = __le64_to_cpu(hw_val[PRESTERA_PORT_PKTS_64_OCTETS_CNT]);
	stats->frames_65_to_127_octets =
		__le64_to_cpu(hw_val[PRESTERA_PORT_PKTS_65TO127_OCTETS_CNT]);
	stats->frames_128_to_255_octets =
		__le64_to_cpu(hw_val[PRESTERA_PORT_PKTS_128TO255_OCTETS_CNT]);
	stats->frames_256_to_511_octets =
		__le64_to_cpu(hw_val[PRESTERA_PORT_PKTS_256TO511_OCTETS_CNT]);
	stats->frames_512_to_1023_octets =
		__le64_to_cpu(hw_val[PRESTERA_PORT_PKTS_512TO1023_OCTETS_CNT]);
	stats->frames_1024_to_max_octets =
		__le64_to_cpu(hw_val[PRESTERA_PORT_PKTS_1024TOMAX_OCTETS_CNT]);
	stats->excessive_collision =
		__le64_to_cpu(hw_val[PRESTERA_PORT_EXCESSIVE_COLLISIONS_CNT]);
	stats->multicast_frames_sent = __le64_to_cpu(hw_val[PRESTERA_PORT_MC_PKTS_SENT_CNT]);
	stats->broadcast_frames_sent = __le64_to_cpu(hw_val[PRESTERA_PORT_BRDC_PKTS_SENT_CNT]);
	stats->fc_sent = __le64_to_cpu(hw_val[PRESTERA_PORT_FC_SENT_CNT]);
	stats->fc_received = __le64_to_cpu(hw_val[PRESTERA_PORT_GOOD_FC_RCV_CNT]);
	stats->buffer_overrun = __le64_to_cpu(hw_val[PRESTERA_PORT_DROP_EVENTS_CNT]);
	stats->undersize = __le64_to_cpu(hw_val[PRESTERA_PORT_UNDERSIZE_PKTS_CNT]);
	stats->fragments = __le64_to_cpu(hw_val[PRESTERA_PORT_FRAGMENTS_PKTS_CNT]);
	stats->oversize = __le64_to_cpu(hw_val[PRESTERA_PORT_OVERSIZE_PKTS_CNT]);
	stats->jabber = __le64_to_cpu(hw_val[PRESTERA_PORT_JABBER_PKTS_CNT]);
	stats->rx_error_frame_received =
		__le64_to_cpu(hw_val[PRESTERA_PORT_MAC_RCV_ERROR_CNT]);
	stats->bad_crc = __le64_to_cpu(hw_val[PRESTERA_PORT_BAD_CRC_CNT]);
	stats->collisions = __le64_to_cpu(hw_val[PRESTERA_PORT_COLLISIONS_CNT]);
	stats->late_collision = __le64_to_cpu(hw_val[PRESTERA_PORT_LATE_COLLISIONS_CNT]);
	stats->unicast_frames_received =
		__le64_to_cpu(hw_val[PRESTERA_PORT_GOOD_UC_PKTS_RCV_CNT]);
	stats->unicast_frames_sent =
		__le64_to_cpu(hw_val[PRESTERA_PORT_GOOD_UC_PKTS_SENT_CNT]);
	stats->sent_multiple = __le64_to_cpu(hw_val[PRESTERA_PORT_MULTIPLE_PKTS_SENT_CNT]);
	stats->sent_deferred = __le64_to_cpu(hw_val[PRESTERA_PORT_DEFERRED_PKTS_SENT_CNT]);
	stats->good_octets_sent = __le64_to_cpu(hw_val[PRESTERA_PORT_GOOD_OCTETS_SENT_CNT]);

	return 0;
}

int prestera_hw_bridge_create(const struct prestera_switch *sw, u16 *bridge_id)
{
	struct prestera_msg_bridge_req req;
	struct prestera_msg_bridge_resp resp;
	int err;

	err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_BRIDGE_CREATE,
			       &req, &resp);
	if (err)
		return err;

	*bridge_id = __le16_to_cpu(resp.bridge);
	return err;
}

int prestera_hw_bridge_delete(const struct prestera_switch *sw, u16 bridge_id)
{
	struct prestera_msg_bridge_req req = {
		.bridge = __cpu_to_le16(bridge_id)
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_BRIDGE_DELETE, &req);
}

int prestera_hw_bridge_port_add(const struct prestera_port *port, u16 bridge_id)
{
	struct prestera_msg_bridge_req req = {
		.bridge = __cpu_to_le16(bridge_id),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id)
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_BRIDGE_PORT_ADD, &req);
}

int prestera_hw_bridge_port_delete(const struct prestera_port *port,
				   u16 bridge_id)
{
	struct prestera_msg_bridge_req req = {
		.bridge = __cpu_to_le16(bridge_id),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id)
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_BRIDGE_PORT_DELETE,
			   &req);
}

int prestera_hw_macvlan_add(const struct prestera_switch *sw, u16 vr_id,
			    const u8 *mac, u16 vid,
			    struct prestera_iface *iface)
{
	struct prestera_msg_macvlan_req req = {
		.vr_id = 0,
		.vid = __cpu_to_le16(vid)
	};
	int err;

	err = prestera_iface_to_msg(iface, &req.iface);
	if (err)
		return err;

	memcpy(req.mac, mac, ETH_ALEN);

	return fw_send_req(sw, PRESTERA_CMD_TYPE_FDB_MACVLAN_ADD, &req);
}

int prestera_hw_macvlan_del(const struct prestera_switch *sw, u16 vr_id,
			    const u8 *mac, u16 vid,
			    struct prestera_iface *iface)
{
	struct prestera_msg_macvlan_req req = {
		.vr_id = 0,
		.vid = __cpu_to_le16(vid)
	};
	int err;

	err = prestera_iface_to_msg(iface, &req.iface);
	if (err)
		return err;

	memcpy(req.mac, mac, ETH_ALEN);

	return fw_send_req(sw, PRESTERA_CMD_TYPE_FDB_MACVLAN_DEL, &req);
}

int prestera_hw_fdb_routed_add(const struct prestera_switch *sw,
			       const u8 *mac, u16 vid)
{
	struct prestera_msg_macvlan_req req = {
		.vr_id = 0,
		.vid = __cpu_to_le16(vid)
	};

	req.iface.type = PRESTERA_IF_VID_E;
	memcpy(req.mac, mac, ETH_ALEN);

	return fw_send_req(sw, PRESTERA_CMD_TYPE_FDB_ROUTED_ADD, &req);
}

int prestera_hw_fdb_routed_del(const struct prestera_switch *sw,
			       const u8 *mac, u16 vid)
{
	struct prestera_msg_macvlan_req req = {
		.vr_id = 0,
		.vid = __cpu_to_le16(vid)
	};

	req.iface.type = PRESTERA_IF_VID_E;
	memcpy(req.mac, mac, ETH_ALEN);

	return fw_send_req(sw, PRESTERA_CMD_TYPE_FDB_ROUTED_DEL, &req);
}

int prestera_hw_fdb_flush_port(const struct prestera_port *port, u32 mode)
{
	struct prestera_msg_fdb_req req = {
		.dest_type = PRESTERA_HW_FDB_ENTRY_TYPE_REG_PORT,
		.dest = {
			.dev = __cpu_to_le32(port->dev_id),
			.port = __cpu_to_le32(port->hw_id),
		},
		.flush_mode = __cpu_to_le32(mode),
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_FDB_FLUSH_PORT, &req);
}

int prestera_hw_fdb_flush_lag(const struct prestera_switch *sw, u16 lag_id,
			      u32 mode)
{
	struct prestera_msg_fdb_req req = {
		.dest_type = PRESTERA_HW_FDB_ENTRY_TYPE_LAG,
		.dest = { .lag_id = __cpu_to_le16(lag_id) },
		.flush_mode = __cpu_to_le32(mode),
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_FDB_FLUSH_PORT, &req);
}

int prestera_hw_fdb_flush_vlan(const struct prestera_switch *sw, u16 vid,
			       u32 mode)
{
	struct prestera_msg_fdb_req req = {
		.vid = __cpu_to_le16(vid),
		.flush_mode = __cpu_to_le32(mode),
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_FDB_FLUSH_VLAN, &req);
}

int prestera_hw_fdb_flush_port_vlan(const struct prestera_port *port, u16 vid,
				    u32 mode)
{
	struct prestera_msg_fdb_req req = {
		.dest_type = PRESTERA_HW_FDB_ENTRY_TYPE_REG_PORT,
		.dest = {
			.dev = __cpu_to_le32(port->dev_id),
			.port = __cpu_to_le32(port->hw_id),
		},
		.vid = __cpu_to_le16(vid),
		.flush_mode = __cpu_to_le32(mode),
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_FDB_FLUSH_PORT_VLAN,
			   &req);
}

int prestera_hw_fdb_flush_lag_vlan(const struct prestera_switch *sw,
				   u16 lag_id, u16 vid, u32 mode)
{
	struct prestera_msg_fdb_req req = {
		.dest_type = PRESTERA_HW_FDB_ENTRY_TYPE_LAG,
		.dest = { .lag_id = __cpu_to_le16(lag_id) },
		.vid = __cpu_to_le16(vid),
		.flush_mode = __cpu_to_le32(mode),
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_FDB_FLUSH_PORT_VLAN, &req);
}

int prestera_hw_port_mac_mode_get(const struct prestera_port *port,
				  u32 *mode, u32 *speed, u8 *duplex, u8 *fec)
{
	struct prestera_msg_port_attr_resp resp;
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_MAC_MODE),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id)
	};
	int err;

	err = fw_send_req_resp(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	if (mode)
		*mode = __le32_to_cpu(resp.param.link_evt.mac.mode);

	if (speed)
		*speed = __le32_to_cpu(resp.param.link_evt.mac.speed);

	if (duplex)
		*duplex = resp.param.link_evt.mac.duplex;

	if (fec)
		*fec = resp.param.link_evt.mac.fec;

	return err;
}

int prestera_hw_port_mac_mode_set(const struct prestera_port *port,
				  bool admin, u32 mode, u8 inband,
				  u32 speed, u8 duplex, u8 fec)
{
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_MAC_MODE),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.param = {
			.link = {
				.mac = {
					.admin = admin,
					.reg_mode.mode = __cpu_to_le32(mode),
					.reg_mode.inband = inband,
					.reg_mode.speed = __cpu_to_le32(speed),
					.reg_mode.duplex = duplex,
					.reg_mode.fec = fec
				}
			}
		}
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_SET, &req);
}

int prestera_hw_port_phy_mode_get(const struct prestera_port *port,
				  u8 *mdix, u64 *lmode_bmap,
				  bool *fc_pause, bool *fc_asym)
{
	struct prestera_msg_port_attr_resp resp;
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_PHY_MODE),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id)
	};
	int err;

	err = fw_send_req_resp(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_GET,
			       &req, &resp);
	if (err)
		return err;

	if (mdix)
		*mdix = prestera_hw_mdix_to_eth(resp.param.link_evt.phy.mdix);

	if (lmode_bmap)
		*lmode_bmap = __le64_to_cpu(resp.param.link_evt.phy.lmode_bmap);

	if (fc_pause && fc_asym)
		prestera_hw_remote_fc_to_eth(resp.param.link_evt.phy.fc,
					     fc_pause, fc_asym);

	return err;
}

int prestera_hw_port_phy_mode_set(const struct prestera_port *port,
				  bool admin, bool adv, u32 mode, u64 modes,
				  u8 mdix)
{
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_PHY_MODE),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.param = {
			.link = {
				.phy = {
					.admin = admin,
					.adv_enable = adv ? 1 : 0,
					.mode = __cpu_to_le32(mode),
					.modes = __cpu_to_le64(modes),
				}
			}
		}
	};

	req.param.link.phy.mdix = prestera_hw_mdix_from_eth(mdix);
	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_SET, &req);
}

int prestera_hw_port_storm_control_cfg_set(const struct prestera_port *port,
					   u32 storm_type,
					   u32 kbyte_per_sec_rate)
{
	struct prestera_msg_port_storm_control_cfg_set_req req = {
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.storm_type = __cpu_to_le32(storm_type),
		.kbyte_per_sec_rate = __cpu_to_le32(kbyte_per_sec_rate)
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_PORT_RATE_LIMIT_MODE_SET,
			   &req);
}

static int prestera_iface_to_msg(struct prestera_iface *iface,
				 struct prestera_msg_iface *msg_if)
{
	switch (iface->type) {
	case PRESTERA_IF_PORT_E:
	case PRESTERA_IF_VID_E:
		msg_if->port = __cpu_to_le32(iface->dev_port.port_num);
		msg_if->dev = __cpu_to_le32(iface->dev_port.hw_dev_num);
		break;
	case PRESTERA_IF_LAG_E:
		msg_if->lag_id = __cpu_to_le16(iface->lag_id);
		break;
	default:
		return -ENOTSUPP;
	}

	msg_if->vr_id = __cpu_to_le16(iface->vr_id);
	msg_if->vid = __cpu_to_le16(iface->vlan_id);
	msg_if->type = iface->type;
	return 0;
}

int prestera_hw_rif_create(const struct prestera_switch *sw,
			   struct prestera_iface *iif, u8 *mac, u16 *rif_id)
{
	struct prestera_msg_rif_req req;
	struct prestera_msg_rif_resp resp;
	int err;

	memcpy(req.mac, mac, ETH_ALEN);

	err = prestera_iface_to_msg(iif, &req.iif);
	if (err)
		return err;

	err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_ROUTER_RIF_CREATE,
			       &req, &resp);
	if (err)
		return err;

	*rif_id = __le16_to_cpu(resp.rif_id);
	return err;
}

int prestera_hw_rif_delete(const struct prestera_switch *sw, u16 rif_id,
			   struct prestera_iface *iif)
{
	struct prestera_msg_rif_req req = {
		.rif_id = __cpu_to_le16(rif_id),
	};
	int err;

	err = prestera_iface_to_msg(iif, &req.iif);
	if (err)
		return err;

	return fw_send_req(sw, PRESTERA_CMD_TYPE_ROUTER_RIF_DELETE, &req);
}

int prestera_hw_rif_set(const struct prestera_switch *sw, u16 *rif_id,
			struct prestera_iface *iif, u8 *mac)
{
	struct prestera_msg_rif_resp resp;
	struct prestera_msg_rif_req req = {
		.rif_id = __cpu_to_le16(*rif_id),
	};
	int err;

	memcpy(req.mac, mac, ETH_ALEN);

	err = prestera_iface_to_msg(iif, &req.iif);
	if (err)
		return err;

	err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_ROUTER_RIF_SET,
			       &req, &resp);
	if (err)
		return err;

	*rif_id = __le16_to_cpu(resp.rif_id);
	return err;
}

int prestera_hw_vr_create(const struct prestera_switch *sw, u16 *vr_id)
{
	int err;
	struct prestera_msg_vr_resp resp;
	struct prestera_msg_vr_req req;

	err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_ROUTER_VR_CREATE,
			       &req, &resp);
	if (err)
		return err;

	*vr_id = __le16_to_cpu(resp.vr_id);
	return err;
}

int prestera_hw_vr_delete(const struct prestera_switch *sw, u16 vr_id)
{
	struct prestera_msg_vr_req req = {
		.vr_id = __cpu_to_le16(vr_id),
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_ROUTER_VR_DELETE, &req);
}

int prestera_hw_lpm_add(const struct prestera_switch *sw, u16 vr_id,
			__be32 dst, u32 dst_len, u32 grp_id)
{
	struct prestera_msg_lpm_req req = {
		.dst.v = PRESTERA_MSG_IPV4,
		.dst.u.ipv4 = dst,
		.dst_len = __cpu_to_le32(dst_len),
		.vr_id = __cpu_to_le16(vr_id),
		.grp_id = __cpu_to_le32(grp_id)
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_ROUTER_LPM_ADD, &req);
}

int prestera_hw_lpm_del(const struct prestera_switch *sw, u16 vr_id, __be32 dst,
			u32 dst_len)
{
	struct prestera_msg_lpm_req req = {
		.dst.v = PRESTERA_MSG_IPV4,
		.dst.u.ipv4 = dst,
		.dst_len = __cpu_to_le32(dst_len),
		.vr_id = __cpu_to_le16(vr_id),
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_ROUTER_LPM_DELETE, &req);
}

int prestera_hw_lpm6_add(const struct prestera_switch *sw, u16 vr_id,
			 __u8 *dst, u32 dst_len, u32 grp_id)
{
	struct prestera_msg_lpm_req req;

	req.dst.v = PRESTERA_MSG_IPV6;
	memcpy(&req.dst.u.ipv6, dst, 16);
	req.dst_len = __cpu_to_le32(dst_len);
	req.vr_id = __cpu_to_le16(vr_id);
	req.grp_id = __cpu_to_le32(grp_id);

	return fw_send_req(sw, PRESTERA_CMD_TYPE_ROUTER_LPM_ADD, &req);
}

int prestera_hw_lpm6_del(const struct prestera_switch *sw, u16 vr_id,
			 __u8 *dst, u32 dst_len)
{
	struct prestera_msg_lpm_req req;

	req.dst.v = PRESTERA_MSG_IPV6;
	memcpy(&req.dst.u.ipv6, dst, 16);
	req.dst_len = __cpu_to_le32(dst_len);
	req.vr_id = __cpu_to_le16(vr_id);

	return fw_send_req(sw, PRESTERA_CMD_TYPE_ROUTER_LPM_DELETE, &req);
}

int prestera_hw_nh_entries_set(const struct prestera_switch *sw, int count,
			       struct prestera_neigh_info *nhs, u32 grp_id)
{
	struct prestera_msg_nh_req req = { .size = __cpu_to_le32((u32)count),
			.grp_id = __cpu_to_le32(grp_id) };
	int i, err;

	for (i = 0; i < count; i++) {
		req.nh[i].is_active = nhs[i].connected;
		memcpy(&req.nh[i].mac, nhs[i].ha, ETH_ALEN);
		err = prestera_iface_to_msg(&nhs[i].iface, &req.nh[i].oif);
		if (err)
			return err;
	}

	return fw_send_req(sw, PRESTERA_CMD_TYPE_ROUTER_NH_GRP_SET, &req);
}

/* TODO: more than one nh */
/* For now "count = 1" supported only */
int prestera_hw_nh_entries_get(const struct prestera_switch *sw, int count,
			       struct prestera_neigh_info *nhs, u32 grp_id)
{
	struct prestera_msg_nh_req req = { .size = __cpu_to_le32((u32)count),
			.grp_id = __cpu_to_le32(grp_id) };
	struct prestera_msg_nh_resp resp;
	int err, i;

	err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_ROUTER_NH_GRP_GET,
			       &req, &resp);
	if (err)
		return err;

	for (i = 0; i < count; i++)
		nhs[i].connected = resp.nh[i].is_active;

	return err;
}

int prestera_hw_nhgrp_blk_get(const struct prestera_switch *sw,
			      u8 *hw_state, u32 buf_size /* Buffer in bytes */)
{
	struct prestera_msg_nh_chunk_req req;
	static struct prestera_msg_nh_chunk_resp resp;
	int err;
	u32 buf_offset;

	memset(&hw_state[0], 0, buf_size);
	buf_offset = 0;
	while (1) {
		if (buf_offset >= buf_size)
			break;

		memset(&req, 0, sizeof(req));
		req.offset = __cpu_to_le32(buf_offset * 8); /* 8 bits in u8 */
		err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_ROUTER_NH_GRP_BLK_GET,
				       &req, &resp);
		if (err)
			return err;

		memcpy(&hw_state[buf_offset], &resp.hw_state[0],
		       buf_offset + PRESTERA_MSG_CHUNK_SIZE > buf_size ?
			buf_size - buf_offset : PRESTERA_MSG_CHUNK_SIZE);
		buf_offset += PRESTERA_MSG_CHUNK_SIZE;
	}

	return err;
}

int prestera_hw_nh_group_create(const struct prestera_switch *sw, u16 nh_count,
				u32 *grp_id)
{
	struct prestera_msg_nh_grp_req req = { .size = __cpu_to_le32((u32)nh_count) };
	struct prestera_msg_nh_grp_resp resp;
	int err;

	err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_ROUTER_NH_GRP_ADD, &req,
			       &resp);
	if (err)
		return err;

	*grp_id = __le32_to_cpu(resp.grp_id);
	return err;
}

int prestera_hw_nh_group_delete(const struct prestera_switch *sw, u16 nh_count,
				u32 grp_id)
{
	struct prestera_msg_nh_grp_req req = {
	    .grp_id = __cpu_to_le32(grp_id),
	    .size = __cpu_to_le32(nh_count)
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_ROUTER_NH_GRP_DELETE, &req);
}

int prestera_hw_mp4_hash_set(const struct prestera_switch *sw, u8 hash_policy)
{
	struct prestera_msg_mp_req req = { .hash_policy = hash_policy};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_ROUTER_MP_HASH_SET, &req);
}

int prestera_hw_rxtx_init(const struct prestera_switch *sw, bool use_sdma,
			  u32 *map_addr)
{
	struct prestera_msg_rxtx_resp resp;
	struct prestera_msg_rxtx_req req;
	int err;

	req.use_sdma = use_sdma;

	err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_RXTX_INIT, &req, &resp);
	if (err)
		return err;

	if (map_addr)
		*map_addr = __le32_to_cpu(resp.map_addr);

	return 0;
}

int prestera_hw_port_autoneg_restart(struct prestera_port *port)
{
	struct prestera_msg_port_attr_req req = {
		.attr = __cpu_to_le32(PRESTERA_CMD_PORT_ATTR_PHY_AUTONEG_RESTART),
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_PORT_ATTR_SET, &req);
}

/* ACL API */
static int acl_rule_add_put_action(struct prestera_msg_acl_action *action,
				   struct prestera_acl_hw_action_info *info)
{
	action->id = __cpu_to_le32(info->id);

	switch (info->id) {
	case PRESTERA_ACL_RULE_ACTION_ACCEPT:
	case PRESTERA_ACL_RULE_ACTION_DROP:
		/* just rule action id, no specific data */
		break;
	case PRESTERA_ACL_RULE_ACTION_TRAP:
		action->trap.hw_tc = info->trap.hw_tc;
		break;
	case PRESTERA_ACL_RULE_ACTION_JUMP:
		action->jump.index = __cpu_to_le32(info->jump.index);
		break;
	case PRESTERA_ACL_RULE_ACTION_POLICE:
		action->police.rate = __cpu_to_le64(info->police.rate);
		action->police.burst = __cpu_to_le64(info->police.burst);
		break;
	case PRESTERA_ACL_RULE_ACTION_NH:
		action->nh.nh_id = __cpu_to_le32(info->nh);
		break;
	case PRESTERA_ACL_RULE_ACTION_NAT:
		action->nat.old_addr = info->nat.old_addr;
		action->nat.new_addr = info->nat.new_addr;
		action->nat.flags = __cpu_to_le32(info->nat.flags);
		action->nat.port = __cpu_to_le32(info->nat.port);
		action->nat.dev = __cpu_to_le32(info->nat.dev);
		break;
	case PRESTERA_ACL_RULE_ACTION_COUNT:
		action->count.id = __cpu_to_le32(info->count.id);
		break;
	case PRESTERA_ACL_RULE_ACTION_REMARK:
		action->remark.dscp = info->remark.dscp;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int prestera_hw_counter_trigger(const struct prestera_switch *sw, u32 block_id)
{
	struct prestera_msg_counter_req req = {
		.block_id = __cpu_to_le32(block_id)
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_COUNTER_TRIGGER, &req);
}

int prestera_hw_counter_abort(const struct prestera_switch *sw)
{
	struct prestera_msg_counter_req req;

	return fw_send_req(sw, PRESTERA_CMD_TYPE_COUNTER_ABORT, &req);
}

int prestera_hw_counters_get(const struct prestera_switch *sw, u32 idx,
			     u32 *len, bool *done,
			     struct prestera_counter_stats *stats)
{
	struct prestera_msg_counter_resp *resp;
	struct prestera_msg_counter_req req = {
		.block_id = __cpu_to_le32(idx),
		.num_counters = __cpu_to_le32(*len),
	};
	size_t size = sizeof(*resp) + sizeof(*resp->stats) * (*len);
	int err, i;

	resp = kmalloc(size, GFP_KERNEL);
	if (!resp)
		return -ENOMEM;

	err = fw_send_nreq_nresp(sw, PRESTERA_CMD_TYPE_COUNTER_GET,
				 &req, sizeof(req), resp, size);
	if (err)
		goto free_buff;

	for (i = 0; i < __le32_to_cpu(resp->num_counters); i++) {
		stats[i].packets += __le64_to_cpu(resp->stats[i].packets);
		stats[i].bytes += __le64_to_cpu(resp->stats[i].bytes);
	}

	*len = __le32_to_cpu(resp->num_counters);
	*done = resp->done;

free_buff:
	kfree(resp);
	return err;
}

int prestera_hw_counter_block_get(const struct prestera_switch *sw,
				  u32 client, u32 *block_id, u32 *offset,
				  u32 *num_counters)
{
	struct prestera_msg_counter_resp resp;
	struct prestera_msg_counter_req req = {
		.client = __cpu_to_le32(client)
	};
	int err = 0;

	err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_COUNTER_BLOCK_GET,
			       &req, &resp);
	if (err)
		return err;

	*block_id = __le32_to_cpu(resp.block_id);
	*offset = __le32_to_cpu(resp.offset);
	*num_counters = __le32_to_cpu(resp.num_counters);

	return 0;
}

int prestera_hw_counter_block_release(const struct prestera_switch *sw,
				      u32 block_id)
{
	struct prestera_msg_counter_req req = {
		.block_id = __cpu_to_le32(block_id)
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_COUNTER_BLOCK_RELEASE, &req);
}

int prestera_hw_counter_clear(const struct prestera_switch *sw, u32 block_id,
			      u32 counter_id)
{
	struct prestera_msg_counter_req req = {
		.block_id = __cpu_to_le32(block_id),
		.num_counters = __cpu_to_le32(counter_id),
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_COUNTER_CLEAR, &req);
}

int prestera_hw_nat_port_neigh_update(const struct prestera_port *port,
				      unsigned char *mac)
{
	struct prestera_msg_nat_port_req req = {
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
	};
	memcpy(req.neigh_mac, mac, sizeof(req.neigh_mac));
	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_NAT_PORT_NEIGH_UPDATE,
			   &req);
}

int prestera_hw_nh_mangle_add(const struct prestera_switch *sw, u32 *nh_id)
{
	struct prestera_msg_nh_mangle_req req;
	struct prestera_msg_nh_mangle_resp resp;
	int err;

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));
	err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_NAT_NH_MANGLE_ADD, &req,
			       &resp);
	if (err)
		return err;

	*nh_id = __le32_to_cpu(resp.nh_id);
	return 0;
}

int prestera_hw_nh_mangle_del(const struct prestera_switch *sw, u32 nh_id)
{
	struct prestera_msg_nh_mangle_req req;

	memset(&req, 0, sizeof(req));
	req.nh_id = __cpu_to_le32(nh_id);
	return fw_send_req(sw, PRESTERA_CMD_TYPE_NAT_NH_MANGLE_DEL, &req);
}

int prestera_hw_nh_mangle_set(const struct prestera_switch *sw, u32 nh_id,
			      bool l4_src_valid, __be16 l4_src,
			      bool l4_dst_valid, __be16 l4_dst,
			      bool sip_valid, struct prestera_ip_addr sip,
			      bool dip_valid, struct prestera_ip_addr dip,
			      struct prestera_neigh_info nh)
{
	struct prestera_msg_nh_mangle_req req;
	int err;

	if (sip.v != PRESTERA_IPV4 || dip.v != PRESTERA_IPV4)
		return -EINVAL;

	memset(&req, 0, sizeof(req));
	req.nh_id = __cpu_to_le32(nh_id);
	req.info.l4_src_valid = l4_src_valid;
	req.info.l4_dst_valid = l4_dst_valid;
	req.info.sip_valid = sip_valid;
	req.info.dip_valid = dip_valid;
	req.info.l4_src = l4_src;
	req.info.l4_dst = l4_dst;
	req.info.sip = sip.u.ipv4;
	req.info.dip = dip.u.ipv4;
	req.info.nh.is_active = nh.connected;
	memcpy(&req.info.nh.mac, nh.ha, ETH_ALEN);
	err = prestera_iface_to_msg(&nh.iface, &req.info.nh.oif);
	if (err)
		return err;

	return fw_send_req(sw, PRESTERA_CMD_TYPE_NAT_NH_MANGLE_SET, &req);
}

int prestera_hw_nh_mangle_get(const struct prestera_switch *sw, u32 nh_id,
			      bool *is_active)
{
	struct prestera_msg_nh_mangle_req req;
	struct prestera_msg_nh_mangle_resp resp;
	int err;

	memset(&req, 0, sizeof(req));
	req.nh_id = __cpu_to_le32(nh_id);
	memset(&resp, 0, sizeof(resp));
	err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_NAT_NH_MANGLE_GET, &req,
			       &resp);
	if (err)
		return err;

	*is_active = resp.info.nh.is_active;
	return 0;
}

int prestera_hw_span_get(const struct prestera_port *port, u8 *span_id)
{
	int err;
	struct prestera_msg_span_resp resp;
	struct prestera_msg_span_req req = {
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
	};

	err = fw_send_req_resp(port->sw, PRESTERA_CMD_TYPE_SPAN_GET,
			       &req, &resp);
	if (err)
		return err;

	*span_id = resp.id;

	return 0;
}

int prestera_hw_span_bind(const struct prestera_port *port, u8 span_id)
{
	struct prestera_msg_span_req req = {
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.id = span_id,
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_SPAN_BIND, &req);
}

int prestera_hw_span_unbind(const struct prestera_port *port)
{
	struct prestera_msg_span_req req = {
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_SPAN_UNBIND, &req);
}

int prestera_hw_span_release(const struct prestera_switch *sw, u8 span_id)
{
	struct prestera_msg_span_req req = {
		.id = span_id
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_SPAN_RELEASE, &req);
}

int prestera_hw_lag_member_add(struct prestera_port *port, u16 lag_id)
{
	struct prestera_msg_lag_req req = {
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.lag_id = __cpu_to_le16(lag_id)
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_LAG_ADD, &req);
}

int prestera_hw_lag_member_del(struct prestera_port *port, u16 lag_id)
{
	struct prestera_msg_lag_req req = {
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.lag_id = __cpu_to_le16(lag_id)
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_LAG_DELETE, &req);
}

int prestera_hw_lag_member_enable(struct prestera_port *port, u16 lag_id,
				  bool enable)
{
	u32 cmd;
	struct prestera_msg_lag_req req = {
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.lag_id = __cpu_to_le16(lag_id)
	};

	cmd = enable ? PRESTERA_CMD_TYPE_LAG_ENABLE :
			PRESTERA_CMD_TYPE_LAG_DISABLE;
	return fw_send_req(port->sw, cmd, &req);
}

int prestera_hw_lag_member_rif_leave(const struct prestera_port *port,
				     u16 lag_id, u16 vr_id)
{
	struct prestera_msg_lag_req req = {
		.port = __cpu_to_le32(port->hw_id),
		.dev = __cpu_to_le32(port->dev_id),
		.lag_id = __cpu_to_le16(lag_id),
		.vr_id = __cpu_to_le16(vr_id)
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_LAG_ROUTER_LEAVE, &req);
}

int
prestera_hw_cpu_code_counters_get(const struct prestera_switch *sw, u8 code,
				  enum prestera_hw_cpu_code_cnt_t counter_type,
				  u64 *packet_count)
{
	struct prestera_msg_cpu_code_counter_req req = {
		.counter_type = counter_type,
		.code = code,
	};
	struct prestera_msg_cpu_code_counter_resp resp;
	int err;

	err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_CPU_CODE_COUNTERS_GET,
			       &req, &resp);
	if (err)
		return err;

	*packet_count = __le64_to_cpu(resp.packet_count);

	return 0;
}

int prestera_hw_vtcam_create(const struct prestera_switch *sw,
			     u8 lookup, const u32 *keymask, u32 *vtcam_id,
			     u8 dir)
{
	int err;
	struct prestera_msg_vtcam_resp resp;
	struct prestera_msg_vtcam_create_req req = {
		.lookup = lookup,
		.direction = dir,
	};

	if (keymask)
		memcpy(req.keymask, keymask, sizeof(req.keymask));
	else
		memset(req.keymask, 0, sizeof(req.keymask));

	err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_VTCAM_CREATE, &req, &resp);
	if (err)
		return err;

	*vtcam_id = __le32_to_cpu(resp.vtcam_id);
	return 0;
}

int prestera_hw_vtcam_destroy(const struct prestera_switch *sw, u32 vtcam_id)
{
	struct prestera_msg_vtcam_destroy_req req = {
		.vtcam_id = __cpu_to_le32(vtcam_id),
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_VTCAM_DESTROY, &req);
}

int prestera_hw_vtcam_rule_add(const struct prestera_switch *sw,
			       u32 vtcam_id, u32 prio, void *key, void *keymask,
			       struct prestera_acl_hw_action_info *act,
			       u8 n_act, u32 *rule_id)
{
	struct prestera_msg_acl_action *actions_msg;
	struct prestera_msg_vtcam_rule_add_req *req;
	struct prestera_msg_vtcam_resp resp;
	void *buff;
	u32 size;
	int err;
	u8 i;

	size = sizeof(*req) + sizeof(*actions_msg) * n_act;

	buff = kzalloc(size, GFP_KERNEL);
	if (!buff)
		return -ENOMEM;

	req = buff;
	req->n_act = __cpu_to_le32((u32)n_act);
	actions_msg = buff + sizeof(*req);

	/* put acl matches into the message */
	memcpy(req->key, key, sizeof(req->key));
	memcpy(req->keymask, keymask, sizeof(req->keymask));

	/* put acl actions into the message */
	for (i = 0; i < n_act; i++) {
		err = acl_rule_add_put_action(&actions_msg[i], &act[i]);
		if (err)
			goto free_buff;
	}

	req->vtcam_id = __cpu_to_le32(vtcam_id);
	req->prio = __cpu_to_le32(prio);

	err = fw_send_nreq_resp(sw, PRESTERA_CMD_TYPE_VTCAM_RULE_ADD, req,
				size, &resp);
	if (err)
		goto free_buff;

	*rule_id = __le32_to_cpu(resp.rule_id);
free_buff:
	kfree(buff);
	return err;
}

int prestera_hw_vtcam_rule_del(const struct prestera_switch *sw,
			       u32 vtcam_id, u32 rule_id)
{
	struct prestera_msg_vtcam_rule_del_req req = {
		.vtcam_id = __cpu_to_le32(vtcam_id),
		.id = __cpu_to_le32(rule_id)
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_VTCAM_RULE_DELETE, &req);
}

int prestera_hw_vtcam_iface_bind(const struct prestera_switch *sw,
				 struct prestera_acl_iface *iface,
				 u32 vtcam_id, u16 pcl_id)
{
	struct prestera_msg_vtcam_bind_req req = {
		.vtcam_id = __cpu_to_le32(vtcam_id),
		.type = __cpu_to_le16(iface->type),
		.pcl_id = __cpu_to_le16(pcl_id)
	};

	if (iface->type == PRESTERA_ACL_IFACE_TYPE_PORT) {
		req.port.dev_id = __cpu_to_le32(iface->port->dev_id);
		req.port.hw_id = __cpu_to_le32(iface->port->hw_id);
	} else {
		req.index = __cpu_to_le32(iface->index);
	}

	return fw_send_req(sw, PRESTERA_CMD_TYPE_VTCAM_IFACE_BIND, &req);
}

int prestera_hw_vtcam_iface_unbind(const struct prestera_switch *sw,
				   struct prestera_acl_iface *iface,
				   u32 vtcam_id)
{
	struct prestera_msg_vtcam_bind_req req = {
		.vtcam_id = __cpu_to_le32(vtcam_id),
		.type = __cpu_to_le16(iface->type),
	};

	if (iface->type == PRESTERA_ACL_IFACE_TYPE_PORT) {
		req.port.dev_id = __cpu_to_le32(iface->port->dev_id);
		req.port.hw_id = __cpu_to_le32(iface->port->hw_id);
	} else {
		req.index = __cpu_to_le32(iface->index);
	}

	return fw_send_req(sw, PRESTERA_CMD_TYPE_VTCAM_IFACE_UNBIND, &req);
}

int prestera_hw_port_qos_mapping_update(const struct prestera_port *port,
					struct dcb_ieee_app_dscp_map *map)
{
	struct prestera_msg_qos_req req = {
		.port = port->hw_id,
		.dev = port->dev_id,
	};

	memcpy(req.dscp, map->map, sizeof(req.dscp));

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_QOS_DSCP_PRIO_MAP_UPDATE,
			   &req);
}

int prestera_hw_port_qos_trust_mode_set(const struct prestera_port *port,
					u8 mode)
{
	struct prestera_msg_qos_req req = {
		.port = port->hw_id,
		.dev = port->dev_id,
		.mode = mode,
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_QOS_TRUST_MODE_SET,
			   &req);
}

int prestera_hw_port_qos_default_prio_set(const struct prestera_port *port,
					  u32 priority)
{
	struct prestera_msg_qos_req req = {
		.port = port->hw_id,
		.dev = port->dev_id,
		.priority = priority,
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_QOS_DEFAULT_PRIO_SET,
			   &req);
}

int prestera_hw_switch_reset(struct prestera_switch *sw)
{
	struct prestera_msg_common_req req;

	return fw_send_req(sw, PRESTERA_CMD_TYPE_SWITCH_RESET, &req);
}

int prestera_hw_flood_domain_create(struct prestera_flood_domain *domain)
{
	struct prestera_msg_flood_domain_create_resp resp;
	struct prestera_msg_flood_domain_create_req req;
	int err;

	err = fw_send_req_resp(domain->sw,
			       PRESTERA_CMD_TYPE_FLOOD_DOMAIN_CREATE, &req,
			       &resp);
	if (err)
		return err;

	domain->idx = __le32_to_cpu(resp.flood_domain_idx);

	return 0;
}

int prestera_hw_flood_domain_destroy(struct prestera_flood_domain *domain)
{
	struct prestera_msg_flood_domain_destroy_req req = {
		.flood_domain_idx = __cpu_to_le32(domain->idx),
	};

	return fw_send_req(domain->sw, PRESTERA_CMD_TYPE_FLOOD_DOMAIN_DESTROY,
			   &req);
}

int prestera_hw_flood_domain_ports_set(struct prestera_flood_domain *domain)
{
	struct prestera_flood_domain_port *flood_domain_port;
	struct prestera_msg_flood_domain_ports_set_req *req;
	struct prestera_msg_flood_domain_port *ports;
	struct prestera_msg_common_resp resp = {0}; /* todo: generic macro to be used */
	struct prestera_switch *sw = domain->sw;
	struct prestera_port *port;
	u32 ports_num = 0;
	int buf_size;
	void *buff;
	u16 lag_id;
	int err;

	list_for_each_entry(flood_domain_port, &domain->flood_domain_port_list,
			    flood_domain_port_node)
		ports_num++;

	if (!ports_num)
		return -EINVAL;

	buf_size = sizeof(*req) + sizeof(*ports) * ports_num;

	buff = kmalloc(buf_size, GFP_KERNEL);
	if (!buff)
		return -ENOMEM;

	req = buff;
	ports = buff + sizeof(*req);

	req->flood_domain_idx = __cpu_to_le32(domain->idx);
	req->ports_num = __cpu_to_le32(ports_num);

	list_for_each_entry(flood_domain_port, &domain->flood_domain_port_list,
			    flood_domain_port_node) {
		if (netif_is_lag_master(flood_domain_port->dev)) {
			if (prestera_lag_id_find(sw, flood_domain_port->dev,
						 &lag_id)) {
				kfree(buff);
				return -EINVAL;
			}

			ports->port_type =
				__cpu_to_le16(PRESTERA_HW_FLOOD_DOMAIN_PORT_TYPE_LAG);
			ports->lag_id = __cpu_to_le16(lag_id);
		} else {
			port = prestera_port_dev_lower_find(flood_domain_port->dev);

			ports->port_type =
				__cpu_to_le16(PRESTERA_HW_FDB_ENTRY_TYPE_REG_PORT);
			ports->dev_num = __cpu_to_le32(port->dev_id);
			ports->port_num = __cpu_to_le32(port->hw_id);
		}

		ports->vid = __cpu_to_le16(flood_domain_port->vid);

		ports++;
	}

	err = fw_send_nreq_resp(sw, PRESTERA_CMD_TYPE_FLOOD_DOMAIN_PORTS_SET,
				req, buf_size, &resp);

	kfree(buff);

	return err;
}

int prestera_hw_flood_domain_ports_reset(struct prestera_flood_domain *domain)
{
	struct prestera_msg_flood_domain_ports_reset_req req = {
		.flood_domain_idx = __cpu_to_le32(domain->idx),
	};

	return fw_send_req(domain->sw,
			   PRESTERA_CMD_TYPE_FLOOD_DOMAIN_PORTS_RESET, &req);
}

int prestera_hw_mdb_create(struct prestera_mdb_entry *mdb)
{
	struct prestera_msg_mdb_create_req req = {
		.flood_domain_idx = __cpu_to_le32(mdb->flood_domain->idx),
		.vid = __cpu_to_le16(mdb->vid),
	};

	memcpy(req.mac, mdb->addr, ETH_ALEN);

	return fw_send_req(mdb->sw, PRESTERA_CMD_TYPE_MDB_CREATE, &req);
}

int prestera_hw_mdb_destroy(struct prestera_mdb_entry *mdb)
{
	struct prestera_msg_mdb_destroy_req req = {
		.flood_domain_idx = __cpu_to_le32(mdb->flood_domain->idx),
		.vid = __cpu_to_le16(mdb->vid),
	};

	memcpy(req.mac, mdb->addr, ETH_ALEN);

	return fw_send_req(mdb->sw, PRESTERA_CMD_TYPE_MDB_DESTROY, &req);
}

int prestera_hw_ipg_set(struct prestera_switch *sw, u32 ipg)
{
	struct prestera_msg_ipg_set_req req = {
		.ipg = ipg,
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_IPG_SET, &req);
}

int prestera_hw_ipg_get(struct prestera_switch *sw, u32 *ipg)
{
	struct prestera_msg_ipg_get_resp resp;
	struct prestera_msg_common_req req;
	int err;

	err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_IPG_GET, &req, &resp);
	if (err)
		return err;

	*ipg = resp.ipg;

	return 0;
}

int prestera_hw_sched_create(const struct prestera_switch *sw, u32 *sched_id)
{
	struct prestera_msg_sched_resp resp;
	struct prestera_msg_common_req req = {};
	int err;

	err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_SCHED_CREATE, &req, &resp);
	if (err)
		return err;

	*sched_id = __le32_to_cpu(resp.id);
	return 0;
}

int prestera_hw_sched_release(const struct prestera_switch *sw, u32 sched_id)
{
	struct prestera_msg_sched_req req = {
		.id = __cpu_to_le32(sched_id)
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_SCHED_RELEASE, &req);
}

int prestera_hw_sched_sdwrr_set(const struct prestera_port *port,
				u8 tc, u32 sched_id, u32 weight)
{
	struct prestera_msg_sched_attr_req req = {
		.type = PRESTERA_HW_SCHED_SDWRR,
		.sdwrr = {
			.weight = __cpu_to_le32(weight)
		},
		.dev = __cpu_to_le32(port->dev_id),
		.port = __cpu_to_le32(port->hw_id),
		.id = __cpu_to_le32(sched_id),
		.tc = tc
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_SCHED_SET, &req);
}

int prestera_hw_sched_sp_set(const struct prestera_port *port,
			     u8 tc, u32 sched_id)
{
	struct prestera_msg_sched_attr_req req = {
		.type = PRESTERA_HW_SCHED_SP,
		.dev = __cpu_to_le32(port->dev_id),
		.port = __cpu_to_le32(port->hw_id),
		.id = __cpu_to_le32(sched_id),
		.tc = tc
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_SCHED_SET, &req);
}

int prestera_hw_sched_port_set(const struct prestera_port *port, u32 sched_id)
{
	struct prestera_msg_sched_req req = {
		.dev = __cpu_to_le32(port->dev_id),
		.port = __cpu_to_le32(port->hw_id),
		.id = __cpu_to_le32(sched_id)
	};

	return fw_send_req(port->sw, PRESTERA_CMD_TYPE_SCHED_PORT_SET, &req);
}

int prestera_hw_sched_port_get(const struct prestera_port *port, u32 *sched_id)
{
	struct prestera_msg_sched_resp resp;
	struct prestera_msg_sched_req req = {
		.dev = __cpu_to_le32(port->dev_id),
		.port = __cpu_to_le32(port->hw_id),
	};
	int err;

	err = fw_send_req_resp(port->sw, PRESTERA_CMD_TYPE_SCHED_PORT_GET, &req, &resp);
	if (err)
		return err;

	*sched_id = __le32_to_cpu(resp.id);
	return 0;
}

int prestera_hw_shaper_port_queue_configure(const struct prestera_port *port,
					    u32 tc, u32 rate, u32 burst)
{
	struct prestera_msg_shaper_req req = {
		.port = port->hw_id,
		.dev = port->dev_id,
		.rate = rate,
		.burst = burst,
		.tc = tc,
	};

	return fw_send_req(port->sw,
			   PRESTERA_CMD_TYPE_SHAPER_PORT_QUEUE_CONFIGURE, &req);
}

int prestera_hw_shaper_port_queue_disable(const struct prestera_port *port,
					  u32 tc)
{
	struct prestera_msg_shaper_req req = {
		.port = port->hw_id,
		.dev = port->dev_id,
		.tc = tc,
	};

	return fw_send_req(port->sw,
			   PRESTERA_CMD_TYPE_SHAPER_PORT_QUEUE_DISABLE, &req);
}

int prestera_hw_port_queue_stats_get(const struct prestera_port *port,
				     u8 tc, u64 *pkts, u64 *bytes,
				     u64 *drops)
{
	struct prestera_msg_shaper_stats_resp resp;
	struct prestera_msg_shaper_req req = {
		.port = port->hw_id,
		.dev = port->dev_id,
		.tc = tc,
	};
	int err;

	err = fw_send_req_resp(port->sw, PRESTERA_CMD_TYPE_PORT_QUEUE_STATS_GET,
			       &req, &resp);
	if (err)
		return err;

	*pkts = resp.pkts;
	*bytes = resp.bytes;
	*drops = resp.drops;

	return 0;
}

int prestera_hw_wred_port_queue_enable(const struct prestera_port *port,
				       u32 tc, u32 min, u32 max, u32 prob)
{
	struct prestera_msg_wred_req req = {
		.port = port->hw_id,
		.dev = port->dev_id,
		.tc = tc,
		.min = min,
		.max = max,
		.prob = prob,
	};

	return fw_send_req(port->sw,
			   PRESTERA_CMD_TYPE_WRED_PORT_QUEUE_ENABLE,
			   &req);
}

int prestera_hw_wred_port_queue_disable(const struct prestera_port *port,
					u32 tc)
{
	struct prestera_msg_wred_req req = {
		.port = port->hw_id,
		.dev = port->dev_id,
		.tc = tc,
	};

	return fw_send_req(port->sw,
			   PRESTERA_CMD_TYPE_WRED_PORT_QUEUE_DISABLE,
			   &req);
}

int
prestera_hw_sct_ratelimit_set(const struct prestera_switch *sw, u8 group,
			      u32 rate)
{
	struct prestera_msg_sct_ratelimit_set_req req = {
		.group = group,
		.rate_pps = rate,
	};

	return fw_send_req(sw, PRESTERA_CMD_TYPE_SWITCH_SCT_RATELIMIT_SET,
			   &req);
}

int
prestera_hw_sct_ratelimit_get(const struct prestera_switch *sw, u8 group,
			      u32 *rate)
{
	struct prestera_msg_sct_ratelimit_get_req req = {
		.group = group,
	};
	struct prestera_msg_sct_ratelimit_get_resp resp;
	int err;

	err = fw_send_req_resp(sw, PRESTERA_CMD_TYPE_SWITCH_SCT_RATELIMIT_GET,
			       &req, &resp);
	if (err)
		return err;

	*rate = resp.rate_pps;

	return 0;
}

