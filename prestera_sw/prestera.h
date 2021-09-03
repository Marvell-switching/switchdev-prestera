/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved. */

#ifndef _PRESTERA_H_
#define _PRESTERA_H_

#include <linux/skbuff.h>
#include <linux/notifier.h>
#include <uapi/linux/if_ether.h>
#include <linux/if_macvlan.h>
#include <linux/workqueue.h>
#include <linux/phylink.h>
#include <net/pkt_cls.h>
#include <net/devlink.h>

#define PRESTERA_DRV_NAME       "prestera"

#define PRESTERA_MSG_MAX_SIZE 1500
#define PRESTERA_MSG_CHUNK_SIZE 1024

#define PRESTERA_DEFAULT_VID 1

#define PRESTERA_MIN_AGEING_TIME 32000
#define PRESTERA_MAX_AGEING_TIME 1000000000
#define PRESTERA_DEFAULT_AGEING_TIME 300000

#define PRESTERA_NHGR_SIZE_MAX 4

#define PRESTERA_PORT_SRCID_ZERO 0 /* source_id */

#define PRESTERA_SPAN_INVALID_ID -1

struct prestera_fw_rev {
	u16 maj;
	u16 min;
	u16 sub;
};

struct prestera_bridge_port;
struct prestera_kern_neigh_cache;
struct prestera_acl;
struct prestera_acl_rule;
struct prestera_acl_ruleset;
struct prestera_acl_nat_port;
struct prestera_span;
struct prestera_span_entry;
struct prestera_storm_control;

struct prestera_flow_block_binding {
	struct list_head list;
	struct prestera_port *port;
	int span_id;
};

struct prestera_flow_block {
	struct list_head binding_list;
	struct list_head template_list;
	struct prestera_switch *sw;
	unsigned int rule_count;
	unsigned int disable_count;
	struct net *net;
	struct prestera_acl_ruleset *ruleset_zero;
	struct flow_block_cb *block_cb;
	u32 mall_prio;
	u32 flower_min_prio;
};

struct prestera_port_vlan {
	struct list_head list;
	struct prestera_port *mvsw_pr_port;
	u16 vid;
	struct prestera_bridge_port *bridge_port;
	struct list_head bridge_vlan_node;
};

struct prestera_port_stats {
	u64 good_octets_received;
	u64 bad_octets_received;
	u64 mac_trans_error;
	u64 broadcast_frames_received;
	u64 multicast_frames_received;
	u64 frames_64_octets;
	u64 frames_65_to_127_octets;
	u64 frames_128_to_255_octets;
	u64 frames_256_to_511_octets;
	u64 frames_512_to_1023_octets;
	u64 frames_1024_to_max_octets;
	u64 excessive_collision;
	u64 multicast_frames_sent;
	u64 broadcast_frames_sent;
	u64 fc_sent;
	u64 fc_received;
	u64 buffer_overrun;
	u64 undersize;
	u64 fragments;
	u64 oversize;
	u64 jabber;
	u64 rx_error_frame_received;
	u64 bad_crc;
	u64 collisions;
	u64 late_collision;
	u64 unicast_frames_received;
	u64 unicast_frames_sent;
	u64 sent_multiple;
	u64 sent_deferred;
	u64 good_octets_sent;
};

struct prestera_port_caps {
	u64 supp_link_modes;
	u8 supp_fec;
	u8 type;
	u8 transceiver;
};

struct prestera_port_link_params {
	u64 lmode_bmap;
	u32 speed;
	u8 duplex;
	bool oper_state;
	struct {
		bool pause;
		bool asym_pause;
	} remote_fc;
	struct {
		u8 status;
		u8 admin_mode;
	} mdix;
};

struct prestera_rxtx_stats {
	u64 rx_packets;
	u64 rx_bytes;
	u64 tx_packets;
	u64 tx_bytes;
	u32 tx_dropped;
	struct u64_stats_sync syncp;
};

/* used for hw call */
struct prestera_port_mac_config {
	bool admin;
	u32 mode;
	u8 inband;
	u32 speed;
	u8 duplex;
	u8 fec;
};

/* TODO: add another paramters here: modes, etc... */
struct prestera_port_phy_config {
	bool admin;
	u32 mode;
};

struct prestera_port {
	struct devlink_port dl_port;
	struct net_device *net_dev;
	struct prestera_switch *sw;
	u32 id;
	u32 hw_id;
	u32 dev_id;
	u16 fp_id;
	u16 pvid;
	bool autoneg;
	u64 adver_link_modes;
	u8 adver_fec;
	u16 lag_id;
	struct prestera_port_caps caps;
	struct prestera_port_mac_config cfg_mac;
	struct prestera_port_phy_config cfg_phy;
	struct list_head list;
	struct list_head vlans_list;
	struct {
		struct prestera_port_stats stats;
		struct delayed_work caching_dw;
	} cached_hw_stats;
	struct prestera_flow_block *flow_block;

	struct phylink_config phy_config;
	struct phylink *phy_link;

	struct prestera_port_link_params link_params;

	struct prestera_rxtx_stats __percpu *rxtx_stats;
};

struct prestera_switchdev {
	struct prestera_switch *sw;
	struct notifier_block swdev_n;
	struct notifier_block swdev_blocking_n;
};

struct prestera_fib {
	struct prestera_switch *sw;
	struct notifier_block fib_nb;
	struct notifier_block netevent_nb;
};

struct prestera_device {
	struct device *dev;
	struct prestera_fw_rev fw_rev;
	struct workqueue_struct *dev_wq;
	u8 __iomem *pp_regs;
	void *priv;

	struct delayed_work keepalive_wdog_work;
	atomic_t keepalive_wdog_counter;
	bool running;

	/* called by device driver to handle received packets */
	void (*recv_pkt)(struct prestera_device *dev);

	/* called by device driver to pass event up to the higher layer */
	int (*recv_msg)(struct prestera_device *dev, u8 *msg, size_t size);

	/* called by higher layer to send request to the firmware */
	int (*send_req)(struct prestera_device *dev, int qid,
			u8 *in_msg, size_t in_size,
			u8 *out_msg, size_t out_size,
			unsigned int wait);
};

enum prestera_event_type {
	MVSW_EVENT_TYPE_UNSPEC,
	MVSW_EVENT_TYPE_PORT,
	MVSW_EVENT_TYPE_FDB,
	MVSW_EVENT_TYPE_RXTX,
	MVSW_EVENT_TYPE_FW_LOG,
	MVSW_EVENT_TYPE_PULSE,

	MVSW_EVENT_TYPE_MAX,
};

enum prestera_rxtx_event_id {
	MVSW_RXTX_EVENT_UNSPEC,

	MVSW_RXTX_EVENT_RCV_PKT,

	MVSW_RXTX_EVENT_MAX,
};

enum prestera_port_event_id {
	MVSW_PORT_EVENT_UNSPEC,
	MVSW_PORT_EVENT_STATE_CHANGED,

	MVSW_PORT_EVENT_MAX,
};

enum prestera_fdb_event_id {
	MVSW_FDB_EVENT_UNSPEC,
	MVSW_FDB_EVENT_LEARNED,
	MVSW_FDB_EVENT_AGED,

	MVSW_FDB_EVENT_MAX,
};

enum prestera_fdb_entry_type {
	MVSW_PR_FDB_ENTRY_TYPE_REG_PORT,
	MVSW_PR_FDB_ENTRY_TYPE_LAG,
	MVSW_PR_FDB_ENTRY_TYPE_MAX
};

struct prestera_fdb_event {
	enum prestera_fdb_entry_type type;
	union {
		u32 port_id;
		u16 lag_id;
	} dest;
	u32 vid;
	union {
		u8 mac[ETH_ALEN];
	} data;
};

struct prestera_port_event {
	u32 port_id;
	struct {
		u64 lmode_bmap;
		u32 link_mode;
		u8 oper_state;
		bool pause;
		bool asym_pause;
		u8 status;
		u8 admin_mode;
	} data;
};

struct prestera_fw_log_event {
	u32 log_len;
	u8 *data;
};

struct prestera_event {
	u16 id;
	union {
		struct prestera_port_event port_evt;
		struct prestera_fdb_event fdb_evt;
		struct prestera_fw_log_event fw_log_evt;
	};
};

struct prestera_lag_member {
	struct list_head list;
	struct prestera_port *port;
};

struct prestera_lag {
	struct net_device *dev;
	u16 member_count;
	struct list_head members;
};

enum prestera_if_type {
	/* the interface is of port type (dev,port) */
	MVSW_IF_PORT_E = 0,

	/* the interface is of lag type (lag-id) */
	MVSW_IF_LAG_E = 1,

	/* the interface is of Vid type (vlan-id) */
	MVSW_IF_VID_E = 3,
};

struct prestera_iface {
	enum prestera_if_type type;
	struct {
		u32 hw_dev_num;
		u32 port_num;
	} dev_port;
	u16 vr_id;
	u16 lag_id;
	u16 vlan_id;
	u32 hw_dev_num;
};

struct prestera_bridge;
struct prestera_router;
struct prestera_rif;
struct prestera_trap_data;
struct prestera_rxtx;

struct prestera_switch {
	struct list_head list;
	struct prestera_device *dev;
	struct list_head event_handlers;
	char base_mac[ETH_ALEN];
	struct list_head port_list;
	u32 port_count;
	u32 mtu_min;
	u32 mtu_max;
	u8 id;
	u8 lag_max;
	u8 lag_member_max;
	u32 size_tbl_router_nexthop;
	struct prestera_storm_control *storm_control;
	struct prestera_acl *acl;
	struct prestera_span *span;
	struct prestera_bridge *bridge;
	struct prestera_switchdev *switchdev;
	struct prestera_router *router;
	struct prestera_lag *lags;
	struct notifier_block netdevice_nb;
	struct device_node *np;
	struct prestera_trap_data *trap_data;
	struct prestera_rxtx *rxtx;
	struct prestera_counter *counter;
};

struct prestera_router {
	struct prestera_switch *sw;
	struct list_head rif_list;	/* list of mvsw_pr_rif */
	struct list_head vr_list;	/* list of mvsw_pr_vr */
	struct rhashtable nh_neigh_ht;
	struct rhashtable nexthop_group_ht;
	struct rhashtable fib_ht;
	struct rhashtable kern_fib_cache_ht;
	struct rhashtable kern_neigh_cache_ht;
	u8 *nhgrp_hw_state_cache; /* Bitmap cached hw state of nhs */
	unsigned long nhgrp_hw_cache_kick; /* jiffies */
	struct {
		struct delayed_work dw;
		unsigned int interval;	/* ms */
	} neighs_update;
	struct notifier_block netevent_nb;
	struct notifier_block inetaddr_nb;
	struct notifier_block fib_nb;
	bool aborted;
};

enum prestera_fdb_flush_mode {
	MVSW_PR_FDB_FLUSH_MODE_DYNAMIC = BIT(0),
	MVSW_PR_FDB_FLUSH_MODE_STATIC = BIT(1),
	MVSW_PR_FDB_FLUSH_MODE_ALL = MVSW_PR_FDB_FLUSH_MODE_DYNAMIC
				   | MVSW_PR_FDB_FLUSH_MODE_STATIC,
};

struct prestera_ip_addr {
	enum {
		MVSW_PR_IPV4 = 0,
		MVSW_PR_IPV6
	} v;
	union {
		__be32 ipv4;
		struct in6_addr ipv6;
	} u;
};

/* Used for hw call */
struct prestera_neigh_info {
	struct prestera_iface iface;
	unsigned char ha[ETH_ALEN];
	bool connected; /* indicate, if mac/oif valid */
};

enum prestera_acl_match_type {
	PRESTERA_ACL_RULE_MATCH_TYPE_PCL_ID,
	PRESTERA_ACL_RULE_MATCH_TYPE_ETH_TYPE,
	PRESTERA_ACL_RULE_MATCH_TYPE_ETH_DMAC_0,
	PRESTERA_ACL_RULE_MATCH_TYPE_ETH_DMAC_1,
	PRESTERA_ACL_RULE_MATCH_TYPE_ETH_SMAC_0,
	PRESTERA_ACL_RULE_MATCH_TYPE_ETH_SMAC_1,
	PRESTERA_ACL_RULE_MATCH_TYPE_IP_PROTO,
	PRESTERA_ACL_RULE_MATCH_TYPE_SYS_PORT,
	PRESTERA_ACL_RULE_MATCH_TYPE_SYS_DEV,
	PRESTERA_ACL_RULE_MATCH_TYPE_IP_SRC,
	PRESTERA_ACL_RULE_MATCH_TYPE_IP_DST,
	PRESTERA_ACL_RULE_MATCH_TYPE_L4_PORT_SRC,
	PRESTERA_ACL_RULE_MATCH_TYPE_L4_PORT_DST,
	PRESTERA_ACL_RULE_MATCH_TYPE_L4_PORT_RANGE_SRC,
	PRESTERA_ACL_RULE_MATCH_TYPE_L4_PORT_RANGE_DST,
	PRESTERA_ACL_RULE_MATCH_TYPE_VLAN_ID,
	PRESTERA_ACL_RULE_MATCH_TYPE_VLAN_TPID,
	PRESTERA_ACL_RULE_MATCH_TYPE_ICMP_TYPE,
	PRESTERA_ACL_RULE_MATCH_TYPE_ICMP_CODE,

	__PRESTERA_ACL_RULE_MATCH_TYPE_MAX
};

struct prestera_acl_match {
	__be32 key[__PRESTERA_ACL_RULE_MATCH_TYPE_MAX];
	__be32 mask[__PRESTERA_ACL_RULE_MATCH_TYPE_MAX];
};

enum prestera_acl_rule_action {
	MVSW_ACL_RULE_ACTION_ACCEPT,
	MVSW_ACL_RULE_ACTION_DROP,
	MVSW_ACL_RULE_ACTION_TRAP,
	MVSW_ACL_RULE_ACTION_POLICE,
	MVSW_ACL_RULE_ACTION_NAT,
	MVSW_ACL_RULE_ACTION_JUMP,
	MVSW_ACL_RULE_ACTION_NH,
	MVSW_ACL_RULE_ACTION_COUNT
};

struct prestera_acl_action_jump {
	u32 index;
};

struct prestera_acl_action_trap {
	u8 hw_tc;
};

struct prestera_acl_action_police {
	u64 rate;
	u64 burst;
};

struct prestera_acl_action_nat {
	__be32 old_addr;
	__be32 new_addr;
	u32 port;
	u32 dev;
	u32 flags;
};

struct prestera_acl_action_count {
	u32 id;
};

/* Used for hw call */
struct prestera_acl_hw_action_info {
	enum prestera_acl_rule_action id;
	union {
		struct prestera_acl_action_trap trap;
		struct prestera_acl_action_police police;
		u32 nh;
		struct prestera_acl_action_nat nat;
		struct prestera_acl_action_jump jump;
		struct prestera_acl_action_count count;
	};
};

struct prestera_fib_key {
	struct prestera_ip_addr addr;
	u32 prefix_len;
	u32 tb_id;
};

struct prestera_fib_info {
	struct mvsw_pr_vr *vr;
	struct list_head vr_node;
	enum mvsw_pr_fib_type {
		MVSW_PR_FIB_TYPE_INVALID = 0,
		/* must be pointer to nh_grp id */
		MVSW_PR_FIB_TYPE_UC_NH,
		/* It can be connected route
		 * and will be overlapped with neighbours
		 */
		MVSW_PR_FIB_TYPE_TRAP,
		MVSW_PR_FIB_TYPE_DROP
	} type;
	/* Valid only if type = UC_NH*/
	struct mvsw_pr_nexthop_group *nh_grp;
};

struct prestera_nh_neigh_key {
	struct prestera_ip_addr addr;
	struct prestera_rif *rif;
};

/* Used to notify nh about neigh change */
struct prestera_nh_neigh {
	struct prestera_nh_neigh_key key;
	struct prestera_neigh_info info;
	struct rhash_head ht_node; /* node of mvsw_pr_vr */
	struct list_head nexthop_group_list;
	struct list_head nh_mangle_entry_list;
};

struct prestera_nexthop_group_key {
	struct prestera_nh_neigh_key neigh[PRESTERA_NHGR_SIZE_MAX];
};

struct prestera_port *dev_to_prestera_port(struct device *dev);

int prestera_switch_ageing_set(struct prestera_switch *sw, u32 ageing_time);

struct prestera_port *prestera_port_find_by_fp_id(u32 fp_id);

int prestera_port_learning_set(struct prestera_port *port, bool learn_enable);
int prestera_port_uc_flood_set(struct prestera_port *port, bool flood);
int prestera_port_mc_flood_set(struct prestera_port *port, bool flood);
int prestera_port_isolation_grp_set(struct prestera_port *port,
				    u32 sourceid);
int prestera_port_pvid_set(struct prestera_port *port, u16 vid);
int prestera_port_vid_stp_set(struct prestera_port *port, u16 vid, u8 state);
struct prestera_port_vlan *
prestera_port_vlan_create(struct prestera_port *port, u16 vid, bool untagged);
void prestera_port_vlan_destroy(struct prestera_port_vlan *mvsw_pr_port_vlan);
int prestera_port_vlan_set(struct prestera_port *port, u16 vid,
			   bool is_member, bool untagged);

struct prestera_bridge_device *
prestera_bridge_device_find(const struct prestera_bridge *bridge,
			    const struct net_device *br_dev);
u16 prestera_vlan_dev_vlan_id(struct prestera_bridge *bridge,
			      struct net_device *dev);
int prestera_8021d_bridge_create(struct prestera_switch *sw, u16 *bridge_id);
int prestera_8021d_bridge_delete(struct prestera_switch *sw, u16 bridge_id);
int prestera_8021d_bridge_port_add(struct prestera_port *port, u16 bridge_id);
int prestera_8021d_bridge_port_delete(struct prestera_port *port,
				      u16 bridge_id);

int prestera_fdb_add(struct prestera_port *port, const unsigned char *mac,
		     u16 vid, bool dynamic);
int prestera_fdb_del(struct prestera_port *port, const unsigned char *mac,
		     u16 vid);
int prestera_fdb_flush_vlan(struct prestera_switch *sw, u16 vid,
			    enum prestera_fdb_flush_mode mode);
int prestera_fdb_flush_port_vlan(struct prestera_port *port, u16 vid,
				 enum prestera_fdb_flush_mode mode);
int prestera_fdb_flush_port(struct prestera_port *port,
			    enum prestera_fdb_flush_mode mode);
int prestera_macvlan_add(const struct prestera_switch *sw, u16 vr_id,
			 const u8 *mac, u16 vid);
int prestera_macvlan_del(const struct prestera_switch *sw, u16 vr_id,
			 const u8 *mac, u16 vid);

int prestera_lag_member_add(struct prestera_port *port,
			    struct net_device *lag_dev, u16 lag_id);
int prestera_lag_member_del(struct prestera_port *port);
int prestera_lag_member_enable(struct prestera_port *port, bool enable);
bool prestera_port_is_lag_member(const struct prestera_port *port);
struct prestera_lag *prestera_lag_get(struct prestera_switch *sw, u8 id);
int prestera_lag_id_find(struct prestera_switch *sw, struct net_device *lag_dev,
			 u16 *lag_id);
void prestera_lag_member_rif_leave(const struct prestera_port *port,
				   u16 lag_id, u16 vr_id);

/* SPAN */
int prestera_span_get(struct prestera_port *port, u8 *span_id);
int prestera_span_put(const struct prestera_switch *sw, u8 span_id);

int prestera_dev_if_type(const struct net_device *dev);

/* prestera_flower.c */
int prestera_flower_replace(struct prestera_switch *sw,
			    struct prestera_flow_block *block,
			    struct flow_cls_offload *f);
void prestera_flower_destroy(struct prestera_switch *sw,
			     struct prestera_flow_block *block,
			     struct flow_cls_offload *f);
int prestera_flower_stats(struct prestera_switch *sw,
			  struct prestera_flow_block *block,
			  struct flow_cls_offload *f);
int prestera_flower_prio_get(struct prestera_flow_block *block,
			     u32 *prio);
int prestera_flower_tmplt_create(struct prestera_switch *sw,
				 struct prestera_flow_block *block,
				 struct flow_cls_offload *f);
void prestera_flower_tmplt_destroy(struct prestera_switch *sw,
				   struct prestera_flow_block *block,
				   struct flow_cls_offload *f);
void prestera_flower_template_cleanup(struct prestera_flow_block *block);

/* prestera_matchall.c */
int prestera_mall_replace(struct prestera_flow_block *block,
			  struct tc_cls_matchall_offload *f);
void prestera_mall_destroy(struct prestera_flow_block *block);
int prestera_mall_prio_get(struct prestera_flow_block *block,
			   u32 *prio);

/* prestera_flow.c */
int prestera_setup_tc_block(struct prestera_port *port,
			    struct flow_block_offload *f);

/* prestera_acl.c */
int prestera_acl_init(struct prestera_switch *sw);
void prestera_acl_fini(struct prestera_switch *sw);
struct net *prestera_acl_block_net(struct prestera_flow_block *block);
struct prestera_switch *
prestera_acl_block_sw(struct prestera_flow_block *block);
unsigned int prestera_acl_block_rule_count(struct prestera_flow_block *block);
void prestera_acl_block_disable_inc(struct prestera_flow_block *block);
void prestera_acl_block_disable_dec(struct prestera_flow_block *block);
bool prestera_acl_block_disabled(const struct prestera_flow_block *block);
void prestera_acl_block_prio_update(struct prestera_switch *sw,
				    struct prestera_flow_block *block);

/* ACL-NAT */
struct prestera_acl_nat_port *
prestera_acl_nat_port_get(struct prestera_acl *acl, u32 port_hw_id,
			  u32 port_dev_id);
void prestera_acl_nat_port_put(struct prestera_acl_nat_port *nat_port);
struct prestera_port *
prestera_acl_nat_port_to_port(struct prestera_acl_nat_port *nat_port);

/* VLAN API */
struct prestera_port_vlan *
prestera_port_vlan_find_by_vid(const struct prestera_port *port, u16 vid);
void
prestera_port_vlan_bridge_leave(struct prestera_port_vlan *mvsw_pr_port_vlan);

int prestera_switchdev_register(struct prestera_switch *sw);
void prestera_switchdev_unregister(struct prestera_switch *sw);

int prestera_device_register(struct prestera_device *dev);
void prestera_device_unregister(struct prestera_device *dev);

bool prestera_netdev_check(const struct net_device *dev);
struct prestera_switch *prestera_switch_get(struct net_device *dev);
int prestera_port_cfg_mac_read(struct prestera_port *port,
			       struct prestera_port_mac_config *cfg);
int prestera_port_cfg_mac_write(struct prestera_port *port,
				struct prestera_port_mac_config *cfg);
struct prestera_port *prestera_port_dev_lower_find(struct net_device *dev);

struct prestera_port *prestera_port_find(u32 dev_hw_id, u32 port_hw_id);

int prestera_port_autoneg_set(struct prestera_port *port, u64 link_modes);

/* prestera_router.c */
int prestera_router_init(struct prestera_switch *sw);
void prestera_router_fini(struct prestera_switch *sw);
int prestera_netdevice_router_port_event(struct net_device *dev,
					 unsigned long event, void *ptr);
int prestera_inetaddr_valid_event(struct notifier_block *unused,
				  unsigned long event, void *ptr);
int prestera_netdevice_vrf_event(struct net_device *dev, unsigned long event,
				 struct netdev_notifier_changeupper_info *info);
void prestera_port_router_leave(struct prestera_port *port);
int prestera_lpm_add(struct prestera_switch *sw, u16 hw_vr_id,
		     struct prestera_ip_addr *addr, u32 prefix_len, u32 grp_id);
int prestera_lpm_del(struct prestera_switch *sw, u16 hw_vr_id,
		     struct prestera_ip_addr *addr, u32 prefix_len);
int prestera_nh_entries_set(const struct prestera_switch *sw, int count,
			    struct prestera_neigh_info *nhs, u32 grp_id);
int prestera_nh_entries_get(const struct prestera_switch *sw, int count,
			    struct prestera_neigh_info *nhs, u32 grp_id);
int prestera_nhgrp_blk_get(const struct prestera_switch *sw, u8 *hw_state,
			   u32 buf_size);
int prestera_nh_group_create(const struct prestera_switch *sw, u16 nh_count,
			     u32 *grp_id);
int prestera_nh_group_delete(const struct prestera_switch *sw, u16 nh_count,
			     u32 grp_id);
int prestera_mp4_hash_set(const struct prestera_switch *sw, u8 hash_policy);

struct prestera_nh_neigh *
prestera_nh_neigh_find(struct prestera_switch *sw,
		       struct prestera_nh_neigh_key *key);
struct prestera_nh_neigh *
prestera_nh_neigh_get(struct prestera_switch *sw,
		      struct prestera_nh_neigh_key *key);
void prestera_nh_neigh_put(struct prestera_switch *sw,
			   struct prestera_nh_neigh *neigh);
int prestera_util_kern_dip2nh_grp_key(struct prestera_switch *sw,
				      u32 tb_id, struct prestera_ip_addr *addr,
				      struct prestera_nexthop_group_key *res);
void prestera_rif_enable(struct prestera_switch *sw, struct net_device *dev,
			 bool enable);
bool prestera_rif_exists(const struct prestera_switch *sw,
			 const struct net_device *dev);
void prestera_router_lag_member_leave(const struct prestera_port *port,
				      const struct net_device *dev);
void prestera_lag_router_leave(struct prestera_switch *sw,
			       struct net_device *lag_dev);

void prestera_bridge_device_rifs_destroy(struct prestera_switch *sw,
					 struct net_device *bridge_dev);
void prestera_k_arb_fdb_evt(struct prestera_switch *sw, struct net_device *dev);
struct prestera_neigh_info *
prestera_kern_neigh_cache_to_neigh_info(struct prestera_kern_neigh_cache *nc);

#endif /* _PRESTERA_H_ */
