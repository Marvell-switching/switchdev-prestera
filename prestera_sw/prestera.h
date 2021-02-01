/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 *
 * Copyright (c) 2019-2020 Marvell International Ltd. All rights reserved.
 *
 */

#ifndef _MVSW_PRESTERA_H_
#define _MVSW_PRESTERA_H_

#include <linux/skbuff.h>
#include <linux/notifier.h>
#include <uapi/linux/if_ether.h>
#include <linux/if_macvlan.h>
#include <linux/workqueue.h>
#include <linux/phylink.h>
#include <net/pkt_cls.h>
#include <net/devlink.h>

#define PRESTERA_DRV_NAME       "prestera"

#define MVSW_MSG_MAX_SIZE 1500

#define MVSW_PR_DEFAULT_VID 1

#define MVSW_PR_MIN_AGEING_TIME 32000
#define MVSW_PR_MAX_AGEING_TIME 1000000000
#define MVSW_PR_DEFAULT_AGEING_TIME 300000

#define MVSW_PR_NHGR_SIZE_MAX 4

struct prestera_fw_rev {
	u16 maj;
	u16 min;
	u16 sub;
};

struct mvsw_pr_bridge_port;
struct prestera_acl;
struct prestera_acl_block;
struct prestera_acl_rule;
struct prestera_acl_ruleset;

struct mvsw_pr_port_vlan {
	struct list_head list;
	struct mvsw_pr_port *mvsw_pr_port;
	u16 vid;
	struct mvsw_pr_bridge_port *bridge_port;
	struct list_head bridge_vlan_node;
};

struct mvsw_pr_port_stats {
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

struct mvsw_pr_port_caps {
	u64 supp_link_modes;
	u8 supp_fec;
	u8 type;
	u8 transceiver;
};

struct mvsw_pr_port {
	struct devlink_port dl_port;
	struct net_device *net_dev;
	struct mvsw_pr_switch *sw;
	u32 id;
	u32 hw_id;
	u32 dev_id;
	u16 fp_id;
	u16 pvid;
	bool autoneg;
	bool hw_oper_state; /* RS (PCS) */
	u32 hw_speed;
	u8 hw_duplex;
	u64 adver_link_modes;
	u8 adver_fec;
	u16 lag_id;
	struct mvsw_pr_port_caps caps;
	struct list_head list;
	struct list_head vlans_list;
	struct {
		struct mvsw_pr_port_stats stats;
		struct delayed_work caching_dw;
	} cached_hw_stats;
	struct prestera_acl_block *acl_block;

	struct phylink_config phy_config;
	struct phylink *phy_link;
};

struct prestera_switchdev {
	struct mvsw_pr_switch *sw;
	struct notifier_block swdev_n;
	struct notifier_block swdev_blocking_n;
};

struct mvsw_pr_fib {
	struct mvsw_pr_switch *sw;
	struct notifier_block fib_nb;
	struct notifier_block netevent_nb;
};

struct prestera_device {
	struct device *dev;
	struct prestera_fw_rev fw_rev;
	struct workqueue_struct *dev_wq;
	u8 __iomem *pp_regs;
	void *priv;

	/* called by device driver to handle received packets */
	void (*recv_pkt)(struct prestera_device *dev);

	/* called by device driver to pass event up to the higher layer */
	int (*recv_msg)(struct prestera_device *dev, u8 *msg, size_t size);

	/* called by higher layer to send request to the firmware */
	int (*send_req)(struct prestera_device *dev, u8 *in_msg,
			size_t in_size, u8 *out_msg, size_t out_size,
			unsigned int wait);
};

enum mvsw_pr_event_type {
	MVSW_EVENT_TYPE_UNSPEC,
	MVSW_EVENT_TYPE_PORT,
	MVSW_EVENT_TYPE_FDB,
	MVSW_EVENT_TYPE_RXTX,
	MVSW_EVENT_TYPE_FW_LOG,

	MVSW_EVENT_TYPE_MAX,
};

enum mvsw_pr_rxtx_event_id {
	MVSW_RXTX_EVENT_UNSPEC,

	MVSW_RXTX_EVENT_RCV_PKT,

	MVSW_RXTX_EVENT_MAX,
};

enum mvsw_pr_port_event_id {
	MVSW_PORT_EVENT_UNSPEC,
	MVSW_PORT_EVENT_STATE_CHANGED,

	MVSW_PORT_EVENT_MAX,
};

enum mvsw_pr_fdb_event_id {
	MVSW_FDB_EVENT_UNSPEC,
	MVSW_FDB_EVENT_LEARNED,
	MVSW_FDB_EVENT_AGED,

	MVSW_FDB_EVENT_MAX,
};

enum mvsw_pr_fdb_entry_type {
	MVSW_PR_FDB_ENTRY_TYPE_REG_PORT,
	MVSW_PR_FDB_ENTRY_TYPE_LAG,
	MVSW_PR_FDB_ENTRY_TYPE_MAX
};

struct mvsw_pr_fdb_event {
	enum mvsw_pr_fdb_entry_type type;
	union {
		u32 port_id;
		u16 lag_id;
	} dest;
	u32 vid;
	union {
		u8 mac[ETH_ALEN];
	} data;
};

struct mvsw_pr_port_event {
	u32 port_id;
	struct {
		u8 oper_state;
		u8 duplex;
		u32 speed;
	} data;
};

struct mvsw_pr_fw_log_event {
	u32 log_len;
	u8 *data;
};

struct mvsw_pr_event {
	u16 id;
	union {
		struct mvsw_pr_port_event port_evt;
		struct mvsw_pr_fdb_event fdb_evt;
		struct mvsw_pr_fw_log_event fw_log_evt;
	};
};

struct prestera_lag_member {
	struct list_head list;
	struct mvsw_pr_port *port;
};

struct prestera_lag {
	struct net_device *dev;
	u16 member_count;
	struct list_head members;
};

enum mvsw_pr_if_type {
	/* the interface is of port type (dev,port) */
	MVSW_IF_PORT_E = 0,

	/* the interface is of lag type (lag-id) */
	MVSW_IF_LAG_E = 1,

	/* the interface is of Vid type (vlan-id) */
	MVSW_IF_VID_E = 3,
};

struct mvsw_pr_iface {
	enum mvsw_pr_if_type type;
	struct {
		u32 hw_dev_num;
		u32 port_num;
	} dev_port;
	u16 vr_id;
	u16 lag_id;
	u16 vlan_id;
	u32 hw_dev_num;
};

struct mvsw_pr_bridge;
struct mvsw_pr_router;
struct mvsw_pr_rif;

struct mvsw_pr_switch {
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
	struct prestera_acl *acl;
	struct mvsw_pr_bridge *bridge;
	struct prestera_switchdev *switchdev;
	struct mvsw_pr_router *router;
	struct prestera_lag *lags;
	struct notifier_block netdevice_nb;
	struct device_node *np;
};

struct mvsw_pr_router {
	struct mvsw_pr_switch *sw;
	struct list_head rif_list;	/* list of mvsw_pr_rif */
	struct list_head vr_list;	/* list of mvsw_pr_vr */
	struct rhashtable nh_neigh_ht;
	struct rhashtable nexthop_group_ht;
	struct rhashtable fib_ht;
	struct rhashtable kern_fib_cache_ht;
	struct rhashtable kern_neigh_cache_ht;
	struct {
		struct delayed_work dw;
		unsigned int interval;	/* ms */
	} neighs_update;
	struct notifier_block netevent_nb;
	struct notifier_block inetaddr_nb;
	struct notifier_block fib_nb;
	bool aborted;
};

enum mvsw_pr_fdb_flush_mode {
	MVSW_PR_FDB_FLUSH_MODE_DYNAMIC = BIT(0),
	MVSW_PR_FDB_FLUSH_MODE_STATIC = BIT(1),
	MVSW_PR_FDB_FLUSH_MODE_ALL = MVSW_PR_FDB_FLUSH_MODE_DYNAMIC
				   | MVSW_PR_FDB_FLUSH_MODE_STATIC,
};

enum prestera_acl_rule_match_entry_type {
	MVSW_ACL_RULE_MATCH_ENTRY_TYPE_ETH_TYPE = 1,
	MVSW_ACL_RULE_MATCH_ENTRY_TYPE_ETH_DMAC,
	MVSW_ACL_RULE_MATCH_ENTRY_TYPE_ETH_SMAC,
	MVSW_ACL_RULE_MATCH_ENTRY_TYPE_IP_PROTO,
	MVSW_ACL_RULE_MATCH_ENTRY_TYPE_PORT,
	MVSW_ACL_RULE_MATCH_ENTRY_TYPE_IP_SRC,
	MVSW_ACL_RULE_MATCH_ENTRY_TYPE_IP_DST,
	MVSW_ACL_RULE_MATCH_ENTRY_TYPE_L4_PORT_SRC,
	MVSW_ACL_RULE_MATCH_ENTRY_TYPE_L4_PORT_DST,
	MVSW_ACL_RULE_MATCH_ENTRY_TYPE_L4_PORT_RANGE_SRC,
	MVSW_ACL_RULE_MATCH_ENTRY_TYPE_L4_PORT_RANGE_DST,
	MVSW_ACL_RULE_MATCH_ENTRY_TYPE_VLAN_ID,
	MVSW_ACL_RULE_MATCH_ENTRY_TYPE_VLAN_TPID,
	MVSW_ACL_RULE_MATCH_ENTRY_TYPE_ICMP_TYPE,
	MVSW_ACL_RULE_MATCH_ENTRY_TYPE_ICMP_CODE
};

enum prestera_acl_rule_action {
	MVSW_ACL_RULE_ACTION_ACCEPT,
	MVSW_ACL_RULE_ACTION_DROP,
	MVSW_ACL_RULE_ACTION_TRAP,
	MVSW_ACL_RULE_ACTION_POLICE
};

struct prestera_acl_rule_match_entry {
	struct list_head list;
	enum prestera_acl_rule_match_entry_type type;
	union {
		struct {
			u8 key, mask;
		} u8;
		struct {
			u16 key, mask;
		} u16;
		struct {
			u32 key, mask;
		} u32;
		struct {
			u64 key, mask;
		} u64;
		struct {
			u8 key[ETH_ALEN];
			u8 mask[ETH_ALEN];
		} mac;
	} keymask;
};

struct prestera_acl_rule_action_entry {
	struct list_head list;
	enum prestera_acl_rule_action id;
	union {
		struct {
			u64 rate, burst;
		} police;
	};
};

struct mvsw_pr_ip_addr {
	enum {
		MVSW_PR_IPV4 = 0,
		MVSW_PR_IPV6
	} v;
	union {
		__be32 ipv4;
		struct in6_addr ipv6;
	} u;
};

struct mvsw_pr_fib_key {
	struct mvsw_pr_ip_addr addr;
	u32 prefix_len;
	u32 tb_id;
};

struct mvsw_pr_fib_info {
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

/* Used for hw call */
struct mvsw_pr_neigh_info {
	struct mvsw_pr_iface iface;
	unsigned char ha[ETH_ALEN];
	bool connected; /* indicate, if mac/oif valid */
};

struct mvsw_pr_nh_neigh_key {
	struct mvsw_pr_ip_addr addr;
	struct mvsw_pr_rif *rif;
};

/* Used to notify nh about neigh change */
struct mvsw_pr_nh_neigh {
	struct mvsw_pr_nh_neigh_key key;
	struct mvsw_pr_neigh_info info;
	struct rhash_head ht_node; /* node of mvsw_pr_vr */
	struct list_head nexthop_group_list;
};

int mvsw_pr_switch_ageing_set(struct mvsw_pr_switch *sw, u32 ageing_time);

int mvsw_pr_port_learning_set(struct mvsw_pr_port *mvsw_pr_port,
			      bool learn_enable);
int mvsw_pr_port_uc_flood_set(struct mvsw_pr_port *mvsw_pr_port, bool flood);
int mvsw_pr_port_mc_flood_set(struct mvsw_pr_port *mvsw_pr_port, bool flood);
int mvsw_pr_port_pvid_set(struct mvsw_pr_port *mvsw_pr_port, u16 vid);
int mvsw_pr_port_vid_stp_set(struct mvsw_pr_port *port, u16 vid, u8 state);
struct mvsw_pr_port_vlan *
mvsw_pr_port_vlan_create(struct mvsw_pr_port *mvsw_pr_port, u16 vid,
			 bool untagged);
void mvsw_pr_port_vlan_destroy(struct mvsw_pr_port_vlan *mvsw_pr_port_vlan);
int mvsw_pr_port_vlan_set(struct mvsw_pr_port *mvsw_pr_port, u16 vid,
			  bool is_member, bool untagged);

struct mvsw_pr_bridge_device *
mvsw_pr_bridge_device_find(const struct mvsw_pr_bridge *bridge,
			   const struct net_device *br_dev);
u16 mvsw_pr_vlan_dev_vlan_id(struct mvsw_pr_bridge *bridge,
			     struct net_device *dev);
int mvsw_pr_8021d_bridge_create(struct mvsw_pr_switch *sw, u16 *bridge_id);
int mvsw_pr_8021d_bridge_delete(struct mvsw_pr_switch *sw, u16 bridge_id);
int mvsw_pr_8021d_bridge_port_add(struct mvsw_pr_port *mvsw_pr_port,
				  u16 bridge_id);
int mvsw_pr_8021d_bridge_port_delete(struct mvsw_pr_port *mvsw_pr_port,
				     u16 bridge_id);

int mvsw_pr_fdb_add(struct mvsw_pr_port *mvsw_pr_port, const unsigned char *mac,
		    u16 vid, bool dynamic);
int mvsw_pr_fdb_del(struct mvsw_pr_port *mvsw_pr_port, const unsigned char *mac,
		    u16 vid);
int mvsw_pr_fdb_flush_vlan(struct mvsw_pr_switch *sw, u16 vid,
			   enum mvsw_pr_fdb_flush_mode mode);
int mvsw_pr_fdb_flush_port_vlan(struct mvsw_pr_port *port, u16 vid,
				enum mvsw_pr_fdb_flush_mode mode);
int mvsw_pr_fdb_flush_port(struct mvsw_pr_port *port,
			   enum mvsw_pr_fdb_flush_mode mode);
int mvsw_pr_macvlan_add(const struct mvsw_pr_switch *sw, u16 vr_id,
			const u8 *mac, u16 vid);
int mvsw_pr_macvlan_del(const struct mvsw_pr_switch *sw, u16 vr_id,
			const u8 *mac, u16 vid);

int prestera_lag_member_add(struct mvsw_pr_port *port,
			    struct net_device *lag_dev, u16 lag_id);
int prestera_lag_member_del(struct mvsw_pr_port *port);
int prestera_lag_member_enable(struct mvsw_pr_port *port, bool enable);
bool mvsw_pr_port_is_lag_member(const struct mvsw_pr_port *port);
int prestera_lag_id_find(struct mvsw_pr_switch *sw, struct net_device *lag_dev,
			 u16 *lag_id);
void prestera_lag_member_rif_leave(const struct mvsw_pr_port *port,
				   u16 lag_id, u16 vr_id);

int mvsw_pr_dev_if_type(const struct net_device *dev);

/* prestera_flower.c */
int mvsw_pr_flower_replace(struct mvsw_pr_switch *sw,
			   struct prestera_acl_block *block,
			   struct flow_cls_offload *f);
void mvsw_pr_flower_destroy(struct mvsw_pr_switch *sw,
			    struct prestera_acl_block *block,
			    struct flow_cls_offload *f);
int mvsw_pr_flower_stats(struct mvsw_pr_switch *sw,
			 struct prestera_acl_block *block,
			 struct flow_cls_offload *f);

/* prestera_acl.c */
int prestera_acl_init(struct mvsw_pr_switch *sw);
void prestera_acl_fini(struct mvsw_pr_switch *sw);
struct prestera_acl_block *
prestera_acl_block_create(struct mvsw_pr_switch *sw, struct net *net);
void prestera_acl_block_destroy(struct prestera_acl_block *block);
struct net *prestera_acl_block_net(struct prestera_acl_block *block);
struct mvsw_pr_switch *prestera_acl_block_sw(struct prestera_acl_block *block);
unsigned int prestera_acl_block_rule_count(struct prestera_acl_block *block);
void prestera_acl_block_disable_inc(struct prestera_acl_block *block);
void prestera_acl_block_disable_dec(struct prestera_acl_block *block);
bool prestera_acl_block_disabled(const struct prestera_acl_block *block);
int prestera_acl_block_bind(struct mvsw_pr_switch *sw,
			    struct prestera_acl_block *block,
			    struct mvsw_pr_port *port);
int prestera_acl_block_unbind(struct mvsw_pr_switch *sw,
			      struct prestera_acl_block *block,
			      struct mvsw_pr_port *port);
struct prestera_acl_ruleset *
prestera_acl_block_ruleset_get(struct prestera_acl_block *block);
struct prestera_acl_rule *
prestera_acl_rule_create(struct prestera_acl_block *block,
			 unsigned long cookie);
u32 prestera_acl_rule_priority_get(struct prestera_acl_rule *rule);
void prestera_acl_rule_priority_set(struct prestera_acl_rule *rule,
				    u32 priority);
u8 prestera_acl_rule_hw_tc_get(struct prestera_acl_rule *rule);
void prestera_acl_rule_hw_tc_set(struct prestera_acl_rule *rule, u8 hw_tc);
u16 prestera_acl_rule_ruleset_id_get(const struct prestera_acl_rule *rule);
struct list_head *
prestera_acl_rule_action_list_get(struct prestera_acl_rule *rule);
u8 prestera_acl_rule_action_len(struct prestera_acl_rule *rule);
void prestera_acl_rule_action_add(struct prestera_acl_rule *rule,
				  struct prestera_acl_rule_action_entry *entry);
struct list_head *
prestera_acl_rule_match_list_get(struct prestera_acl_rule *rule);
void prestera_acl_rule_match_add(struct prestera_acl_rule *rule,
				 struct prestera_acl_rule_match_entry *entry);
void prestera_acl_rule_destroy(struct prestera_acl_rule *rule);
struct prestera_acl_rule *
prestera_acl_rule_lookup(struct prestera_acl_ruleset *ruleset,
			 unsigned long cookie);
int prestera_acl_rule_add(struct mvsw_pr_switch *sw,
			  struct prestera_acl_rule *rule);
void prestera_acl_rule_del(struct mvsw_pr_switch *sw,
			   struct prestera_acl_rule *rule);
int prestera_acl_rule_get_stats(struct mvsw_pr_switch *sw,
				struct prestera_acl_rule *rule,
				u64 *packets, u64 *bytes, u64 *last_use);

/* VLAN API */
struct mvsw_pr_port_vlan *
mvsw_pr_port_vlan_find_by_vid(const struct mvsw_pr_port *mvsw_pr_port, u16 vid);
void
mvsw_pr_port_vlan_bridge_leave(struct mvsw_pr_port_vlan *mvsw_pr_port_vlan);

int prestera_switchdev_register(struct mvsw_pr_switch *sw);
void prestera_switchdev_unregister(struct mvsw_pr_switch *sw);

int prestera_device_register(struct prestera_device *dev);
void prestera_device_unregister(struct prestera_device *dev);

bool mvsw_pr_netdev_check(const struct net_device *dev);
struct mvsw_pr_switch *mvsw_pr_switch_get(struct net_device *dev);
struct mvsw_pr_port *mvsw_pr_port_dev_lower_find(struct net_device *dev);

const struct mvsw_pr_port *mvsw_pr_port_find(u32 dev_hw_id, u32 port_hw_id);
int mvsw_pr_schedule_dw(struct delayed_work *dwork, unsigned long delay);

/* prestera_router.c */
int mvsw_pr_router_init(struct mvsw_pr_switch *sw);
void mvsw_pr_router_fini(struct mvsw_pr_switch *sw);
int mvsw_pr_netdevice_router_port_event(struct net_device *dev,
					unsigned long event, void *ptr);
int mvsw_pr_inetaddr_valid_event(struct notifier_block *unused,
				 unsigned long event, void *ptr);
int mvsw_pr_netdevice_vrf_event(struct net_device *dev, unsigned long event,
				struct netdev_notifier_changeupper_info *info);
void mvsw_pr_port_router_leave(struct mvsw_pr_port *mvsw_pr_port);
int mvsw_pr_lpm_add(struct mvsw_pr_switch *sw, u16 hw_vr_id,
		    struct mvsw_pr_ip_addr *addr, u32 prefix_len, u32 grp_id);
int mvsw_pr_lpm_del(struct mvsw_pr_switch *sw, u16 hw_vr_id,
		    struct mvsw_pr_ip_addr *addr, u32 prefix_len);
int mvsw_pr_nh_entries_set(const struct mvsw_pr_switch *sw, int count,
			   struct mvsw_pr_neigh_info *nhs, u32 grp_id);
int mvsw_pr_nh_entries_get(const struct mvsw_pr_switch *sw, int count,
			   struct mvsw_pr_neigh_info *nhs, u32 grp_id);
int mvsw_pr_nh_group_create(const struct mvsw_pr_switch *sw, u16 nh_count,
			    u32 *grp_id);
int mvsw_pr_nh_group_delete(const struct mvsw_pr_switch *sw, u16 nh_count,
			    u32 grp_id);
int mvsw_pr_mp4_hash_set(const struct mvsw_pr_switch *sw, u8 hash_policy);

void mvsw_pr_rif_enable(struct mvsw_pr_switch *sw, struct net_device *dev,
			bool enable);
bool mvsw_pr_rif_exists(const struct mvsw_pr_switch *sw,
			const struct net_device *dev);
void mvsw_pr_router_lag_member_leave(const struct mvsw_pr_port *port,
				     const struct net_device *dev);
void prestera_lag_router_leave(struct mvsw_pr_switch *sw,
			       struct net_device *lag_dev);

void mvsw_pr_bridge_device_rifs_destroy(struct mvsw_pr_switch *sw,
					struct net_device *bridge_dev);

#endif /* _MVSW_PRESTERA_H_ */
