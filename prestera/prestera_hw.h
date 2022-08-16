/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved. */

#ifndef _PRESTERA_HW_H_
#define _PRESTERA_HW_H_

#include <linux/types.h>

enum prestera_accept_frame_type {
	PRESTERA_ACCEPT_FRAME_TYPE_TAGGED,
	PRESTERA_ACCEPT_FRAME_TYPE_UNTAGGED,
	PRESTERA_ACCEPT_FRAME_TYPE_ALL
};

enum {
	PRESTERA_MAC_MODE_INTERNAL,
	PRESTERA_MAC_MODE_SGMII,
	PRESTERA_MAC_MODE_1000BASE_X,
	PRESTERA_MAC_MODE_KR,
	PRESTERA_MAC_MODE_KR2,
	PRESTERA_MAC_MODE_KR4,
	PRESTERA_MAC_MODE_CR,
	PRESTERA_MAC_MODE_CR2,
	PRESTERA_MAC_MODE_CR4,
	PRESTERA_MAC_MODE_SR_LR,
	PRESTERA_MAC_MODE_SR_LR2,
	PRESTERA_MAC_MODE_SR_LR4,
	PRESTERA_MAC_MODE_MAX
};

enum {
	PRESTERA_LINK_MODE_10baseT_Half,
	PRESTERA_LINK_MODE_10baseT_Full,
	PRESTERA_LINK_MODE_100baseT_Half,
	PRESTERA_LINK_MODE_100baseT_Full,
	PRESTERA_LINK_MODE_1000baseT_Half,
	PRESTERA_LINK_MODE_1000baseT_Full,
	PRESTERA_LINK_MODE_1000baseX_Full,
	PRESTERA_LINK_MODE_1000baseKX_Full,
	PRESTERA_LINK_MODE_2500baseX_Full,
	PRESTERA_LINK_MODE_10GbaseKR_Full,
	PRESTERA_LINK_MODE_10GbaseSR_Full,
	PRESTERA_LINK_MODE_10GbaseLR_Full,
	PRESTERA_LINK_MODE_20GbaseKR2_Full,
	PRESTERA_LINK_MODE_25GbaseCR_Full,
	PRESTERA_LINK_MODE_25GbaseKR_Full,
	PRESTERA_LINK_MODE_25GbaseSR_Full,
	PRESTERA_LINK_MODE_40GbaseKR4_Full,
	PRESTERA_LINK_MODE_40GbaseCR4_Full,
	PRESTERA_LINK_MODE_40GbaseSR4_Full,
	PRESTERA_LINK_MODE_50GbaseCR2_Full,
	PRESTERA_LINK_MODE_50GbaseKR2_Full,
	PRESTERA_LINK_MODE_50GbaseSR2_Full,
	PRESTERA_LINK_MODE_100GbaseKR4_Full,
	PRESTERA_LINK_MODE_100GbaseSR4_Full,
	PRESTERA_LINK_MODE_100GbaseCR4_Full,
	PRESTERA_LINK_MODE_MAX,
};

enum {
	PRESTERA_PORT_TYPE_NONE,
	PRESTERA_PORT_TYPE_TP,
	PRESTERA_PORT_TYPE_AUI,
	PRESTERA_PORT_TYPE_MII,
	PRESTERA_PORT_TYPE_FIBRE,
	PRESTERA_PORT_TYPE_BNC,
	PRESTERA_PORT_TYPE_DA,
	PRESTERA_PORT_TYPE_OTHER,
	PRESTERA_PORT_TYPE_MAX,
};

enum {
	PRESTERA_PORT_TCVR_COPPER,
	PRESTERA_PORT_TCVR_SFP,
	PRESTERA_PORT_TCVR_MAX,
};

enum {
	PRESTERA_PORT_FEC_OFF,
	PRESTERA_PORT_FEC_BASER,
	PRESTERA_PORT_FEC_RS,
	PRESTERA_PORT_FEC_MAX,
};

enum {
	PRESTERA_PORT_DUPLEX_HALF,
	PRESTERA_PORT_DUPLEX_FULL,
	PRESTERA_PORT_DUPLEX_MAX
};

enum {
	PRESTERA_STP_DISABLED,
	PRESTERA_STP_BLOCK_LISTEN,
	PRESTERA_STP_LEARN,
	PRESTERA_STP_FORWARD
};

enum {
	PRESTERA_FW_LOG_LIB_BRIDGE = 0,
	PRESTERA_FW_LOG_LIB_CNC,
	PRESTERA_FW_LOG_LIB_CONFIG,
	PRESTERA_FW_LOG_LIB_COS,
	PRESTERA_FW_LOG_LIB_HW_INIT,
	PRESTERA_FW_LOG_LIB_CSCD,
	PRESTERA_FW_LOG_LIB_CUT_THROUGH,
	PRESTERA_FW_LOG_LIB_DIAG,
	PRESTERA_FW_LOG_LIB_FABRIC,
	PRESTERA_FW_LOG_LIB_IP,
	PRESTERA_FW_LOG_LIB_IPFIX,
	PRESTERA_FW_LOG_LIB_IP_LPM,
	PRESTERA_FW_LOG_LIB_L2_MLL,
	PRESTERA_FW_LOG_LIB_LOGICAL_TARGET,
	PRESTERA_FW_LOG_LIB_LPM,
	PRESTERA_FW_LOG_LIB_MIRROR,
	PRESTERA_FW_LOG_LIB_MULTI_PORT_GROUP,
	PRESTERA_FW_LOG_LIB_NETWORK_IF,
	PRESTERA_FW_LOG_LIB_NST,
	PRESTERA_FW_LOG_LIB_OAM,
	PRESTERA_FW_LOG_LIB_PCL,
	PRESTERA_FW_LOG_LIB_PHY,
	PRESTERA_FW_LOG_LIB_POLICER,
	PRESTERA_FW_LOG_LIB_PORT,
	PRESTERA_FW_LOG_LIB_PROTECTION,
	PRESTERA_FW_LOG_LIB_PTP,
	PRESTERA_FW_LOG_LIB_SYSTEM_RECOVERY,
	PRESTERA_FW_LOG_LIB_TCAM,
	PRESTERA_FW_LOG_LIB_TM_GLUE,
	PRESTERA_FW_LOG_LIB_TRUNK,
	PRESTERA_FW_LOG_LIB_TTI,
	PRESTERA_FW_LOG_LIB_TUNNEL,
	PRESTERA_FW_LOG_LIB_VNT,
	PRESTERA_FW_LOG_LIB_RESOURCE_MANAGER,
	PRESTERA_FW_LOG_LIB_VERSION,
	PRESTERA_FW_LOG_LIB_TM,
	PRESTERA_FW_LOG_LIB_SMI,
	PRESTERA_FW_LOG_LIB_INIT,
	PRESTERA_FW_LOG_LIB_DRAGONITE,
	PRESTERA_FW_LOG_LIB_VIRTUAL_TCAM,
	PRESTERA_FW_LOG_LIB_INGRESS,
	PRESTERA_FW_LOG_LIB_EGRESS,
	PRESTERA_FW_LOG_LIB_LATENCY_MONITORING,
	PRESTERA_FW_LOG_LIB_TAM,
	PRESTERA_FW_LOG_LIB_EXACT_MATCH,
	PRESTERA_FW_LOG_LIB_PHA,
	PRESTERA_FW_LOG_LIB_PACKET_ANALYZER,
	PRESTERA_FW_LOG_LIB_FLOW_MANAGER,
	PRESTERA_FW_LOG_LIB_BRIDGE_FDB_MANAGER,
	PRESTERA_FW_LOG_LIB_I2C,
	PRESTERA_FW_LOG_LIB_PPU,
	PRESTERA_FW_LOG_LIB_EXACT_MATCH_MANAGER,
	PRESTERA_FW_LOG_LIB_MAC_SEC,
	PRESTERA_FW_LOG_LIB_PTP_MANAGER,
	PRESTERA_FW_LOG_LIB_HSR_PRP,
	PRESTERA_FW_LOG_LIB_STREAM,
	PRESTERA_FW_LOG_LIB_IPFIX_MANAGER,
	PRESTERA_FW_LOG_LIB_ALL,

	PRESTERA_FW_LOG_LIB_MAX
};

enum {
	PRESTERA_FW_LOG_TYPE_INFO = 0,
	PRESTERA_FW_LOG_TYPE_ENTRY_LEVEL_FUNCTION,
	PRESTERA_FW_LOG_TYPE_ERROR,
	PRESTERA_FW_LOG_TYPE_ALL,
	PRESTERA_FW_LOG_TYPE_NONE,

	PRESTERA_FW_LOG_TYPE_MAX
};

enum {
	PRESTERA_PORT_STORM_CTL_TYPE_BC = 0,
	PRESTERA_PORT_STORM_CTL_TYPE_UC_UNK = 1,
	PRESTERA_PORT_STORM_CTL_TYPE_MC = 2
};

enum prestera_hw_cpu_code_cnt_t {
	PRESTERA_HW_CPU_CODE_CNT_TYPE_DROP = 0,
	PRESTERA_HW_CPU_CODE_CNT_TYPE_TRAP = 1,
};

enum {
	PRESTERA_HW_VTCAM_DIR_INGRESS = 0,
	PRESTERA_HW_VTCAM_DIR_EGRESS = 1,
};

enum {
	PRESTERA_HW_COUNTER_CLIENT_INGRESS_LOOKUP_0 = 0,
	PRESTERA_HW_COUNTER_CLIENT_INGRESS_LOOKUP_1 = 1,
	PRESTERA_HW_COUNTER_CLIENT_INGRESS_LOOKUP_2 = 2,
	PRESTERA_HW_COUNTER_CLIENT_EGRESS_LOOKUP = 3,
};

enum {
	PRESTERA_HW_QOS_TRUST_MODE_L2 = 0,
	PRESTERA_HW_QOS_TRUST_MODE_L3 = 1,
};

enum {
	PRESTERA_SCT_ALL_UNSPECIFIED_CPU_OPCODES,
	PRESTERA_SCT_ACL_TRAP_QUEUE_0,
	PRESTERA_SCT_ACL_TRAP_QUEUE_1,
	PRESTERA_SCT_ACL_TRAP_QUEUE_2,
	PRESTERA_SCT_ACL_TRAP_QUEUE_3,
	PRESTERA_SCT_ACL_TRAP_QUEUE_4,
	PRESTERA_SCT_ACL_TRAP_QUEUE_5,
	PRESTERA_SCT_ACL_TRAP_QUEUE_6,
	PRESTERA_SCT_ACL_TRAP_QUEUE_7,
	PRESTERA_SCT_STP,
	PRESTERA_SCT_LACP,
	PRESTERA_SCT_LLDP,
	PRESTERA_SCT_CDP,
	PRESTERA_SCT_ARP_INTERVENTION,
	PRESTERA_SCT_ARP_TO_ME,
	PRESTERA_SCT_BGP_ALL_ROUTERS_MC,
	PRESTERA_SCT_VRRP,
	PRESTERA_SCT_IP_BC,
	PRESTERA_SCT_IP_TO_ME,
	PRESTERA_SCT_DEFAULT_ROUTE,
	PRESTERA_SCT_BGP,
	PRESTERA_SCT_SSH,
	PRESTERA_SCT_TELNET,
	PRESTERA_SCT_DHCP,
	PRESTERA_SCT_ICMP,
	PRESTERA_SCT_IGMP,
	PRESTERA_SCT_SPECIAL_IP4_ICMP_REDIRECT,
	PRESTERA_SCT_SPECIAL_IP4_OPTIONS_IN_IP_HDR,
	PRESTERA_SCT_SPECIAL_IP4_MTU_EXCEED,
	PRESTERA_SCT_SPECIAL_IP4_ZERO_TTL,
	PRESTERA_SCT_OSPF,
	PRESTERA_SCT_ISIS,
	PRESTERA_SCT_NAT,

	PRESTERA_SCT_MAX
};

struct prestera_switch;
struct prestera_port;
struct prestera_port_stats;
struct prestera_port_caps;
struct prestera_acl_rule;

struct prestera_iface;
struct prestera_neigh_info;
struct prestera_counter_stats;
struct prestera_acl_iface;

enum prestera_event_type;
struct prestera_event;

/* Switch API */
int prestera_hw_switch_init(struct prestera_switch *sw);
int prestera_hw_switch_reset(struct prestera_switch *sw);
int prestera_hw_switch_ageing_set(const struct prestera_switch *sw,
				  u32 ageing_time);
int prestera_hw_switch_mac_set(const struct prestera_switch *sw, const u8 *mac);
int prestera_hw_switch_trap_policer_set(const struct prestera_switch *sw,
					u8 profile);

/* Port API */
int prestera_hw_port_info_get(const struct prestera_port *port,
			      u16 *fp_id, u32 *hw_id, u32 *dev_id);
int prestera_hw_port_mtu_set(const struct prestera_port *port, u32 mtu);
int prestera_hw_port_mtu_get(const struct prestera_port *port, u32 *mtu);
int prestera_hw_port_mac_set(const struct prestera_port *port, char *mac);
int prestera_hw_port_mac_get(const struct prestera_port *port, char *mac);
int prestera_hw_port_accept_frame_type_set(const struct prestera_port *port,
					   enum prestera_accept_frame_type type);
int prestera_hw_port_learning_set(const struct prestera_port *port,
				  bool enable);
int prestera_hw_port_uc_flood_set(const struct prestera_port *port, bool flood);
int prestera_hw_port_mc_flood_set(const struct prestera_port *port, bool flood);
int prestera_hw_port_srcid_default_set(const struct prestera_port *port,
				       u32 sourceid);
int prestera_hw_port_srcid_filter_set(const struct prestera_port *port,
				      u32 sourceid);
int prestera_hw_port_cap_get(const struct prestera_port *port,
			     struct prestera_port_caps *caps);
int prestera_hw_port_type_get(const struct prestera_port *port, u8 *type);
int prestera_hw_port_stats_get(const struct prestera_port *port,
			       struct prestera_port_stats *stats);
int prestera_hw_port_mac_mode_get(const struct prestera_port *port,
				  u32 *mode, u32 *speed, u8 *duplex, u8 *fec);
int prestera_hw_port_mac_mode_set(const struct prestera_port *port,
				  bool admin, u32 mode, u8 inband,
				  u32 speed, u8 duplex, u8 fec);
int prestera_hw_port_phy_mode_get(const struct prestera_port *port,
				  u8 *mdix, u64 *lmode_bmap,
				  bool *fc_pause, bool *fc_asym);
int prestera_hw_port_phy_mode_set(const struct prestera_port *port,
				  bool admin, bool adv, u32 mode, u64 modes,
				  u8 mdix);
int prestera_hw_port_autoneg_restart(struct prestera_port *port);

int prestera_hw_port_storm_control_cfg_set(const struct prestera_port *port,
					   u32 storm_type,
					   u32 kbyte_per_sec_rate);

/* Vlan API */
int prestera_hw_vlan_create(const struct prestera_switch *sw, u16 vid);
int prestera_hw_vlan_delete(const struct prestera_switch *sw, u16 vid);
int prestera_hw_vlan_port_set(const struct prestera_port *port,
			      u16 vid, bool is_member, bool untagged);
int prestera_hw_vlan_port_vid_set(const struct prestera_port *port, u16 vid);

/* FDB API */
int prestera_hw_fdb_add(const struct prestera_port *port,
			const unsigned char *mac, u16 vid, bool dynamic);
int prestera_hw_fdb_del(const struct prestera_port *port,
			const unsigned char *mac, u16 vid);
int prestera_hw_fdb_flush_port(const struct prestera_port *port, u32 mode);
int prestera_hw_fdb_flush_vlan(const struct prestera_switch *sw, u16 vid,
			       u32 mode);
int prestera_hw_fdb_flush_port_vlan(const struct prestera_port *port, u16 vid,
				    u32 mode);
int prestera_hw_macvlan_add(const struct prestera_switch *sw, u16 vr_id,
			    const u8 *mac, u16 vid,
			    struct prestera_iface *iface);
int prestera_hw_macvlan_del(const struct prestera_switch *sw, u16 vr_id,
			    const u8 *mac, u16 vid,
			    struct prestera_iface *iface);
int prestera_hw_fdb_routed_add(const struct prestera_switch *sw,
			       const u8 *mac, u16 vid);
int prestera_hw_fdb_routed_del(const struct prestera_switch *sw,
			       const u8 *mac, u16 vid);

/* Bridge API */
int prestera_hw_bridge_create(const struct prestera_switch *sw, u16 *bridge_id);
int prestera_hw_bridge_delete(const struct prestera_switch *sw, u16 bridge_id);
int prestera_hw_bridge_port_add(const struct prestera_port *port,
				u16 bridge_id);
int prestera_hw_bridge_port_delete(const struct prestera_port *port,
				   u16 bridge_id);

/* STP API */
int prestera_hw_port_vid_stp_set(struct prestera_port *port, u16 vid, u8 state);

/* Counter API */
int prestera_hw_counter_trigger(const struct prestera_switch *sw, u32 block_id);
int prestera_hw_counter_abort(const struct prestera_switch *sw);
int prestera_hw_counters_get(const struct prestera_switch *sw, u32 idx,
			     u32 *len, bool *done,
			     struct prestera_counter_stats *stats);
int prestera_hw_counter_block_get(const struct prestera_switch *sw, u32 client,
				  u32 *block_id, u32 *offset, u32 *num_counters);
int prestera_hw_counter_block_release(const struct prestera_switch *sw,
				      u32 block_id);
int prestera_hw_counter_clear(const struct prestera_switch *sw, u32 block_id,
			      u32 counter_id);

/* vTCAM API */
int prestera_hw_vtcam_create(const struct prestera_switch *sw,
			     u8 lookup, const u32 *keymask, u32 *vtcam_id,
			     u8 direction);
int prestera_hw_vtcam_rule_add(const struct prestera_switch *sw, u32 vtcam_id,
			       u32 prio, void *key, void *keymask,
			       struct prestera_acl_hw_action_info *act,
			       u8 n_act, u32 *rule_id);
int prestera_hw_vtcam_rule_del(const struct prestera_switch *sw,
			       u32 vtcam_id, u32 rule_id);
int prestera_hw_vtcam_destroy(const struct prestera_switch *sw, u32 vtcam_id);
int prestera_hw_vtcam_iface_bind(const struct prestera_switch *sw,
				 struct prestera_acl_iface *iface,
				 u32 vtcam_id, u16 pcl_id);
int prestera_hw_vtcam_iface_unbind(const struct prestera_switch *sw,
				   struct prestera_acl_iface *iface,
				   u32 vtcam_id);

/* NAT API */
int prestera_hw_nat_port_neigh_update(const struct prestera_port *port,
				      unsigned char *mac);
int prestera_hw_nh_mangle_add(const struct prestera_switch *sw, u32 *nh_id);
int prestera_hw_nh_mangle_del(const struct prestera_switch *sw, u32 nh_id);
int prestera_hw_nh_mangle_set(const struct prestera_switch *sw, u32 nh_id,
			      bool l4_src_valid, __be16 l4_src,
			      bool l4_dst_valid, __be16 l4_dst,
			      bool sip_valid, struct prestera_ip_addr sip,
			      bool dip_valid, struct prestera_ip_addr dip,
			      struct prestera_neigh_info nh);
int prestera_hw_nh_mangle_get(const struct prestera_switch *sw, u32 nh_id,
			      bool *is_active);

/* SPAN API */
int prestera_hw_span_get(const struct prestera_port *port, u8 *span_id);
int prestera_hw_span_bind(const struct prestera_port *port, u8 span_id);
int prestera_hw_span_unbind(const struct prestera_port *port);
int prestera_hw_span_release(const struct prestera_switch *sw, u8 span_id);

/* Router API */
int prestera_hw_rif_create(const struct prestera_switch *sw,
			   struct prestera_iface *iif, u8 *mac, u16 *rif_id);
int prestera_hw_rif_delete(const struct prestera_switch *sw, u16 rif_id,
			   struct prestera_iface *iif);
int prestera_hw_rif_set(const struct prestera_switch *sw, u16 *rif_id,
			struct prestera_iface *iif, u8 *mac);

/* Virtual Router API */
int prestera_hw_vr_create(const struct prestera_switch *sw, u16 *vr_id);
int prestera_hw_vr_delete(const struct prestera_switch *sw, u16 vr_id);

/* LPM API */
int prestera_hw_lpm_add(const struct prestera_switch *sw, u16 vr_id,
			__be32 dst, u32 dst_len, u32 grp_id);
int prestera_hw_lpm_del(const struct prestera_switch *sw, u16 vr_id, __be32 dst,
			u32 dst_len);
int prestera_hw_lpm6_add(const struct prestera_switch *sw, u16 vr_id,
			 __u8 *dst, u32 dst_len, u32 grp_id);
int prestera_hw_lpm6_del(const struct prestera_switch *sw, u16 vr_id,
			 __u8 *dst, u32 dst_len);

/* NH API */
int prestera_hw_nh_entries_set(const struct prestera_switch *sw, int count,
			       struct prestera_neigh_info *nhs, u32 grp_id);
int prestera_hw_nh_entries_get(const struct prestera_switch *sw, int count,
			       struct prestera_neigh_info *nhs, u32 grp_id);
int prestera_hw_nhgrp_blk_get(const struct prestera_switch *sw,
			      u8 *hw_state, u32 buf_size /* Buffer in bytes */);
int prestera_hw_nh_group_create(const struct prestera_switch *sw, u16 nh_count,
				u32 *grp_id);
int prestera_hw_nh_group_delete(const struct prestera_switch *sw, u16 nh_count,
				u32 grp_id);

/* MP API */
int prestera_hw_mp4_hash_set(const struct prestera_switch *sw, u8 hash_policy);

/* LAG API */
int prestera_hw_lag_member_add(struct prestera_port *port, u16 lag_id);
int prestera_hw_lag_member_del(struct prestera_port *port, u16 lag_id);
int prestera_hw_lag_member_enable(struct prestera_port *port, u16 lag_id,
				  bool enable);
int prestera_hw_lag_fdb_add(const struct prestera_switch *sw, u16 lag_id,
			    const unsigned char *mac, u16 vid, bool dynamic);
int prestera_hw_lag_fdb_del(const struct prestera_switch *sw, u16 lag_id,
			    const unsigned char *mac, u16 vid);
int prestera_hw_fdb_flush_lag(const struct prestera_switch *sw, u16 lag_id,
			      u32 mode);
int prestera_hw_fdb_flush_lag_vlan(const struct prestera_switch *sw,
				   u16 lag_id, u16 vid, u32 mode);
int prestera_hw_lag_member_rif_leave(const struct prestera_port *port,
				     u16 lag_id, u16 vr_id);

/* Event handlers */
int prestera_hw_event_handler_register(struct prestera_switch *sw,
				       enum prestera_event_type type,
				       void (*cb)(struct prestera_switch *sw,
						  struct prestera_event *evt,
						  void *arg),
				       void *arg);

void prestera_hw_event_handler_unregister(struct prestera_switch *sw,
					  enum prestera_event_type type);

/* FW Log API */
int prestera_hw_fw_log_level_set(const struct prestera_switch *sw, u32 lib,
				 u32 type);

int prestera_hw_rxtx_init(const struct prestera_switch *sw, bool use_sdma,
			  u32 *map_addr);

/* FW Keepalive/ Watchdog API */
void prestera_hw_keepalive_fini(const struct prestera_switch *sw);

/* HW trap/drop counters API */
int
prestera_hw_cpu_code_counters_get(const struct prestera_switch *sw, u8 code,
				  enum prestera_hw_cpu_code_cnt_t counter_type,
				  u64 *packet_count);

/* Flood domain / MDB API */
int prestera_hw_flood_domain_create(struct prestera_flood_domain *domain);
int prestera_hw_flood_domain_destroy(struct prestera_flood_domain *domain);
int prestera_hw_flood_domain_ports_set(struct prestera_flood_domain *domain);
int prestera_hw_flood_domain_ports_reset(struct prestera_flood_domain *domain);

int prestera_hw_mdb_create(struct prestera_mdb_entry *mdb);
int prestera_hw_mdb_destroy(struct prestera_mdb_entry *mdb);

/* HW IPG API */
int prestera_hw_ipg_set(struct prestera_switch *sw, u32 ipg);
int prestera_hw_ipg_get(struct prestera_switch *sw, u32 *ipg);

/* QoS */
int prestera_hw_port_qos_mapping_update(const struct prestera_port *port,
					struct dcb_ieee_app_dscp_map *map);
int prestera_hw_port_qos_trust_mode_set(const struct prestera_port *port,
					u8 mode);
int prestera_hw_port_qos_default_prio_set(const struct prestera_port *port,
					  u32 priority);

/* QoS Scheduler */
int prestera_hw_sched_create(const struct prestera_switch *sw, u32 *sched_id);
int prestera_hw_sched_sdwrr_set(const struct prestera_port *port,
				u8 tc, u32 sched_id, u32 weight);
int prestera_hw_sched_sp_set(const struct prestera_port *port,
			     u8 tc, u32 sched_id);
int prestera_hw_sched_release(const struct prestera_switch *sw, u32 sched_id);
int prestera_hw_sched_port_set(const struct prestera_port *port, u32 sched_id);
int prestera_hw_sched_port_get(const struct prestera_port *port, u32 *sched_id);

/* QoS Shaper */
int prestera_hw_shaper_port_queue_configure(const struct prestera_port *port,
					    u32 tc, u32 rate, u32 burst);
int prestera_hw_shaper_port_queue_disable(const struct prestera_port *port,
					  u32 tc);
int prestera_hw_port_queue_stats_get(const struct prestera_port *port,
				     u8 tc, u64 *pkts, u64 *bytes,
				     u64 *drops);

/* QoS Congestion Avoidance */
int prestera_hw_wred_port_queue_enable(const struct prestera_port *port,
				       u32 tc, u32 min, u32 max, u32 prob);
int prestera_hw_wred_port_queue_disable(const struct prestera_port *port,
					u32 tc);

/* SCT configuration API */
int
prestera_hw_sct_ratelimit_set(const struct prestera_switch *sw, u8 group,
			      u32 rate);
int
prestera_hw_sct_ratelimit_get(const struct prestera_switch *sw, u8 group,
			      u32 *rate);

#endif /* _PRESTERA_HW_H_ */
