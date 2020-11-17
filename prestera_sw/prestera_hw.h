/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 *
 * Copyright (c) 2019-2020 Marvell International Ltd. All rights reserved.
 *
 */

#ifndef _MVSW_PRESTERA_HW_H_
#define _MVSW_PRESTERA_HW_H_

#include <linux/types.h>

enum mvsw_pr_accept_frame_type {
	MVSW_ACCEPT_FRAME_TYPE_TAGGED,
	MVSW_ACCEPT_FRAME_TYPE_UNTAGGED,
	MVSW_ACCEPT_FRAME_TYPE_ALL
};

enum {
	MVSW_LINK_MODE_10baseT_Half_BIT,
	MVSW_LINK_MODE_10baseT_Full_BIT,
	MVSW_LINK_MODE_100baseT_Half_BIT,
	MVSW_LINK_MODE_100baseT_Full_BIT,
	MVSW_LINK_MODE_1000baseT_Half_BIT,
	MVSW_LINK_MODE_1000baseT_Full_BIT,
	MVSW_LINK_MODE_1000baseX_Full_BIT,
	MVSW_LINK_MODE_1000baseKX_Full_BIT,
	MVSW_LINK_MODE_2500baseX_Full_BIT,
	MVSW_LINK_MODE_10GbaseKR_Full_BIT,
	MVSW_LINK_MODE_10GbaseSR_Full_BIT,
	MVSW_LINK_MODE_10GbaseLR_Full_BIT,
	MVSW_LINK_MODE_20GbaseKR2_Full_BIT,
	MVSW_LINK_MODE_25GbaseCR_Full_BIT,
	MVSW_LINK_MODE_25GbaseKR_Full_BIT,
	MVSW_LINK_MODE_25GbaseSR_Full_BIT,
	MVSW_LINK_MODE_40GbaseKR4_Full_BIT,
	MVSW_LINK_MODE_40GbaseCR4_Full_BIT,
	MVSW_LINK_MODE_40GbaseSR4_Full_BIT,
	MVSW_LINK_MODE_50GbaseCR2_Full_BIT,
	MVSW_LINK_MODE_50GbaseKR2_Full_BIT,
	MVSW_LINK_MODE_50GbaseSR2_Full_BIT,
	MVSW_LINK_MODE_100GbaseKR4_Full_BIT,
	MVSW_LINK_MODE_100GbaseSR4_Full_BIT,
	MVSW_LINK_MODE_100GbaseCR4_Full_BIT,
	MVSW_LINK_MODE_MAX,
};

enum {
	MVSW_PORT_TYPE_NONE,
	MVSW_PORT_TYPE_TP,
	MVSW_PORT_TYPE_AUI,
	MVSW_PORT_TYPE_MII,
	MVSW_PORT_TYPE_FIBRE,
	MVSW_PORT_TYPE_BNC,
	MVSW_PORT_TYPE_DA,
	MVSW_PORT_TYPE_OTHER,
	MVSW_PORT_TYPE_MAX,
};

enum {
	MVSW_PORT_TRANSCEIVER_COPPER,
	MVSW_PORT_TRANSCEIVER_SFP,
	MVSW_PORT_TRANSCEIVER_MAX,
};

enum {
	MVSW_PORT_FEC_OFF_BIT,
	MVSW_PORT_FEC_BASER_BIT,
	MVSW_PORT_FEC_RS_BIT,
	MVSW_PORT_FEC_MAX,
};

enum {
	MVSW_PORT_DUPLEX_HALF,
	MVSW_PORT_DUPLEX_FULL
};

enum {
	MVSW_STP_DISABLED,
	MVSW_STP_BLOCK_LISTEN,
	MVSW_STP_LEARN,
	MVSW_STP_FORWARD
};

enum {
	MVSW_FW_LOG_LIB_BRIDGE = 0,
	MVSW_FW_LOG_LIB_CNC,
	MVSW_FW_LOG_LIB_CONFIG,
	MVSW_FW_LOG_LIB_COS,
	MVSW_FW_LOG_LIB_HW_INIT,
	MVSW_FW_LOG_LIB_CSCD,
	MVSW_FW_LOG_LIB_CUT_THROUGH,
	MVSW_FW_LOG_LIB_DIAG,
	MVSW_FW_LOG_LIB_FABRIC,
	MVSW_FW_LOG_LIB_IP,
	MVSW_FW_LOG_LIB_IPFIX,
	MVSW_FW_LOG_LIB_IP_LPM,
	MVSW_FW_LOG_LIB_L2_MLL,
	MVSW_FW_LOG_LIB_LOGICAL_TARGET,
	MVSW_FW_LOG_LIB_LPM,
	MVSW_FW_LOG_LIB_MIRROR,
	MVSW_FW_LOG_LIB_MULTI_PORT_GROUP,
	MVSW_FW_LOG_LIB_NETWORK_IF,
	MVSW_FW_LOG_LIB_NST,
	MVSW_FW_LOG_LIB_OAM,
	MVSW_FW_LOG_LIB_PCL,
	MVSW_FW_LOG_LIB_PHY,
	MVSW_FW_LOG_LIB_POLICER,
	MVSW_FW_LOG_LIB_PORT,
	MVSW_FW_LOG_LIB_PROTECTION,
	MVSW_FW_LOG_LIB_PTP,
	MVSW_FW_LOG_LIB_SYSTEM_RECOVERY,
	MVSW_FW_LOG_LIB_TCAM,
	MVSW_FW_LOG_LIB_TM_GLUE,
	MVSW_FW_LOG_LIB_TRUNK,
	MVSW_FW_LOG_LIB_TTI,
	MVSW_FW_LOG_LIB_TUNNEL,
	MVSW_FW_LOG_LIB_VNT,
	MVSW_FW_LOG_LIB_RESOURCE_MANAGER,
	MVSW_FW_LOG_LIB_VERSION,
	MVSW_FW_LOG_LIB_TM,
	MVSW_FW_LOG_LIB_SMI,
	MVSW_FW_LOG_LIB_INIT,
	MVSW_FW_LOG_LIB_DRAGONITE,
	MVSW_FW_LOG_LIB_VIRTUAL_TCAM,
	MVSW_FW_LOG_LIB_INGRESS,
	MVSW_FW_LOG_LIB_EGRESS,
	MVSW_FW_LOG_LIB_LATENCY_MONITORING,
	MVSW_FW_LOG_LIB_TAM,
	MVSW_FW_LOG_LIB_EXACT_MATCH,
	MVSW_FW_LOG_LIB_PHA,
	MVSW_FW_LOG_LIB_PACKET_ANALYZER,
	MVSW_FW_LOG_LIB_FLOW_MANAGER,
	MVSW_FW_LOG_LIB_BRIDGE_FDB_MANAGER,
	MVSW_FW_LOG_LIB_I2C,
	MVSW_FW_LOG_LIB_PPU,
	MVSW_FW_LOG_LIB_EXACT_MATCH_MANAGER,
	MVSW_FW_LOG_LIB_MAC_SEC,
	MVSW_FW_LOG_LIB_ALL,

	MVSW_FW_LOG_LIB_MAX
};

enum {
	MVSW_FW_LOG_TYPE_INFO = 0,
	MVSW_FW_LOG_TYPE_ENTRY_LEVEL_FUNCTION,
	MVSW_FW_LOG_TYPE_ERROR,
	MVSW_FW_LOG_TYPE_ALL,
	MVSW_FW_LOG_TYPE_NONE,

	MVSW_FW_LOG_TYPE_MAX
};

struct mvsw_pr_switch;
struct mvsw_pr_port;
struct mvsw_pr_port_stats;
struct mvsw_pr_port_caps;
struct prestera_acl_rule;
struct mvsw_pr_iface;
struct mvsw_pr_neigh_info;

enum mvsw_pr_event_type;
struct mvsw_pr_event;

/* Switch API */
int mvsw_pr_hw_switch_init(struct mvsw_pr_switch *sw);
int mvsw_pr_hw_switch_ageing_set(const struct mvsw_pr_switch *sw,
				 u32 ageing_time);
int mvsw_pr_hw_switch_mac_set(const struct mvsw_pr_switch *sw, const u8 *mac);
int mvsw_pr_hw_switch_trap_policer_set(const struct mvsw_pr_switch *sw,
				       u8 profile);

/* Port API */
int mvsw_pr_hw_port_info_get(const struct mvsw_pr_port *port,
			     u16 *fp_id, u32 *hw_id, u32 *dev_id);
int mvsw_pr_hw_port_state_set(const struct mvsw_pr_port *port,
			      bool admin_state);
int mvsw_pr_hw_port_state_get(const struct mvsw_pr_port *port,
			      bool *admin_state, bool *oper_state);
int mvsw_pr_hw_port_mtu_set(const struct mvsw_pr_port *port, u32 mtu);
int mvsw_pr_hw_port_mtu_get(const struct mvsw_pr_port *port, u32 *mtu);
int mvsw_pr_hw_port_mac_set(const struct mvsw_pr_port *port, char *mac);
int mvsw_pr_hw_port_mac_get(const struct mvsw_pr_port *port, char *mac);
int mvsw_pr_hw_port_accept_frame_type_set(const struct mvsw_pr_port *port,
					  enum mvsw_pr_accept_frame_type type);
int mvsw_pr_hw_port_learning_set(const struct mvsw_pr_port *port, bool enable);
int mvsw_pr_hw_port_speed_get(const struct mvsw_pr_port *port, u32 *speed);
int mvsw_pr_hw_port_uc_flood_set(const struct mvsw_pr_port *port, bool flood);
int mvsw_pr_hw_port_mc_flood_set(const struct mvsw_pr_port *port, bool flood);
int mvsw_pr_hw_port_cap_get(const struct mvsw_pr_port *port,
			    struct mvsw_pr_port_caps *caps);
int mvsw_pr_hw_port_remote_cap_get(const struct mvsw_pr_port *port,
				   u64 *link_mode_bitmap);
int mvsw_pr_hw_port_remote_fc_get(const struct mvsw_pr_port *port,
				  bool *pause, bool *asym_pause);
int mvsw_pr_hw_port_type_get(const struct mvsw_pr_port *port, u8 *type);
int mvsw_pr_hw_port_fec_get(const struct mvsw_pr_port *port, u8 *fec);
int mvsw_pr_hw_port_fec_set(const struct mvsw_pr_port *port, u8 fec);
int mvsw_pr_hw_port_autoneg_set(const struct mvsw_pr_port *port,
				bool autoneg, u64 link_modes, u8 fec);
int mvsw_pr_hw_port_duplex_get(const struct mvsw_pr_port *port, u8 *duplex);
int mvsw_pr_hw_port_stats_get(const struct mvsw_pr_port *port,
			      struct mvsw_pr_port_stats *stats);
int mvsw_pr_hw_port_link_mode_get(const struct mvsw_pr_port *port,
				  u32 *mode);
int mvsw_pr_hw_port_link_mode_set(const struct mvsw_pr_port *port,
				  u32 mode);
int mvsw_pr_hw_port_mdix_get(const struct mvsw_pr_port *port, u8 *status,
			     u8 *admin_mode);
int mvsw_pr_hw_port_mdix_set(const struct mvsw_pr_port *port, u8 mode);
int mvsw_pr_hw_port_autoneg_restart(struct mvsw_pr_port *port);

/* Vlan API */
int mvsw_pr_hw_vlan_create(const struct mvsw_pr_switch *sw, u16 vid);
int mvsw_pr_hw_vlan_delete(const struct mvsw_pr_switch *sw, u16 vid);
int mvsw_pr_hw_vlan_port_set(const struct mvsw_pr_port *port,
			     u16 vid, bool is_member, bool untagged);
int mvsw_pr_hw_vlan_port_vid_set(const struct mvsw_pr_port *port, u16 vid);

/* FDB API */
int mvsw_pr_hw_fdb_add(const struct mvsw_pr_port *port,
		       const unsigned char *mac, u16 vid, bool dynamic);
int mvsw_pr_hw_fdb_del(const struct mvsw_pr_port *port,
		       const unsigned char *mac, u16 vid);
int mvsw_pr_hw_fdb_flush_port(const struct mvsw_pr_port *port, u32 mode);
int mvsw_pr_hw_fdb_flush_vlan(const struct mvsw_pr_switch *sw, u16 vid,
			      u32 mode);
int mvsw_pr_hw_fdb_flush_port_vlan(const struct mvsw_pr_port *port, u16 vid,
				   u32 mode);
int mvsw_pr_hw_macvlan_add(const struct mvsw_pr_switch *sw, u16 vr_id,
			   const u8 *mac, u16 vid);
int mvsw_pr_hw_macvlan_del(const struct mvsw_pr_switch *sw, u16 vr_id,
			   const u8 *mac, u16 vid);

/* Bridge API */
int mvsw_pr_hw_bridge_create(const struct mvsw_pr_switch *sw, u16 *bridge_id);
int mvsw_pr_hw_bridge_delete(const struct mvsw_pr_switch *sw, u16 bridge_id);
int mvsw_pr_hw_bridge_port_add(const struct mvsw_pr_port *port, u16 bridge_id);
int mvsw_pr_hw_bridge_port_delete(const struct mvsw_pr_port *port,
				  u16 bridge_id);

/* STP API */
int mvsw_pr_hw_port_vid_stp_set(struct mvsw_pr_port *port, u16 vid, u8 state);

/* ACL API */
int mvsw_pr_hw_acl_ruleset_create(const struct mvsw_pr_switch *sw,
				  u16 *ruleset_id);
int mvsw_pr_hw_acl_ruleset_del(const struct mvsw_pr_switch *sw,
			       u16 ruleset_id);
int mvsw_pr_hw_acl_rule_add(const struct mvsw_pr_switch *sw,
			    struct prestera_acl_rule *rule,
			    u32 *rule_id);
int mvsw_pr_hw_acl_rule_del(const struct mvsw_pr_switch *sw, u32 rule_id);
int mvsw_pr_hw_acl_rule_stats_get(const struct mvsw_pr_switch *sw, u32 rule_id,
				  u64 *packets, u64 *bytes);
int mvsw_pr_hw_acl_port_bind(const struct mvsw_pr_port *port, u16 ruleset_id);
int mvsw_pr_hw_acl_port_unbind(const struct mvsw_pr_port *port, u16 ruleset_id);

/* Router API */
int mvsw_pr_hw_rif_create(const struct mvsw_pr_switch *sw,
			  struct mvsw_pr_iface *iif, u8 *mac, u16 *rif_id);
int mvsw_pr_hw_rif_delete(const struct mvsw_pr_switch *sw, u16 rif_id,
			  struct mvsw_pr_iface *iif);
int mvsw_pr_hw_rif_set(const struct mvsw_pr_switch *sw, u16 *rif_id,
		       struct mvsw_pr_iface *iif, u8 *mac);

/* Virtual Router API */
int mvsw_pr_hw_vr_create(const struct mvsw_pr_switch *sw, u16 *vr_id);
int mvsw_pr_hw_vr_delete(const struct mvsw_pr_switch *sw, u16 vr_id);
int mvsw_pr_hw_vr_abort(const struct mvsw_pr_switch *sw, u16 vr_id);

/* LPM API */
int mvsw_pr_hw_lpm_add(const struct mvsw_pr_switch *sw, u16 vr_id,
		       __be32 dst, u32 dst_len, u32 grp_id);
int mvsw_pr_hw_lpm_del(const struct mvsw_pr_switch *sw, u16 vr_id, __be32 dst,
		       u32 dst_len);

/* NH API */
int mvsw_pr_hw_nh_entries_set(const struct mvsw_pr_switch *sw, int count,
			      struct mvsw_pr_neigh_info *nhs, u32 grp_id);
int mvsw_pr_hw_nh_entries_get(const struct mvsw_pr_switch *sw, int count,
			      struct mvsw_pr_neigh_info *nhs, u32 grp_id);
int mvsw_pr_hw_nh_group_create(const struct mvsw_pr_switch *sw, u16 nh_count,
			       u32 *grp_id);
int mvsw_pr_hw_nh_group_delete(const struct mvsw_pr_switch *sw, u16 nh_count,
			       u32 grp_id);

/* MP API */
int mvsw_pr_hw_mp4_hash_set(const struct mvsw_pr_switch *sw, u8 hash_policy);

/* LAG API */
int mvsw_pr_hw_lag_member_add(struct mvsw_pr_port *port, u16 lag_id);
int mvsw_pr_hw_lag_member_del(struct mvsw_pr_port *port, u16 lag_id);
int mvsw_pr_hw_lag_member_enable(struct mvsw_pr_port *port, u16 lag_id,
				 bool enable);
int mvsw_pr_hw_lag_fdb_add(const struct mvsw_pr_switch *sw, u16 lag_id,
			   const unsigned char *mac, u16 vid, bool dynamic);
int mvsw_pr_hw_lag_fdb_del(const struct mvsw_pr_switch *sw, u16 lag_id,
			   const unsigned char *mac, u16 vid);
int mvsw_pr_hw_fdb_flush_lag(const struct mvsw_pr_switch *sw, u16 lag_id,
			     u32 mode);
int mvsw_pr_hw_fdb_flush_lag_vlan(const struct mvsw_pr_switch *sw,
				  u16 lag_id, u16 vid, u32 mode);
int mvsw_pr_hw_lag_member_rif_leave(const struct mvsw_pr_port *port,
				    u16 lag_id, u16 vr_id);

/* Event handlers */
int mvsw_pr_hw_event_handler_register(struct mvsw_pr_switch *sw,
				      enum mvsw_pr_event_type type,
				      void (*cb)(struct mvsw_pr_switch *sw,
						 struct mvsw_pr_event *evt,
						 void *arg),
				      void *arg);

void mvsw_pr_hw_event_handler_unregister(struct mvsw_pr_switch *sw,
					 enum mvsw_pr_event_type type);

/* FW Log API */
int mvsw_pr_hw_fw_log_level_set(const struct mvsw_pr_switch *sw, u32 lib,
				u32 type);

int mvsw_pr_hw_rxtx_init(const struct mvsw_pr_switch *sw, bool use_sdma,
			 u32 *map_addr);

#endif /* _MVSW_PRESTERA_HW_H_ */
