/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved. */

#ifndef _PRESTERA_ACL_H_
#define _PRESTERA_ACL_H_

#include <linux/types.h>
#include "prestera_ct.h"
#include "prestera_counter.h"

#define PRESTERA_ACL_RULE_DEF_HW_CHAIN_ID	0

#define PRESTERA_ACL_KEYMASK_PCL_ID		0x3FF
#define PRESTERA_ACL_KEYMASK_PCL_ID_USER			\
	(PRESTERA_ACL_KEYMASK_PCL_ID & 0x00FF)
#define PRESTERA_ACL_KEYMASK_PCL_ID_CHAIN			\
	(PRESTERA_ACL_KEYMASK_PCL_ID & 0xFF00)
#define PRESTERA_ACL_CHAIN_MASK					\
	(PRESTERA_ACL_KEYMASK_PCL_ID >> 8)

#define PRESTERA_ACL_PCL_ID_MAKE(uid, chain_id)			\
	(((uid) & PRESTERA_ACL_KEYMASK_PCL_ID_USER) |		\
	(((chain_id) << 8) & PRESTERA_ACL_KEYMASK_PCL_ID_CHAIN))

#define rule_flag_set(rule, flag) \
	prestera_acl_rule_flag_set(rule, PRESTERA_ACL_RULE_FLAG_##flag)
#define rule_flag_test(rule, flag) \
	prestera_acl_rule_flag_test(rule, PRESTERA_ACL_RULE_FLAG_##flag)

#define rule_match_set_n(match_p, type, val_p, size)		\
	memcpy(&(match_p)[PRESTERA_ACL_RULE_MATCH_TYPE_##type],	\
	       val_p, size)
#define rule_match_set(match_p, type, val)			\
	memcpy(&(match_p)[PRESTERA_ACL_RULE_MATCH_TYPE_##type],	\
	       &(val), sizeof(val))
#define rule_match_set_u32(match_p, type, val)			\
	((match_p)[PRESTERA_ACL_RULE_MATCH_TYPE_##type] =	\
	       htonl(val))
#define rule_match_set_u16(match_p, type, val)			\
	((match_p)[PRESTERA_ACL_RULE_MATCH_TYPE_##type] =	\
	       (__force __be32)htons(val))
#define rule_match_set_u8(match_p, type, val)			\
	((match_p)[PRESTERA_ACL_RULE_MATCH_TYPE_##type] =	\
	       (__force __be32)(val))
#define rule_match_get_u32(match_p, type)			\
	(match_p[PRESTERA_ACL_RULE_MATCH_TYPE_##type])

#define MVSW_ACL_RULE_DEF_HW_CHAIN_ID	0
#define MVSW_ACL_RULESET_ALL		0xff

#define PRESTERA_ACL_ACTION_MAX 8

/* HW objects infrastructure */
struct prestera_mangle_cfg {
	u8 l4_src_valid:1, l4_dst_valid:1,
	   sip_valid:1, dip_valid:1;
	__be16 l4_src;
	__be16 l4_dst;
	struct prestera_ip_addr sip;
	struct prestera_ip_addr dip;
};

/* TODO: Move mangle_entry to router ? */
struct prestera_nh_mangle_entry {
	struct rhash_head ht_node; /* node of prestera_router */
	struct prestera_nh_mangle_entry_key {
		struct prestera_mangle_cfg mangle;
		struct prestera_nh_neigh_key n;
	} key;
	struct prestera_nh_neigh *n;
	u32 hw_id;
	unsigned long is_active_hw_cache_kick; /* jiffies */
	bool is_active_hw_cache;
	u32 ref_cnt;
	struct list_head nh_neigh_head;
};

struct prestera_acl_rule_entry {
	struct rhash_head ht_node; /* node of prestera_sw */
	struct prestera_acl_rule_entry_key {
		u32 prio;
		struct prestera_acl_match match;
	} key;
	u32 hw_id;
	u32 vtcam_id;
	/* This struct seems to be dublicate of arg, but purpose is to pass
	 * in cfg objet keys, resolve them and save object links here.
	 * E.g. chain can be link to object, when chain_id just key in cfg.
	 */
	struct {
		struct {
			u8 valid:1;
		} accept, drop;
		struct {
			u8 valid:1;
			struct prestera_acl_action_trap i;
		} trap;
		struct {
			u8 valid:1;
			struct prestera_acl_action_police i;
		} police;
		struct {
			u8 valid:1;
			struct prestera_acl_action_nat i;
		} nat;
		struct {
			u8 valid:1;
			struct prestera_acl_action_jump i;
		} jump;
		struct {
			u8 valid:1;
			struct prestera_nh_mangle_entry *e; /* entry */
		} nh;
		struct {
			u32 id;
			struct prestera_counter_block *block;
		} counter;
		struct {
			u8 valid:1;
			struct prestera_acl_action_remark i;
		} remark;
	};
};

/* This struct (arg) used only to be passed as parameter for
 * acl_rule_entry_create. Must be flat. Can contain object keys, which will be
 * resolved to object links, before saving to acl_rule_entry struct
 */
struct prestera_acl_rule_entry_arg {
	u32 vtcam_id;
	struct {
		struct {
			u8 valid:1;
		} accept, drop;
		struct {
			u8 valid:1;
			struct prestera_acl_action_trap i;
		} trap;
		struct {
			u8 valid:1;
			struct prestera_acl_action_police i;
		} police;
		struct {
			u8 valid:1;
			struct prestera_acl_action_nat i;
		} nat;
		struct {
			u8 valid:1;
			struct prestera_acl_action_jump i;
		} jump;
		struct {
			u8 valid:1;
			struct prestera_nh_mangle_entry_key k; /* key */
		} nh;
		struct {
			u8 valid:1;
			u32 client;
		} count;
		struct {
			u8 valid:1;
			struct prestera_acl_action_remark i;
		} remark;
	};
};

enum {
	PRESTERA_ACL_RULE_FLAG_CT,
	PRESTERA_ACL_RULE_FLAG_GOTO,
	PRESTERA_ACL_RULE_FLAG_NAT
};

struct prestera_acl_stats {
	u64 packets;
	u64 bytes;
};

struct prestera_acl {
	struct prestera_switch *sw;
	struct list_head nat_port_list;
	struct list_head vtcam_list;
	struct list_head rules;
	struct rhashtable ruleset_ht;
	struct rhashtable acl_rule_entry_ht;
	/* TODO: move nh_mangle_entry_ht to router ? */
	struct rhashtable nh_mangle_entry_ht;
	struct prestera_ct_priv *ct_priv;
	struct idr uid;
};

struct prestera_acl_nat_port {
	struct list_head list;
	struct prestera_port *port;
	refcount_t refcount;
};

struct prestera_acl_rule_attr {
	struct prestera_ct_attr ct_attr;
	unsigned long flags;
};

struct prestera_acl_rule {
	struct rhash_head ht_node; /* Member of acl HT */
	struct list_head list;
	struct prestera_acl_nat_port *nat_port;
	struct prestera_acl_rule_attr attr;
	struct prestera_acl_ruleset *ruleset;
	struct prestera_acl_ruleset *jump_ruleset;
	unsigned long cookie;
	u32 chain_index;
	u32 priority;
	u8 hw_tc;
	struct prestera_acl_rule_entry_key re_key;
	struct prestera_acl_rule_entry_arg re_arg;
	struct prestera_acl_rule_entry *re;
};

enum {
	PRESTERA_ACL_IFACE_TYPE_PORT,
	PRESTERA_ACL_IFACE_TYPE_INDEX
};

struct prestera_acl_iface {
	u8 type;
	union {
		struct prestera_port *port;
		u32 index;
	};
};

void prestera_acl_rule_flag_set(struct prestera_acl_rule *rule,
				unsigned long flag);
bool
prestera_acl_rule_flag_test(const struct prestera_acl_rule *rule,
			    unsigned long flag);
struct prestera_acl_rule *
prestera_acl_rule_create(struct prestera_acl_ruleset *ruleset,
			 unsigned long cookie, u32 chain_index);
void prestera_acl_rule_priority_set(struct prestera_acl_rule *rule,
				    u32 priority);
u8 prestera_acl_rule_hw_tc_get(struct prestera_acl_rule *rule);
void prestera_acl_rule_hw_tc_set(struct prestera_acl_rule *rule, u8 hw_tc);
u8 prestera_acl_rule_hw_chain_id_get(const struct prestera_acl_rule *rule);
void prestera_acl_rule_destroy(struct prestera_acl_rule *rule);
struct prestera_acl_rule *
prestera_acl_rule_lookup(struct prestera_acl_ruleset *ruleset,
			 unsigned long cookie);
int prestera_acl_rule_add(struct prestera_switch *sw,
			  struct prestera_acl_rule *rule);
void prestera_acl_rule_del(struct prestera_switch *sw,
			   struct prestera_acl_rule *rule);
int prestera_acl_rule_get_stats(struct prestera_acl *acl,
				struct prestera_acl_rule *rule,
				u64 *packets, u64 *bytes, u64 *last_use);

int prestera_nh_mangle_entry_set(struct prestera_switch *sw,
				 struct prestera_nh_mangle_entry *e);
bool prestera_nh_mangle_entry_util_hw_state(struct prestera_switch *sw,
					    struct prestera_nh_mangle_entry *e);
struct prestera_acl_rule_entry *
prestera_acl_rule_entry_find(struct prestera_acl *acl,
			     struct prestera_acl_rule_entry_key *key);
void prestera_acl_rule_entry_destroy(struct prestera_acl *acl,
				     struct prestera_acl_rule_entry *e);
struct prestera_acl_rule_entry *
prestera_acl_rule_entry_create(struct prestera_acl *acl,
			       struct prestera_acl_rule_entry_key *key,
			       struct prestera_acl_rule_entry_arg *arg);
struct prestera_acl_ruleset *
prestera_acl_ruleset_get(struct prestera_acl *acl,
			 struct prestera_flow_block *block,
			 u32 chain_index);
struct prestera_acl_ruleset *
prestera_acl_ruleset_lookup(struct prestera_acl *acl,
			    struct prestera_flow_block *block,
			    u32 chain_index);
void prestera_acl_ruleset_keymask_set(struct prestera_acl_ruleset *ruleset,
				      void *keymask);
int prestera_acl_ruleset_offload(struct prestera_acl_ruleset *ruleset);
u32 prestera_acl_ruleset_index_get(const struct prestera_acl_ruleset *ruleset);
bool prestera_acl_ruleset_is_offload(struct prestera_acl_ruleset *ruleset);
void prestera_acl_ruleset_put(struct prestera_acl_ruleset *ruleset);
int prestera_acl_ruleset_bind(struct prestera_acl_ruleset *ruleset,
			      struct prestera_port *port);
int prestera_acl_ruleset_unbind(struct prestera_acl_ruleset *ruleset,
				struct prestera_port *port);
void
prestera_acl_rule_keymask_pcl_id_set(struct prestera_acl_rule *rule,
				     u16 pcl_id);
int prestera_acl_vtcam_id_get(struct prestera_acl *acl, u8 lookup, u8 dir,
			      void *keymask, u32 *vtcam_id);
int prestera_acl_vtcam_id_put(struct prestera_acl *acl, u32 vtcam_id);
int prestera_acl_chain_to_client(u32 chain_index, bool ingress, u32 *client);

#endif /* _PRESTERA_ACL_H_ */
