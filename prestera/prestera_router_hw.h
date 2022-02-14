/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved. */

#ifndef _PRESTERA_ROUTER_HW_H_
#define _PRESTERA_ROUTER_HW_H_

/* TODO: move structures, that not used from external to .c file */

struct prestera_vr {
	u16 hw_vr_id;			/* virtual router ID */
	u32 tb_id;			/* key (kernel fib table id) */
	struct list_head router_node;
	unsigned int ref_cnt;
};

struct prestera_rif_macvlan_list_node {
	struct list_head head;
	unsigned char addr[ETH_ALEN];
};

/* Add port to vlan + FDB ... or only FDB for vlan */
struct prestera_rif_entry {
	struct prestera_rif_entry_key {
		struct prestera_iface iface;
	} key;
	struct prestera_vr *vr;
	unsigned char addr[ETH_ALEN];
	struct list_head macvlan_list;
	u16 hw_id; /* rif_id */
	struct list_head router_node; /* ht */
};

struct prestera_nexthop_group {
	struct prestera_nexthop_group_key key;
	/* Store intermediate object here.
	 * This prevent overhead kzalloc call.
	 */
	/* nh_neigh is used only to notify nexthop_group */
	struct prestera_nh_neigh_head {
		struct prestera_nexthop_group *this;
		struct list_head head;
		/* ptr to neigh is not necessary.
		 * It used to prevent lookup of nh_neigh by key (n) on destroy
		 */
		struct prestera_nh_neigh *neigh;
	} nh_neigh_head[PRESTERA_NHGR_SIZE_MAX];
	u32 grp_id; /* hw */
	struct rhash_head ht_node; /* node of prestera_vr */
	unsigned int ref_cnt;
};

struct prestera_fib_key {
	struct prestera_ip_addr addr;
	u32 prefix_len;
	u32 tb_id;
};

struct prestera_fib_info {
	struct prestera_vr *vr;
	struct list_head vr_node;
	enum prestera_fib_type {
		PRESTERA_FIB_TYPE_INVALID = 0,
		/* must be pointer to nh_grp id */
		PRESTERA_FIB_TYPE_UC_NH,
		/* It can be connected route
		 * and will be overlapped with neighbours
		 */
		PRESTERA_FIB_TYPE_TRAP,
		PRESTERA_FIB_TYPE_DROP
	} type;
	/* Valid only if type = UC_NH*/
	struct prestera_nexthop_group *nh_grp;
};

struct prestera_fib_node {
	struct rhash_head ht_node; /* node of prestera_vr */
	struct prestera_fib_key key;
	struct prestera_fib_info info; /* action related info */
};

int prestera_rif_entry_set_macvlan(const struct prestera_switch *sw,
				   struct prestera_rif_entry *e,
				   bool enable, const char *addr);
struct prestera_rif_entry *
prestera_rif_entry_find(const struct prestera_switch *sw,
			const struct prestera_rif_entry_key *k);
void prestera_rif_entry_destroy(struct prestera_switch *sw,
				struct prestera_rif_entry *e);
void prestera_rif_entry_destroy_ht(struct prestera_switch *sw);
struct prestera_rif_entry *
prestera_rif_entry_create(struct prestera_switch *sw,
			  struct prestera_rif_entry_key *k,
			  u32 tb_id, unsigned char *addr);
void prestera_vr_util_hw_abort(struct prestera_switch *sw);
int prestera_router_hw_init(struct prestera_switch *sw);
void prestera_router_hw_fini(struct prestera_switch *sw);
struct prestera_nh_neigh *
prestera_nh_neigh_find(struct prestera_switch *sw,
		       struct prestera_nh_neigh_key *key);
struct prestera_nh_neigh *
prestera_nh_neigh_get(struct prestera_switch *sw,
		      struct prestera_nh_neigh_key *key);
void prestera_nh_neigh_put(struct prestera_switch *sw,
			   struct prestera_nh_neigh *neigh);
int prestera_nh_neigh_set(struct prestera_switch *sw,
			  struct prestera_nh_neigh *neigh);
bool prestera_nh_neigh_util_hw_state(struct prestera_switch *sw,
				     struct prestera_nh_neigh *nh_neigh);
struct prestera_fib_node *
prestera_fib_node_find(struct prestera_switch *sw, struct prestera_fib_key *key);
void prestera_fib_node_destroy(struct prestera_switch *sw,
			       struct prestera_fib_node *fib_node);
void prestera_fib_node_destroy_ht(struct prestera_switch *sw);
struct prestera_fib_node *
prestera_fib_node_create(struct prestera_switch *sw,
			 struct prestera_fib_key *key,
			 enum prestera_fib_type fib_type,
			 struct prestera_nexthop_group_key *nh_grp_key);

#endif /* _PRESTERA_ROUTER_HW_H_ */
