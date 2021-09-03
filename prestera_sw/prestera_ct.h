/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved. */

#ifndef _PRESTERA_CT_H_
#define _PRESTERA_CT_H_

#include <linux/types.h>
#include <linux/netlink.h>
#include <net/flow_offload.h>

struct prestera_switch;
struct prestera_ct_ft;
struct prestera_ct_priv;

struct prestera_ct_attr {
	u16 zone;
	u16 ct_action;
	struct net *net;
	struct prestera_ct_ft *ft;
	struct nf_flowtable *nf_ft;
};

struct prestera_ct_priv *prestera_ct_init(struct prestera_acl *acl);
void prestera_ct_clean(struct prestera_ct_priv *ct_priv);

/* match & action */
int prestera_ct_match_parse(struct flow_cls_offload *f,
			    struct netlink_ext_ack *extack);
int prestera_ct_parse_action(const struct flow_action_entry *act,
			     struct prestera_acl_rule *rule,
			     struct netlink_ext_ack *extack);

/* flowtable */
int prestera_ct_ft_offload_add_cb(struct prestera_switch *sw,
				  struct prestera_acl_rule *rule);
void prestera_ct_ft_offload_del_cb(struct prestera_switch *sw,
				   struct prestera_acl_rule *rule);

#endif /* _PRESTERA_CT_H_ */
