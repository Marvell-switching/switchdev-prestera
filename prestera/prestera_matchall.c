// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include <linux/kernel.h>
#include <linux/list.h>

#include "prestera.h"
#include "prestera_hw.h"
#include "prestera_flower.h"

static int prestera_mall_rule_add(struct prestera_flow_block_binding *binding,
				  struct prestera_port *to_port)
{
	int err;
	u8 span_id;
	struct prestera_switch *sw = binding->port->sw;

	if (binding->span_id != PRESTERA_SPAN_INVALID_ID)
		/* port already in mirroring */
		return -EEXIST;

	err = prestera_span_get(to_port, &span_id);
	if (err)
		return err;

	err = prestera_hw_span_bind(binding->port, span_id);
	if (err) {
		prestera_span_put(sw, span_id);
		return err;
	}

	binding->span_id = span_id;
	return 0;
}

static int prestera_mall_rule_del(struct prestera_flow_block_binding *binding)
{
	int err;

	err = prestera_hw_span_unbind(binding->port);
	if (err)
		return err;

	err = prestera_span_put(binding->port->sw, binding->span_id);
	if (err)
		return err;

	binding->span_id = PRESTERA_SPAN_INVALID_ID;
	return 0;
}

static int prestera_mall_prio_check(struct prestera_flow_block *block,
				    struct tc_cls_matchall_offload *f)
{
	u32 flower_prio;
	int err;

	err = prestera_flower_prio_get(block, &flower_prio);
	if (err == -ENOENT)
		return 0;
	if (err)
		return err;

	if (f->common.prio >= flower_prio)
		return -EOPNOTSUPP;

	return 0;
}

int prestera_mall_prio_get(struct prestera_flow_block *block,
			   u32 *prio)
{
	if (block->mall_prio == UINT_MAX)
		return -ENOENT;

	*prio = block->mall_prio;
	return 0;
}

static void prestera_mall_prio_update(struct prestera_flow_block *block,
				      struct tc_cls_matchall_offload *f)
{
	if (f->common.prio > block->mall_prio || block->mall_prio == UINT_MAX)
		block->mall_prio = f->common.prio;
}

int prestera_mall_replace(struct prestera_flow_block *block,
			  struct tc_cls_matchall_offload *f)
{
	struct prestera_flow_block_binding *binding;
	__be16 protocol = f->common.protocol;
	struct flow_action_entry *act;
	struct prestera_port *port;
	int err;

	if (!flow_offload_has_one_action(&f->rule->action)) {
		NL_SET_ERR_MSG(f->common.extack,
			       "Only singular actions are supported");
		return -EOPNOTSUPP;
	}

	act = &f->rule->action.entries[0];

	if (act->id != FLOW_ACTION_MIRRED)
		return -EOPNOTSUPP;

	if (protocol != htons(ETH_P_ALL))
		return -EOPNOTSUPP;

	err = prestera_mall_prio_check(block, f);
	if (err)
		return err;

	if (!prestera_netdev_check(act->dev)) {
		NL_SET_ERR_MSG(f->common.extack,
			       "Only switchdev port is supported");
		return -EINVAL;
	}

	port = netdev_priv(act->dev);
	list_for_each_entry(binding, &block->binding_list, list) {
		err = prestera_mall_rule_add(binding, port);
		if (err == -EEXIST)
			return err;
		if (err)
			goto rollback;
	}

	prestera_mall_prio_update(block, f);

	return 0;

rollback:
	list_for_each_entry_continue_reverse(binding,
					     &block->binding_list, list)
		prestera_mall_rule_del(binding);
	return err;
}

void prestera_mall_destroy(struct prestera_flow_block *block)
{
	struct prestera_flow_block_binding *binding;

	list_for_each_entry(binding, &block->binding_list, list)
		prestera_mall_rule_del(binding);

	block->mall_prio = UINT_MAX;
}

