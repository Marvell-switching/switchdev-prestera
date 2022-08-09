// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include <linux/netlink.h>
#include <net/flow_offload.h>

#include "prestera.h"
#include "prestera_hw.h"
#include "prestera_qdisc.h"

#define PRESTERA_PRIO_BAND_TO_TCLASS(band) (IEEE_8021QAZ_MAX_TCS - (band) - 1)

struct prestera_qdisc_sched_info {
	struct {
		u32 sdwrr_weight;
		bool sdwrr;
	} tc[IEEE_8021QAZ_MAX_TCS];
};

struct prestera_qdisc_sched {
	struct list_head list;
	struct prestera_qdisc_sched_info info;
	refcount_t refcount;
	u32 id;
};

struct prestera_qdisc_ets_band {
	int tclass_num;
};

struct prestera_qdisc_ets_data {
	struct prestera_qdisc_ets_band bands[IEEE_8021QAZ_MAX_TCS];
	struct prestera_qdisc_sched *sched;
	u32 default_sched_id;
};

struct prestera_qdisc;
struct prestera_qdisc_ops {
	int (*check)(void *params);
	int (*replace)(struct prestera_port *port, u32 handle,
		       struct prestera_qdisc *qdisc, void *params);
	int (*destroy)(struct prestera_port *port,
		       struct prestera_qdisc *qdisc);
	int (*get_stats)(struct prestera_port *port,
			 struct prestera_qdisc *qdisc,
			 struct tc_qopt_offload_stats *stats_ptr);
	struct prestera_qdisc *(*find_class)(struct prestera_qdisc *qdisc,
					     u32 parent);
	int (*get_tclass_num)(struct prestera_qdisc *qdisc,
			      struct prestera_qdisc *child);
	unsigned int num_classes;
};

struct prestera_qdisc {
	struct prestera_qdisc *qdiscs;
	struct prestera_qdisc *parent;
	struct prestera_qdisc_ops *ops;
	union {
		struct prestera_qdisc_ets_data *ets_data;
	};
	unsigned int num_classes;
	u32 handle;
};

struct prestera_qdisc_port {
	struct mutex lock;  /* Protects qdisc */
	struct prestera_qdisc root_qdisc;
};

static int prestera_qdisc_sched_put(struct prestera_switch *sw,
				    struct prestera_qdisc_sched *sched)
{
	int err;

	if (!refcount_dec_and_test(&sched->refcount))
		return 0;

	err = prestera_hw_sched_release(sw, sched->id);
	if (err)
		return err;

	list_del(&sched->list);
	kfree(sched);
	return 0;
}

static int
prestera_qdisc_sched_info_cmp(struct prestera_qdisc_sched_info *info1,
			      struct prestera_qdisc_sched_info *info2)
{
	unsigned int i, sched_match = 0;

	for (i = 0; i < ARRAY_SIZE(info1->tc); i++) {
		if (info1->tc[i].sdwrr != info2->tc[i].sdwrr)
			break;

		if (info1->tc[i].sdwrr &&
		    info1->tc[i].sdwrr_weight != info2->tc[i].sdwrr_weight)
			break;

		sched_match++;
	}

	return !(sched_match == ARRAY_SIZE(info1->tc));
}

static int prestera_qdisc_sched_set(struct prestera_port *port, u8 tc,
				    u32 sched_id, bool sdwrr, u8 sdwrr_weight)
{
	if (!sdwrr)
		return prestera_hw_sched_sp_set(port, tc, sched_id);

	return prestera_hw_sched_sdwrr_set(port, tc, sched_id, sdwrr_weight);
}

static struct prestera_qdisc_sched *
prestera_qdisc_sched_get(struct prestera_port *port,
			 struct prestera_qdisc_sched_info *sched_info)
{
	struct prestera_qdisc_sched *sched;
	int err, i;

	list_for_each_entry(sched, &port->sw->sched_list, list)
		if (!prestera_qdisc_sched_info_cmp(&sched->info, sched_info)) {
			refcount_inc(&sched->refcount);
			return sched;
		}

	sched = kzalloc(sizeof(*sched), GFP_KERNEL);
	if (!sched)
		return ERR_PTR(-ENOMEM);

	err = prestera_hw_sched_create(port->sw, &sched->id);
	if (err)
		goto err_sched_create;

	refcount_set(&sched->refcount, 1);
	list_add_rcu(&sched->list, &port->sw->sched_list);

	for (i = 0; i < ARRAY_SIZE(sched->info.tc); i++) {
		sched->info.tc[i].sdwrr = sched_info->tc[i].sdwrr;
		sched->info.tc[i].sdwrr_weight = sched_info->tc[i].sdwrr_weight;
		err = prestera_qdisc_sched_set(port, i, sched->id,
					       sched->info.tc[i].sdwrr,
					       sched->info.tc[i].sdwrr_weight);
		if (err) {
			prestera_qdisc_sched_put(port->sw, sched);
			return ERR_PTR(err);
		}
	}

	return sched;

err_sched_create:
	kfree(sched);
	return ERR_PTR(err);
}

static struct prestera_qdisc *
prestera_qdisc_find(struct prestera_port *port, u32 parent)
{
	struct prestera_qdisc_port *qdisc_port = port->qdisc;
	struct prestera_qdisc *qdisc;

	if (!qdisc_port)
		return NULL;

	qdisc = &qdisc_port->root_qdisc;
	if (parent == TC_H_ROOT)
		return qdisc;

	if (qdisc->ops && TC_H_MAJ(qdisc->handle) == TC_H_MAJ(parent)) {
		if (qdisc->ops->find_class)
			return qdisc->ops->find_class(qdisc, parent);
	}

	return NULL;
}

static void prestera_qdisc_cleanup(struct prestera_qdisc *qdisc)
{
	qdisc->handle = TC_H_UNSPEC;
	qdisc->num_classes = 0;
	qdisc->ops = NULL;
	kfree(qdisc->qdiscs);
	qdisc->qdiscs = NULL;
}

static int prestera_qdisc_create(struct prestera_port *port,
				 u32 handle, struct prestera_qdisc *qdisc,
				 struct prestera_qdisc_ops *ops, void *params)
{
	unsigned int i;
	int err;

	if (ops->check) {
		err = ops->check(params);
		if (err)
			return err;
	}

	if (ops->num_classes) {
		qdisc->qdiscs = kcalloc(ops->num_classes,
					sizeof(*qdisc->qdiscs), GFP_KERNEL);
		if (!qdisc->qdiscs)
			return -ENOMEM;

		for (i = 0; i < ops->num_classes; i++)
			qdisc->qdiscs[i].parent = qdisc;
	}

	qdisc->num_classes = ops->num_classes;
	qdisc->ops = ops;
	qdisc->handle = handle;

	err = ops->replace(port, handle, qdisc, params);
	if (err)
		goto err_replace;

	return 0;

err_replace:
	prestera_qdisc_cleanup(qdisc);
	return err;
}

static int
prestera_qdisc_replace(struct prestera_port *port,
		       u32 handle, struct prestera_qdisc *qdisc,
		       struct prestera_qdisc_ops *ops, void *params)
{
	if (!qdisc->ops)
		return prestera_qdisc_create(port, handle, qdisc, ops, params);

	/* qdisc change is not supported for now */
	return -EOPNOTSUPP;
}

static int
prestera_qdisc_destroy(struct prestera_port *port,
		       struct prestera_qdisc *qdisc)
{
	int err = 0;
	int i;

	if (!qdisc->ops)
		return 0;

	for (i = 0; i < qdisc->num_classes; i++)
		prestera_qdisc_destroy(port, &qdisc->qdiscs[i]);

	if (qdisc->ops->destroy)
		err = qdisc->ops->destroy(port, qdisc);

	prestera_qdisc_cleanup(qdisc);
	return err;
}

static int
prestera_qdisc_get_stats(struct prestera_port *port,
			 struct prestera_qdisc *qdisc,
			 struct tc_qopt_offload_stats *stats_ptr)
{
	if (qdisc && qdisc->ops && qdisc->ops->get_stats)
		return qdisc->ops->get_stats(port, qdisc, stats_ptr);

	return -EOPNOTSUPP;
}

static int prestera_qdisc_graft(struct prestera_port *port,
				struct prestera_qdisc *qdisc,
				u8 band, u32 child_handle)
{
	if (band < qdisc->num_classes &&
	    qdisc->qdiscs[band].handle == child_handle)
		return 0;

	if (!child_handle)
		/* This is an invisible FIFO replacing the original Qdisc */
		return 0;

	return -EOPNOTSUPP;
}

static int prestera_qdisc_get_tclass_num(struct prestera_qdisc *qdisc)
{
	struct prestera_qdisc *parent = qdisc->parent;

	if (!parent->ops->get_tclass_num)
		return prestera_qdisc_get_tclass_num(parent);

	return parent->ops->get_tclass_num(parent, qdisc);
}

static int prestera_qdisc_ets_check(void *params)
{
	struct tc_ets_qopt_offload_replace_params *p = params;
	u8 i, prio2bandmap[] = { 7, 6, 5, 4, 3, 2, 1, 0 };

	if (p->bands != IEEE_8021QAZ_MAX_TCS)
		return -EOPNOTSUPP;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++)
		if (prio2bandmap[i] != p->priomap[i])
			return -EOPNOTSUPP;

	return 0;
}

static int
prestera_qdisc_ets_replace(struct prestera_port *port, u32 handle,
			   struct prestera_qdisc *qdisc, void *params)
{
	struct prestera_qdisc_ets_data *ets_data = qdisc->ets_data;
	struct tc_ets_qopt_offload_replace_params *p = params;
	struct prestera_qdisc_sched_info sched_info;
	int err, band, tclass_num;

	if (!ets_data) {
		ets_data = kzalloc(sizeof(*ets_data), GFP_KERNEL);
		if (!ets_data)
			return -ENOMEM;

		qdisc->ets_data = ets_data;
		for (band = 0; band < qdisc->num_classes; band++) {
			tclass_num = PRESTERA_PRIO_BAND_TO_TCLASS(band);
			ets_data->bands[band].tclass_num = tclass_num;
		}
	}

	for (band = 0; band < p->bands; band++) {
		tclass_num = ets_data->bands[band].tclass_num;
		sched_info.tc[tclass_num].sdwrr = !!p->quanta[band];
		sched_info.tc[tclass_num].sdwrr_weight = p->weights[band];
	}

	ets_data->sched = prestera_qdisc_sched_get(port, &sched_info);
	if (IS_ERR(ets_data->sched))
		goto err_sched_port_get;

	err = prestera_hw_sched_port_get(port, &ets_data->default_sched_id);
	if (err)
		goto err_sched_get;

	err = prestera_hw_sched_port_set(port, ets_data->sched->id);
	if (err)
		goto err_sched_port_band_set;

	return 0;

err_sched_port_band_set:
	WARN_ON(prestera_hw_sched_port_set(port, ets_data->default_sched_id));
err_sched_get:
	WARN_ON(prestera_qdisc_sched_put(port->sw, ets_data->sched));

err_sched_port_get:
	qdisc->ets_data = NULL;
	kfree(ets_data);
	return err;
}

static int prestera_qdisc_ets_destroy(struct prestera_port *port,
				      struct prestera_qdisc *qdisc)
{
	struct prestera_qdisc_ets_data *ets_data = qdisc->ets_data;
	int err;

	err = prestera_hw_sched_port_set(port, ets_data->default_sched_id);
	if (err)
		return err;

	err = prestera_qdisc_sched_put(port->sw, ets_data->sched);
	if (err)
		return err;

	qdisc->ets_data = NULL;
	kfree(ets_data);
	return 0;
}

static int
prestera_qdisc_ets_get_tclass_num(struct prestera_qdisc *parent,
				  struct prestera_qdisc *child)
{
	unsigned int band = child - parent->qdiscs;

	WARN_ON(band >= IEEE_8021QAZ_MAX_TCS);
	return parent->ets_data->bands[band].tclass_num;
}

static struct prestera_qdisc *
prestera_qdisc_ets_find_class(struct prestera_qdisc *qdisc, u32 parent)
{
	int child_index = TC_H_MIN(parent);
	int band = child_index - 1;

	if (band < 0 || band >= qdisc->num_classes)
		return NULL;

	return &qdisc->qdiscs[band];
}

static int prestera_qdisc_ets_stats_get(struct prestera_port *port,
					struct prestera_qdisc *qdisc,
					struct tc_qopt_offload_stats *stats_ptr)
{
	return 0;
}

static u32
prestera_qdisc_tbf_burst(struct tc_tbf_qopt_offload_replace_params *p)
{
	/* burst is configured in units of 4K bytes */
	return p->max_size / 4096;
}

static u64
prestera_qdisc_tbf_rate_kbps(struct tc_tbf_qopt_offload_replace_params *p)
{
	/* rate is configured in Kbps */
	return div_u64(p->rate.rate_bytes_ps, 1000) * 8;
}

static int prestera_qdisc_tbf_replace(struct prestera_port *port,
				      u32 handle, struct prestera_qdisc *qdisc,
				      void *params)
{
	struct tc_tbf_qopt_offload_replace_params *p = params;
	int tclass_num;
	u32 burst;
	u32 rate;

	burst = prestera_qdisc_tbf_burst(p);
	rate = (u32)prestera_qdisc_tbf_rate_kbps(p);
	tclass_num = prestera_qdisc_get_tclass_num(qdisc);

	return prestera_hw_shaper_port_queue_configure(port, tclass_num, rate, burst);
}

static int prestera_qdisc_tbf_destroy(struct prestera_port *port,
				      struct prestera_qdisc *qdisc)
{
	int tclass_num;

	tclass_num = prestera_qdisc_get_tclass_num(qdisc);
	return prestera_hw_shaper_port_queue_disable(port, tclass_num);
}

static int prestera_qdisc_tc_stats_get(struct prestera_port *port, u8 tc,
				       struct tc_qopt_offload_stats *stats_ptr)
{
	u64 pkts, bytes, drops;
	int err;

	err = prestera_hw_port_queue_stats_get(port, tc, &pkts, &bytes, &drops);
	if (err)
		return err;

	_bstats_update(stats_ptr->bstats, bytes, pkts);
	stats_ptr->qstats->drops += drops;

	return 0;
}

static int prestera_qdisc_tbf_stats_get(struct prestera_port *port,
					struct prestera_qdisc *qdisc,
					struct tc_qopt_offload_stats *stats_ptr)
{
	int tclass_num;

	tclass_num = prestera_qdisc_get_tclass_num(qdisc);
	return prestera_qdisc_tc_stats_get(port, tclass_num, stats_ptr);
}

static int prestera_qdisc_red_check(void *params)
{
	struct tc_red_qopt_offload_params *p = params;

	if (p->min > p->max)
		return -EINVAL;

	if (p->min == 0 || p->max == 0)
		return -EINVAL;

	return 0;
}

static int prestera_qdisc_red_replace(struct prestera_port *port,
				      u32 handle, struct prestera_qdisc *qdisc,
				      void *params)
{
	struct tc_red_qopt_offload_params *p = params;
	int tclass_num;
	u64 prob;

	/* calculate probability as a percentage */
	prob = p->probability;
	prob *= 100;
	prob = DIV_ROUND_UP(prob, 1 << 16);
	prob = DIV_ROUND_UP(prob, 1 << 16);

	tclass_num = prestera_qdisc_get_tclass_num(qdisc);

	return prestera_hw_wred_port_queue_enable(port, tclass_num, p->min,
						  p->max, (u32)prob);
}

static int prestera_qdisc_red_destroy(struct prestera_port *port,
				      struct prestera_qdisc *qdisc)
{
	int tclass_num;

	tclass_num = prestera_qdisc_get_tclass_num(qdisc);
	return prestera_hw_wred_port_queue_disable(port, tclass_num);
}

static struct prestera_qdisc_ops prestera_qdisc_ets_ops = {
	.check = prestera_qdisc_ets_check,
	.replace = prestera_qdisc_ets_replace,
	.destroy = prestera_qdisc_ets_destroy,
	.get_tclass_num = prestera_qdisc_ets_get_tclass_num,
	.find_class = prestera_qdisc_ets_find_class,
	.get_stats = prestera_qdisc_ets_stats_get,
	.num_classes = IEEE_8021QAZ_MAX_TCS
};

static int __prestera_setup_tc_ets(struct prestera_port *port,
				   struct tc_ets_qopt_offload *p)
{
	struct prestera_qdisc *qdisc;

	qdisc = prestera_qdisc_find(port, p->parent);
	if (!qdisc)
		return -EOPNOTSUPP;

	if (p->command == TC_ETS_REPLACE)
		return prestera_qdisc_replace(port, p->handle, qdisc,
					      &prestera_qdisc_ets_ops,
					      &p->replace_params);

	if (qdisc->handle != p->handle)
		return -EOPNOTSUPP;

	switch (p->command) {
	case TC_ETS_DESTROY:
		return prestera_qdisc_destroy(port, qdisc);
	case TC_ETS_STATS:
		return prestera_qdisc_get_stats(port, qdisc, &p->stats);
	case TC_ETS_GRAFT:
		return prestera_qdisc_graft(port, qdisc, p->graft_params.band,
					    p->graft_params.child_handle);
	default:
		return -EOPNOTSUPP;
	}
}

int prestera_setup_tc_ets(struct prestera_port *port,
			  struct tc_ets_qopt_offload *p)
{
	int err;

	mutex_lock(&port->qdisc->lock);
	err = __prestera_setup_tc_ets(port, p);
	mutex_unlock(&port->qdisc->lock);

	return err;
}

static struct prestera_qdisc_ops prestera_qdisc_tbf_ops = {
	.replace = prestera_qdisc_tbf_replace,
	.destroy = prestera_qdisc_tbf_destroy,
	.get_stats = prestera_qdisc_tbf_stats_get
};

static int __prestera_setup_tc_tbf(struct prestera_port *port,
				   struct tc_tbf_qopt_offload *p)
{
	struct prestera_qdisc *qdisc;

	qdisc = prestera_qdisc_find(port, p->parent);
	if (!qdisc)
		return -EOPNOTSUPP;

	if (p->command == TC_TBF_REPLACE)
		return prestera_qdisc_replace(port, p->handle, qdisc,
					      &prestera_qdisc_tbf_ops,
					      &p->replace_params);

	if (qdisc->handle != p->handle)
		return -EOPNOTSUPP;

	switch (p->command) {
	case TC_TBF_DESTROY:
		return prestera_qdisc_destroy(port, qdisc);
	case TC_TBF_STATS:
		return prestera_qdisc_get_stats(port, qdisc, &p->stats);
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

int prestera_setup_tc_tbf(struct prestera_port *port,
			  struct tc_tbf_qopt_offload *p)
{
	int err;

	mutex_lock(&port->qdisc->lock);
	err = __prestera_setup_tc_tbf(port, p);
	mutex_unlock(&port->qdisc->lock);

	return err;
}

static struct prestera_qdisc_ops prestera_qdisc_red_ops = {
	.check = prestera_qdisc_red_check,
	.replace = prestera_qdisc_red_replace,
	.destroy = prestera_qdisc_red_destroy,
	.get_stats = prestera_qdisc_tbf_stats_get
};

static int __prestera_setup_tc_red(struct prestera_port *port,
				   struct tc_red_qopt_offload *p)
{
	struct prestera_qdisc *qdisc;

	qdisc = prestera_qdisc_find(port, p->parent);
	if (!qdisc)
		return -EOPNOTSUPP;

	if (p->command == TC_RED_REPLACE)
		return prestera_qdisc_replace(port, p->handle, qdisc,
					      &prestera_qdisc_red_ops,
					      &p->set);

	if (qdisc->handle != p->handle)
		return -EOPNOTSUPP;

	switch (p->command) {
	case TC_RED_DESTROY:
		return prestera_qdisc_destroy(port, qdisc);
	case TC_RED_STATS:
		return prestera_qdisc_get_stats(port, qdisc, &p->stats);
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

int prestera_setup_tc_red(struct prestera_port *port,
			  struct tc_red_qopt_offload *p)
{
	int err;

	mutex_lock(&port->qdisc->lock);
	err = __prestera_setup_tc_red(port, p);
	mutex_unlock(&port->qdisc->lock);

	return err;
}

int prestera_qdisc_port_init(struct prestera_port *port)
{
	struct prestera_qdisc_port *qdisc_port;

	qdisc_port = kzalloc(sizeof(*qdisc_port), GFP_KERNEL);
	if (!qdisc_port)
		return -ENOMEM;

	mutex_init(&qdisc_port->lock);
	port->qdisc = qdisc_port;
	return 0;
}

void prestera_qdisc_port_fini(struct prestera_port *port)
{
	mutex_destroy(&port->qdisc->lock);
	kfree(port->qdisc);
}

int prestera_qdisc_init(struct prestera_switch *sw)
{
	INIT_LIST_HEAD(&sw->sched_list);
	return 0;
}

int prestera_qdisc_fini(struct prestera_switch *sw)
{
	WARN_ON(!list_empty(&sw->sched_list));
	return 0;
}
