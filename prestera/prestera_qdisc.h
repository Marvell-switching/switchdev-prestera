/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved. */
/* tc qdisc add dev sw1p1 root handle 1: ets bands 8 strict 8 */
#ifndef _PRESTERA_ETS_H_
#define _PRESTERA_ETS_H_

#include <linux/types.h>
#include <net/pkt_cls.h>

struct prestera_port;

int prestera_setup_tc_ets(struct prestera_port *port,
			  struct tc_ets_qopt_offload *p);
int prestera_setup_tc_tbf(struct prestera_port *port,
			  struct tc_tbf_qopt_offload *p);
int prestera_setup_tc_red(struct prestera_port *port,
			  struct tc_red_qopt_offload *p);

int prestera_qdisc_init(struct prestera_switch *sw);
int prestera_qdisc_fini(struct prestera_switch *sw);
int prestera_qdisc_port_init(struct prestera_port *port);
void prestera_qdisc_port_fini(struct prestera_port *port);

#endif /* _PRESTERA_ETS_H_ */
