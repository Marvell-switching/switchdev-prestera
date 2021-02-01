/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 *
 * Copyright (c) 2019-2020 Marvell International Ltd. All rights reserved.
 *
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/netdev_features.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/jiffies.h>
#include <linux/if_bridge.h>
#include <linux/phylink.h>
#include <linux/of.h>
#include <net/switchdev.h>
#include <linux/of.h>
#include <linux/of_net.h>

#include "prestera.h"
#include "prestera_log.h"
#include "prestera_hw.h"
#include "prestera_debugfs.h"
#include "prestera_devlink.h"
#include "prestera_dsa.h"
#include "prestera_rxtx.h"
#include "prestera_drv_ver.h"

static u8 trap_policer_profile = 1;

#define MVSW_PR_MTU_DEFAULT 1536
#define MVSW_PR_MAC_ADDR_OFFSET 4

#define PORT_STATS_CACHE_TIMEOUT_MS	(msecs_to_jiffies(1000))
#define PORT_STATS_CNT	(sizeof(struct mvsw_pr_port_stats) / sizeof(u64))
#define PORT_STATS_IDX(name) \
	(offsetof(struct mvsw_pr_port_stats, name) / sizeof(u64))
#define PORT_STATS_FIELD(name)	\
	[PORT_STATS_IDX(name)] = __stringify(name)

static struct list_head switches_registered;

static const char mvsw_driver_kind[] = "prestera_sw";
static const char mvsw_driver_name[] = "mvsw_switchdev";
static const char mvsw_driver_version[] = PRESTERA_DRV_VER;

#define mvsw_dev(sw)		((sw)->dev->dev)
#define mvsw_dev_name(sw)	dev_name((sw)->dev->dev)

static struct workqueue_struct *mvsw_pr_wq;

struct mvsw_pr_link_mode {
	enum ethtool_link_mode_bit_indices eth_mode;
	u32 speed;
	u64 pr_mask;
	u8 duplex;
	u8 port_type;
};

static const struct mvsw_pr_link_mode
mvsw_pr_link_modes[MVSW_LINK_MODE_MAX] = {
	[MVSW_LINK_MODE_10baseT_Half_BIT] = {
		.eth_mode =  ETHTOOL_LINK_MODE_10baseT_Half_BIT,
		.speed = 10,
		.pr_mask = 1 << MVSW_LINK_MODE_10baseT_Half_BIT,
		.duplex = MVSW_PORT_DUPLEX_HALF,
		.port_type = MVSW_PORT_TYPE_TP,
	},
	[MVSW_LINK_MODE_10baseT_Full_BIT] = {
		.eth_mode =  ETHTOOL_LINK_MODE_10baseT_Full_BIT,
		.speed = 10,
		.pr_mask = 1 << MVSW_LINK_MODE_10baseT_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_TP,
	},
	[MVSW_LINK_MODE_100baseT_Half_BIT] = {
		.eth_mode =  ETHTOOL_LINK_MODE_100baseT_Half_BIT,
		.speed = 100,
		.pr_mask = 1 << MVSW_LINK_MODE_100baseT_Half_BIT,
		.duplex = MVSW_PORT_DUPLEX_HALF,
		.port_type = MVSW_PORT_TYPE_TP,
	},
	[MVSW_LINK_MODE_100baseT_Full_BIT] = {
		.eth_mode =  ETHTOOL_LINK_MODE_100baseT_Full_BIT,
		.speed = 100,
		.pr_mask = 1 << MVSW_LINK_MODE_100baseT_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_TP,
	},
	[MVSW_LINK_MODE_1000baseT_Half_BIT] = {
		.eth_mode =  ETHTOOL_LINK_MODE_1000baseT_Half_BIT,
		.speed = 1000,
		.pr_mask = 1 << MVSW_LINK_MODE_1000baseT_Half_BIT,
		.duplex = MVSW_PORT_DUPLEX_HALF,
		.port_type = MVSW_PORT_TYPE_TP,
	},
	[MVSW_LINK_MODE_1000baseT_Full_BIT] = {
		.eth_mode =  ETHTOOL_LINK_MODE_1000baseT_Full_BIT,
		.speed = 1000,
		.pr_mask = 1 << MVSW_LINK_MODE_1000baseT_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_TP,
	},
	[MVSW_LINK_MODE_1000baseX_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_1000baseX_Full_BIT,
		.speed = 1000,
		.pr_mask = 1 << MVSW_LINK_MODE_1000baseX_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_FIBRE,
	},
	[MVSW_LINK_MODE_1000baseKX_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_1000baseKX_Full_BIT,
		.speed = 1000,
		.pr_mask = 1 << MVSW_LINK_MODE_1000baseKX_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_TP,
	},
	[MVSW_LINK_MODE_2500baseX_Full_BIT] = {
		.eth_mode =  ETHTOOL_LINK_MODE_2500baseX_Full_BIT,
		.speed = 2500,
		.pr_mask = 1 << MVSW_LINK_MODE_2500baseX_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
	},
	[MVSW_LINK_MODE_10GbaseKR_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_10000baseKR_Full_BIT,
		.speed = 10000,
		.pr_mask = 1 << MVSW_LINK_MODE_10GbaseKR_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_TP,
	},
	[MVSW_LINK_MODE_10GbaseSR_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_10000baseSR_Full_BIT,
		.speed = 10000,
		.pr_mask = 1 << MVSW_LINK_MODE_10GbaseSR_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_FIBRE,
	},
	[MVSW_LINK_MODE_10GbaseLR_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_10000baseLR_Full_BIT,
		.speed = 10000,
		.pr_mask = 1 << MVSW_LINK_MODE_10GbaseLR_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_FIBRE,
	},
	[MVSW_LINK_MODE_20GbaseKR2_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT,
		.speed = 20000,
		.pr_mask = 1 << MVSW_LINK_MODE_20GbaseKR2_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_TP,
	},
	[MVSW_LINK_MODE_25GbaseCR_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_25000baseCR_Full_BIT,
		.speed = 25000,
		.pr_mask = 1 << MVSW_LINK_MODE_25GbaseCR_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_DA,
	},
	[MVSW_LINK_MODE_25GbaseKR_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_25000baseKR_Full_BIT,
		.speed = 25000,
		.pr_mask = 1 << MVSW_LINK_MODE_25GbaseKR_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_TP,
	},
	[MVSW_LINK_MODE_25GbaseSR_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_25000baseSR_Full_BIT,
		.speed = 25000,
		.pr_mask = 1 << MVSW_LINK_MODE_25GbaseSR_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_FIBRE,
	},
	[MVSW_LINK_MODE_40GbaseKR4_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT,
		.speed = 40000,
		.pr_mask = 1 << MVSW_LINK_MODE_40GbaseKR4_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_TP,
	},
	[MVSW_LINK_MODE_40GbaseCR4_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT,
		.speed = 40000,
		.pr_mask = 1 << MVSW_LINK_MODE_40GbaseCR4_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_DA,
	},
	[MVSW_LINK_MODE_40GbaseSR4_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT,
		.speed = 40000,
		.pr_mask = 1 << MVSW_LINK_MODE_40GbaseSR4_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_FIBRE,
	},
	[MVSW_LINK_MODE_50GbaseCR2_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT,
		.speed = 50000,
		.pr_mask = 1 << MVSW_LINK_MODE_50GbaseCR2_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_DA,
	},
	[MVSW_LINK_MODE_50GbaseKR2_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT,
		.speed = 50000,
		.pr_mask = 1 << MVSW_LINK_MODE_50GbaseKR2_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_TP,
	},
	[MVSW_LINK_MODE_50GbaseSR2_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT,
		.speed = 50000,
		.pr_mask = 1 << MVSW_LINK_MODE_50GbaseSR2_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_FIBRE,
	},
	[MVSW_LINK_MODE_100GbaseKR4_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT,
		.speed = 100000,
		.pr_mask = 1 << MVSW_LINK_MODE_100GbaseKR4_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_TP,
	},
	[MVSW_LINK_MODE_100GbaseSR4_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT,
		.speed = 100000,
		.pr_mask = 1 << MVSW_LINK_MODE_100GbaseSR4_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_FIBRE,
	},
	[MVSW_LINK_MODE_100GbaseCR4_Full_BIT] = {
		.eth_mode = ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT,
		.speed = 100000,
		.pr_mask = 1 << MVSW_LINK_MODE_100GbaseCR4_Full_BIT,
		.duplex = MVSW_PORT_DUPLEX_FULL,
		.port_type = MVSW_PORT_TYPE_DA,
	}
};

struct mvsw_pr_fec {
	u32 eth_fec;
	enum ethtool_link_mode_bit_indices eth_mode;
	u8 pr_fec;
};

static const struct mvsw_pr_fec mvsw_pr_fec_caps[MVSW_PORT_FEC_MAX] = {
	[MVSW_PORT_FEC_OFF_BIT] = {
		.eth_fec = ETHTOOL_FEC_OFF,
		.eth_mode = ETHTOOL_LINK_MODE_FEC_NONE_BIT,
		.pr_fec = 1 << MVSW_PORT_FEC_OFF_BIT,
	},
	[MVSW_PORT_FEC_BASER_BIT] = {
		.eth_fec = ETHTOOL_FEC_BASER,
		.eth_mode = ETHTOOL_LINK_MODE_FEC_BASER_BIT,
		.pr_fec = 1 << MVSW_PORT_FEC_BASER_BIT,
	},
	[MVSW_PORT_FEC_RS_BIT] = {
		.eth_fec = ETHTOOL_FEC_RS,
		.eth_mode = ETHTOOL_LINK_MODE_FEC_RS_BIT,
		.pr_fec = 1 << MVSW_PORT_FEC_RS_BIT,
	}
};

struct mvsw_pr_port_type {
	enum ethtool_link_mode_bit_indices eth_mode;
	u8 eth_type;
};

static const struct mvsw_pr_port_type
mvsw_pr_port_types[MVSW_PORT_TYPE_MAX] = {
	[MVSW_PORT_TYPE_NONE] = {
		.eth_mode = __ETHTOOL_LINK_MODE_MASK_NBITS,
		.eth_type = PORT_NONE,
	},
	[MVSW_PORT_TYPE_TP] = {
		.eth_mode = ETHTOOL_LINK_MODE_TP_BIT,
		.eth_type = PORT_TP,
	},
	[MVSW_PORT_TYPE_AUI] = {
		.eth_mode = ETHTOOL_LINK_MODE_AUI_BIT,
		.eth_type = PORT_AUI,
	},
	[MVSW_PORT_TYPE_MII] = {
		.eth_mode = ETHTOOL_LINK_MODE_MII_BIT,
		.eth_type = PORT_MII,
	},
	[MVSW_PORT_TYPE_FIBRE] = {
		.eth_mode = ETHTOOL_LINK_MODE_FIBRE_BIT,
		.eth_type = PORT_FIBRE,
	},
	[MVSW_PORT_TYPE_BNC] = {
		.eth_mode = ETHTOOL_LINK_MODE_BNC_BIT,
		.eth_type = PORT_BNC,
	},
	[MVSW_PORT_TYPE_DA] = {
		.eth_mode = ETHTOOL_LINK_MODE_TP_BIT,
		.eth_type = PORT_TP,
	},
	[MVSW_PORT_TYPE_OTHER] = {
		.eth_mode = __ETHTOOL_LINK_MODE_MASK_NBITS,
		.eth_type = PORT_OTHER,
	}
};

static const char mvsw_pr_port_cnt_name[PORT_STATS_CNT][ETH_GSTRING_LEN] = {
	PORT_STATS_FIELD(good_octets_received),
	PORT_STATS_FIELD(bad_octets_received),
	PORT_STATS_FIELD(mac_trans_error),
	PORT_STATS_FIELD(broadcast_frames_received),
	PORT_STATS_FIELD(multicast_frames_received),
	PORT_STATS_FIELD(frames_64_octets),
	PORT_STATS_FIELD(frames_65_to_127_octets),
	PORT_STATS_FIELD(frames_128_to_255_octets),
	PORT_STATS_FIELD(frames_256_to_511_octets),
	PORT_STATS_FIELD(frames_512_to_1023_octets),
	PORT_STATS_FIELD(frames_1024_to_max_octets),
	PORT_STATS_FIELD(excessive_collision),
	PORT_STATS_FIELD(multicast_frames_sent),
	PORT_STATS_FIELD(broadcast_frames_sent),
	PORT_STATS_FIELD(fc_sent),
	PORT_STATS_FIELD(fc_received),
	PORT_STATS_FIELD(buffer_overrun),
	PORT_STATS_FIELD(undersize),
	PORT_STATS_FIELD(fragments),
	PORT_STATS_FIELD(oversize),
	PORT_STATS_FIELD(jabber),
	PORT_STATS_FIELD(rx_error_frame_received),
	PORT_STATS_FIELD(bad_crc),
	PORT_STATS_FIELD(collisions),
	PORT_STATS_FIELD(late_collision),
	PORT_STATS_FIELD(unicast_frames_received),
	PORT_STATS_FIELD(unicast_frames_sent),
	PORT_STATS_FIELD(sent_multiple),
	PORT_STATS_FIELD(sent_deferred),
	PORT_STATS_FIELD(good_octets_sent),
};

static LIST_HEAD(mvsw_pr_block_cb_list);

static struct mvsw_pr_port *__find_pr_port(const struct mvsw_pr_switch *sw,
					   u32 port_id)
{
	struct mvsw_pr_port *port;

	list_for_each_entry(port, &sw->port_list, list) {
		if (port->id == port_id)
			return port;
	}

	return NULL;
}

static int mvsw_pr_port_state_set(struct net_device *dev, bool is_up)
{
	struct mvsw_pr_port *port = netdev_priv(dev);
	int err;

	if (!is_up)
		netif_stop_queue(dev);

	err = mvsw_pr_hw_port_state_set(port, is_up);

	if (is_up && !err)
		netif_start_queue(dev);

	return err;
}

static int mvsw_pr_port_open(struct net_device *dev)
{
#ifdef CONFIG_PHYLINK
	struct mvsw_pr_port *port = netdev_priv(dev);

	if (port->caps.transceiver == MVSW_PORT_TRANSCEIVER_SFP)
		phylink_start(port->phy_link);
#endif
	return mvsw_pr_port_state_set(dev, true);
}

static int mvsw_pr_port_close(struct net_device *dev)
{
	struct mvsw_pr_port *port = netdev_priv(dev);

	mvsw_pr_fdb_flush_port(port, MVSW_PR_FDB_FLUSH_MODE_DYNAMIC);

#ifdef CONFIG_PHYLINK
	if (port->caps.transceiver == MVSW_PORT_TRANSCEIVER_SFP)
		phylink_stop(port->phy_link);
#endif
	return mvsw_pr_port_state_set(dev, false);
}

static netdev_tx_t mvsw_pr_port_xmit(struct sk_buff *skb,
				     struct net_device *dev)
{
	struct mvsw_pr_port *port = netdev_priv(dev);
	struct mvsw_pr_rxtx_info rxtx_info = {
		.port_id = port->id
	};

	return mvsw_pr_rxtx_xmit(skb, &rxtx_info);
}

/* TC flower */
static int
mvsw_pr_setup_tc_cls_flower(struct prestera_acl_block *acl_block,
			    struct flow_cls_offload *f)
{
	struct mvsw_pr_switch *sw = prestera_acl_block_sw(acl_block);

	if (f->common.chain_index != 0)
		return -EOPNOTSUPP;

	switch (f->command) {
	case FLOW_CLS_REPLACE:
		return mvsw_pr_flower_replace(sw, acl_block, f);
	case FLOW_CLS_DESTROY:
		mvsw_pr_flower_destroy(sw, acl_block, f);
		return 0;
	case FLOW_CLS_STATS:
		return mvsw_pr_flower_stats(sw, acl_block, f);
	default:
		return -EOPNOTSUPP;
	}
}

static int mvsw_pr_setup_tc_block_cb_flower(enum tc_setup_type type,
					    void *type_data, void *cb_priv)
{
	struct prestera_acl_block *acl_block = cb_priv;

	switch (type) {
	case TC_SETUP_CLSFLOWER:
		if (prestera_acl_block_disabled(acl_block))
			return -EOPNOTSUPP;
		return mvsw_pr_setup_tc_cls_flower(acl_block, type_data);
	default:
		return -EOPNOTSUPP;
	}
}

static void mvsw_pr_tc_block_flower_release(void *cb_priv)
{
	struct prestera_acl_block *acl_block = cb_priv;

	prestera_acl_block_destroy(acl_block);
}

static int
mvsw_pr_setup_tc_block_flower_bind(struct mvsw_pr_port *port,
				   struct flow_block_offload *f)
{
	struct mvsw_pr_switch *sw = port->sw;
	struct prestera_acl_block *acl_block;
	struct flow_block_cb *block_cb;
	bool register_block = false;
	bool disable_block = false;
	int err;

	block_cb = flow_block_cb_lookup(f->block,
					mvsw_pr_setup_tc_block_cb_flower, sw);
	if (!block_cb) {
		acl_block = prestera_acl_block_create(sw, f->net);
		if (!acl_block)
			return -ENOMEM;
		block_cb = flow_block_cb_alloc(mvsw_pr_setup_tc_block_cb_flower,
					       sw, acl_block,
					       mvsw_pr_tc_block_flower_release);
		if (IS_ERR(block_cb)) {
			prestera_acl_block_destroy(acl_block);
			err = PTR_ERR(block_cb);
			goto err_cb_register;
		}
		register_block = true;
	} else {
		acl_block = flow_block_cb_priv(block_cb);
	}
	flow_block_cb_incref(block_cb);

	if (!tc_can_offload(port->net_dev)) {
		if (prestera_acl_block_rule_count(acl_block)) {
			err = -EOPNOTSUPP;
			goto err_block_bind;
		}

		disable_block = true;
	}

	err = prestera_acl_block_bind(sw, acl_block, port);
	if (err)
		goto err_block_bind;

	if (register_block) {
		flow_block_cb_add(block_cb, f);
		list_add_tail(&block_cb->driver_list, &mvsw_pr_block_cb_list);
	}

	if (disable_block)
		prestera_acl_block_disable_inc(acl_block);

	port->acl_block = acl_block;
	return 0;

err_block_bind:
	if (!flow_block_cb_decref(block_cb))
		flow_block_cb_free(block_cb);
err_cb_register:
	return err;
}

static void
mvsw_pr_setup_tc_block_flower_unbind(struct mvsw_pr_port *port,
				     struct flow_block_offload *f)
{
	struct mvsw_pr_switch *sw = port->sw;
	struct prestera_acl_block *acl_block;
	struct flow_block_cb *block_cb;
	int err;

	block_cb = flow_block_cb_lookup(f->block,
					mvsw_pr_setup_tc_block_cb_flower, sw);
	if (!block_cb)
		return;

	acl_block = flow_block_cb_priv(block_cb);

	if (!tc_can_offload(port->net_dev))
		prestera_acl_block_disable_dec(acl_block);

	err = prestera_acl_block_unbind(sw, acl_block, port);
	if (!err && !flow_block_cb_decref(block_cb)) {
		flow_block_cb_remove(block_cb, f);
		list_del(&block_cb->driver_list);
	}
	port->acl_block = NULL;
}

static int mvsw_sp_setup_tc_block(struct mvsw_pr_port *port,
				  struct flow_block_offload *f)
{
	if (f->binder_type != FLOW_BLOCK_BINDER_TYPE_CLSACT_INGRESS)
		return -EOPNOTSUPP;

	f->driver_block_list = &mvsw_pr_block_cb_list;

	switch (f->command) {
	case FLOW_BLOCK_BIND:
		return mvsw_pr_setup_tc_block_flower_bind(port, f);
	case FLOW_BLOCK_UNBIND:
		mvsw_pr_setup_tc_block_flower_unbind(port, f);
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static int mvsw_pr_setup_tc(struct net_device *dev, enum tc_setup_type type,
			    void *type_data)
{
	struct mvsw_pr_port *port = netdev_priv(dev);

	switch (type) {
	case TC_SETUP_BLOCK:
		return mvsw_sp_setup_tc_block(port, type_data);
	default:
		return -EOPNOTSUPP;
	}
}

static void mvsw_pr_set_rx_mode(struct net_device *dev)
{
	/* TO DO: add implementation */
}

static int mvsw_is_valid_mac_addr(struct mvsw_pr_port *port, u8 *addr)
{
	int err;

	if (!is_valid_ether_addr(addr))
		return -EADDRNOTAVAIL;

	err = memcmp(port->sw->base_mac, addr, ETH_ALEN - 1);
	if (err)
		return -EINVAL;

	return 0;
}

static int mvsw_pr_port_set_mac_address(struct net_device *dev, void *p)
{
	struct mvsw_pr_port *port = netdev_priv(dev);
	struct sockaddr *addr = p;
	int err;

	err = mvsw_is_valid_mac_addr(port, addr->sa_data);
	if (err)
		return err;

	err = mvsw_pr_hw_port_mac_set(port, addr->sa_data);
	if (!err)
		memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);

	return err;
}

static int mvsw_pr_port_change_mtu(struct net_device *dev, int mtu)
{
	struct mvsw_pr_port *port = netdev_priv(dev);
	int err;

	if (port->sw->mtu_min <= mtu && mtu <= port->sw->mtu_max)
		err = mvsw_pr_hw_port_mtu_set(port, mtu);
	else
		err = -EINVAL;

	if (!err)
		dev->mtu = mtu;

	return err;
}

static void mvsw_pr_port_get_stats64(struct net_device *dev,
				     struct rtnl_link_stats64 *stats)
{
	struct mvsw_pr_port *port = netdev_priv(dev);
	struct mvsw_pr_port_stats *port_stats = &port->cached_hw_stats.stats;

	stats->rx_packets =	port_stats->broadcast_frames_received +
				port_stats->multicast_frames_received +
				port_stats->unicast_frames_received;

	stats->tx_packets =	port_stats->broadcast_frames_sent +
				port_stats->multicast_frames_sent +
				port_stats->unicast_frames_sent;

	stats->rx_bytes = port_stats->good_octets_received;

	stats->tx_bytes = port_stats->good_octets_sent;

	stats->rx_errors = port_stats->rx_error_frame_received;
	stats->tx_errors = port_stats->mac_trans_error;

	stats->rx_dropped = port_stats->buffer_overrun;
	stats->tx_dropped = 0;

	stats->multicast = port_stats->multicast_frames_received;
	stats->collisions = port_stats->excessive_collision;

	stats->rx_crc_errors = port_stats->bad_crc;
}

static void mvsw_pr_port_get_hw_stats(struct mvsw_pr_port *port)
{
	mvsw_pr_hw_port_stats_get(port, &port->cached_hw_stats.stats);
}

static void update_stats_cache(struct work_struct *work)
{
	struct mvsw_pr_port *port =
		container_of(work, struct mvsw_pr_port,
			     cached_hw_stats.caching_dw.work);

	rtnl_lock();
	mvsw_pr_port_get_hw_stats(port);
	rtnl_unlock();

	queue_delayed_work(mvsw_pr_wq, &port->cached_hw_stats.caching_dw,
			   PORT_STATS_CACHE_TIMEOUT_MS);
}

static bool mvsw_pr_port_has_offload_stats(const struct net_device *dev,
					   int attr_id)
{
	/* TO DO: add implementation */
	return false;
}

static int mvsw_pr_port_get_offload_stats(int attr_id,
					  const struct net_device *dev,
					  void *sp)
{
	/* TO DO: add implementation */
	return 0;
}

static int mvsw_pr_feature_hw_tc(struct net_device *dev, bool enable)
{
	struct mvsw_pr_port *port = netdev_priv(dev);

	if (!enable) {
		if (prestera_acl_block_rule_count(port->acl_block)) {
			netdev_err(dev, "Active offloaded tc filters, can't turn hw_tc_offload off\n");
			return -EINVAL;
		}
		prestera_acl_block_disable_inc(port->acl_block);
	} else {
		prestera_acl_block_disable_dec(port->acl_block);
	}
	return 0;
}

static int
mvsw_pr_handle_feature(struct net_device *dev,
		       netdev_features_t wanted_features,
		       netdev_features_t feature,
		       int (*feature_handler)(struct net_device *dev,
					      bool enable))
{
	netdev_features_t changes = wanted_features ^ dev->features;
	bool enable = !!(wanted_features & feature);
	int err;

	if (!(changes & feature))
		return 0;

	err = feature_handler(dev, enable);
	if (err) {
		netdev_err(dev, "%s feature %pNF failed, err %d\n",
			   enable ? "Enable" : "Disable", &feature, err);
		return err;
	}

	if (enable)
		dev->features |= feature;
	else
		dev->features &= ~feature;

	return 0;
}

static int mvsw_pr_set_features(struct net_device *dev,
				netdev_features_t features)
{
	netdev_features_t oper_features = dev->features;
	int err = 0;

	err |= mvsw_pr_handle_feature(dev, features, NETIF_F_HW_TC,
				       mvsw_pr_feature_hw_tc);

	if (err) {
		dev->features = oper_features;
		return -EINVAL;
	}

	return 0;
}

static void mvsw_pr_port_get_drvinfo(struct net_device *dev,
				     struct ethtool_drvinfo *drvinfo)
{
	struct mvsw_pr_port *port = netdev_priv(dev);
	struct mvsw_pr_switch *sw = port->sw;

	strlcpy(drvinfo->driver, mvsw_driver_kind, sizeof(drvinfo->driver));
	strlcpy(drvinfo->bus_info, mvsw_dev_name(sw), sizeof(drvinfo->bus_info));
	snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version),
		 "%d.%d.%d",
		 sw->dev->fw_rev.maj,
		 sw->dev->fw_rev.min,
		 sw->dev->fw_rev.sub);
}

static const struct net_device_ops mvsw_pr_netdev_ops = {
	.ndo_open = mvsw_pr_port_open,
	.ndo_stop = mvsw_pr_port_close,
	.ndo_start_xmit = mvsw_pr_port_xmit,
	.ndo_setup_tc = mvsw_pr_setup_tc,
	.ndo_change_mtu = mvsw_pr_port_change_mtu,
	.ndo_set_rx_mode = mvsw_pr_set_rx_mode,
	.ndo_get_stats64 = mvsw_pr_port_get_stats64,
	.ndo_set_features = mvsw_pr_set_features,
	.ndo_set_mac_address = mvsw_pr_port_set_mac_address,
	.ndo_has_offload_stats = mvsw_pr_port_has_offload_stats,
	.ndo_get_offload_stats = mvsw_pr_port_get_offload_stats,
	.ndo_get_devlink_port = prestera_devlink_get_port,
};

bool mvsw_pr_netdev_check(const struct net_device *dev)
{
	return dev->netdev_ops == &mvsw_pr_netdev_ops;
}

static int mvsw_pr_lower_dev_walk(struct net_device *lower_dev,
	struct netdev_nested_priv  *priv)
{
	struct mvsw_pr_port **pport = (struct mvsw_pr_port **)priv->data;

	if (mvsw_pr_netdev_check(lower_dev)) {
		*pport = netdev_priv(lower_dev);
		return 1;
	}

	return 0;
}

struct mvsw_pr_port *mvsw_pr_port_dev_lower_find(struct net_device *dev)
{
	struct mvsw_pr_port *port = NULL;
	struct netdev_nested_priv priv = {
		.data = (void *)&port,
	};

	if (!dev)
		return NULL;

	if (mvsw_pr_netdev_check(dev))
		return netdev_priv(dev);

	port = NULL;
	netdev_walk_all_lower_dev(dev, mvsw_pr_lower_dev_walk, &priv);

	return port;
}

struct mvsw_pr_switch *mvsw_pr_switch_get(struct net_device *dev)
{
	struct mvsw_pr_port *port;

	port = mvsw_pr_port_dev_lower_find(dev);
	return port ? port->sw : NULL;
}

static void mvsw_modes_to_eth(unsigned long *eth_modes, u64 link_modes, u8 fec,
			      u8 type)
{
	u32 mode;

	for (mode = 0; mode < MVSW_LINK_MODE_MAX; mode++) {
		if ((mvsw_pr_link_modes[mode].pr_mask & link_modes) == 0)
			continue;
		if (type != MVSW_PORT_TYPE_NONE &&
		    mvsw_pr_link_modes[mode].port_type != type)
			continue;
		__set_bit(mvsw_pr_link_modes[mode].eth_mode, eth_modes);
	}

	for (mode = 0; mode < MVSW_PORT_FEC_MAX; mode++) {
		if ((mvsw_pr_fec_caps[mode].pr_fec & fec) == 0)
			continue;
		__set_bit(mvsw_pr_fec_caps[mode].eth_mode, eth_modes);
	}
}

static void mvsw_pr_port_autoneg_get(struct ethtool_link_ksettings *ecmd,
				     struct mvsw_pr_port *port)
{
	ecmd->base.autoneg = port->autoneg ? AUTONEG_ENABLE : AUTONEG_DISABLE;

	mvsw_modes_to_eth(ecmd->link_modes.supported,
			  port->caps.supp_link_modes,
			  port->caps.supp_fec,
			  port->caps.type);

	if (port->caps.type != MVSW_PORT_TYPE_TP)
		return;

	ethtool_link_ksettings_add_link_mode(ecmd, supported, Autoneg);

	if (!netif_running(port->net_dev))
		return;

	if (port->autoneg) {
		mvsw_modes_to_eth(ecmd->link_modes.advertising,
				  port->adver_link_modes,
				  port->adver_fec,
				  port->caps.type);
		ethtool_link_ksettings_add_link_mode(ecmd, advertising,
						     Autoneg);
	} else if (port->caps.transceiver == MVSW_PORT_TRANSCEIVER_COPPER)
		ethtool_link_ksettings_add_link_mode(ecmd, advertising,
						     Autoneg);
}

static int mvsw_modes_from_eth(struct mvsw_pr_port *port,
			       const unsigned long *advertising,
			       const unsigned long *supported,
			       u64 *link_modes, u8 *fec)
{
	struct ethtool_link_ksettings curr = {};
	u32 mode;

	ethtool_link_ksettings_zero_link_mode(&curr, supported);
	ethtool_link_ksettings_zero_link_mode(&curr, advertising);

	mvsw_pr_port_autoneg_get(&curr, port);

	if (linkmode_equal(advertising, curr.link_modes.advertising)) {
		*link_modes = port->adver_link_modes;
		*fec = port->adver_fec;
		return 0;
	}

	if (!linkmode_subset(advertising, supported)) {
		netdev_err(port->net_dev, "Unsupported link mode requested");
		return -EINVAL;
	}

	*link_modes  = 0;
	*fec = 0;
	for (mode = 0; mode < MVSW_LINK_MODE_MAX; mode++) {
		if (!test_bit(mvsw_pr_link_modes[mode].eth_mode, advertising))
			continue;
		if (mvsw_pr_link_modes[mode].port_type != port->caps.type)
			continue;
		*link_modes |= mvsw_pr_link_modes[mode].pr_mask;
	}

	for (mode = 0; mode < MVSW_PORT_FEC_MAX; mode++) {
		if (!test_bit(mvsw_pr_fec_caps[mode].eth_mode, advertising))
			continue;
		*fec |= mvsw_pr_fec_caps[mode].pr_fec;
	}

	if (*link_modes == 0 && *fec == 0) {
		netdev_err(port->net_dev, "No link modes requested");
		return -EINVAL;
	}
	if (*link_modes == 0)
		*link_modes = port->adver_link_modes;
	if (*fec == 0)
		*fec = port->adver_fec ? port->adver_fec :
					 BIT(MVSW_PORT_FEC_OFF_BIT);

	return 0;
}

static void mvsw_pr_port_supp_types_get(struct ethtool_link_ksettings *ecmd,
					struct mvsw_pr_port *port)
{
	u32 mode;
	u8 ptype;

	for (mode = 0; mode < MVSW_LINK_MODE_MAX; mode++) {
		if ((mvsw_pr_link_modes[mode].pr_mask &
		    port->caps.supp_link_modes) == 0)
			continue;
		ptype = mvsw_pr_link_modes[mode].port_type;
		__set_bit(mvsw_pr_port_types[ptype].eth_mode,
			  ecmd->link_modes.supported);
	}
}

static void mvsw_pr_port_speed_get(struct ethtool_link_ksettings *ecmd,
				   struct mvsw_pr_port *port)
{
	u32 speed;
	int err;

	err = mvsw_pr_hw_port_speed_get(port, &speed);
	ecmd->base.speed = !err ? speed : SPEED_UNKNOWN;
}

static int mvsw_pr_port_link_mode_set(struct mvsw_pr_port *port,
				      u32 speed, u8 duplex, u8 type)
{
	u32 new_mode = MVSW_LINK_MODE_MAX;
	u32 mode;

	for (mode = 0; mode < MVSW_LINK_MODE_MAX; mode++) {
		if (speed != mvsw_pr_link_modes[mode].speed)
			continue;
		if (duplex != mvsw_pr_link_modes[mode].duplex)
			continue;
		if (!(mvsw_pr_link_modes[mode].pr_mask &
		    port->caps.supp_link_modes))
			continue;
		if (type != mvsw_pr_link_modes[mode].port_type)
			continue;

		new_mode = mode;
		break;
	}

	if (new_mode == MVSW_LINK_MODE_MAX) {
		netdev_err(port->net_dev, "Unsupported speed/duplex requested");
		return -EINVAL;
	}

	return mvsw_pr_hw_port_link_mode_set(port, new_mode);
}

static int mvsw_pr_port_speed_duplex_set(const struct ethtool_link_ksettings
					 *ecmd, struct mvsw_pr_port *port)
{
	int err;
	u8 duplex;
	u32 speed;
	u32 curr_mode;

	err = mvsw_pr_hw_port_link_mode_get(port, &curr_mode);
	if (err || curr_mode >= MVSW_LINK_MODE_MAX)
		return -EINVAL;

	if (ecmd->base.duplex != DUPLEX_UNKNOWN)
		duplex = ecmd->base.duplex == DUPLEX_FULL ?
			 MVSW_PORT_DUPLEX_FULL : MVSW_PORT_DUPLEX_HALF;
	else
		duplex = mvsw_pr_link_modes[curr_mode].duplex;

	if (ecmd->base.speed != SPEED_UNKNOWN)
		speed = ecmd->base.speed;
	else
		speed = mvsw_pr_link_modes[curr_mode].speed;

	return mvsw_pr_port_link_mode_set(port, speed, duplex, port->caps.type);
}

static u8 mvsw_pr_port_type_get(struct mvsw_pr_port *port)
{
	if (port->caps.type < MVSW_PORT_TYPE_MAX)
		return mvsw_pr_port_types[port->caps.type].eth_type;
	return PORT_OTHER;
}

static int mvsw_pr_port_type_set(const struct ethtool_link_ksettings *ecmd,
				 struct mvsw_pr_port *port)
{
	int err;
	u32 type, mode;
	u32 new_mode = MVSW_LINK_MODE_MAX;

	for (type = 0; type < MVSW_PORT_TYPE_MAX; type++) {
		if (mvsw_pr_port_types[type].eth_type == ecmd->base.port &&
		    test_bit(mvsw_pr_port_types[type].eth_mode,
			     ecmd->link_modes.supported)) {
			break;
		}
	}

	if (type == port->caps.type)
		return 0;

	if (type != port->caps.type && ecmd->base.autoneg == AUTONEG_ENABLE)
		return -EINVAL;

	if (type == MVSW_PORT_TYPE_MAX) {
		pr_err("Unsupported port type requested\n");
		return -EINVAL;
	}

	for (mode = 0; mode < MVSW_LINK_MODE_MAX; mode++) {
		if ((mvsw_pr_link_modes[mode].pr_mask &
		    port->caps.supp_link_modes) &&
		    type == mvsw_pr_link_modes[mode].port_type) {
			new_mode = mode;
		}
	}

	if (new_mode < MVSW_LINK_MODE_MAX)
		err = mvsw_pr_hw_port_link_mode_set(port, new_mode);
	else
		err = -EINVAL;

	if (!err) {
		port->caps.type = type;
		port->autoneg = false;
	}

	return err;
}

static void mvsw_pr_port_remote_cap_get(struct ethtool_link_ksettings *ecmd,
					struct mvsw_pr_port *port)
{
	u64 bitmap;
	bool pause;
	bool asym_pause;

	if (!mvsw_pr_hw_port_remote_cap_get(port, &bitmap)) {
		mvsw_modes_to_eth(ecmd->link_modes.lp_advertising,
				  bitmap, 0, MVSW_PORT_TYPE_NONE);

		if (!bitmap_empty(ecmd->link_modes.lp_advertising,
				  __ETHTOOL_LINK_MODE_MASK_NBITS)) {
			ethtool_link_ksettings_add_link_mode(ecmd,
							     lp_advertising,
							     Autoneg);
		}
	}

	if (mvsw_pr_hw_port_remote_fc_get(port, &pause, &asym_pause))
		return;
	if (pause)
		ethtool_link_ksettings_add_link_mode(ecmd,
						     lp_advertising,
						     Pause);
	if (asym_pause)
		ethtool_link_ksettings_add_link_mode(ecmd,
						     lp_advertising,
						     Asym_Pause);
}

static void mvsw_pr_port_duplex_get(struct ethtool_link_ksettings *ecmd,
				    struct mvsw_pr_port *port)
{
	u8 duplex;

	if (!mvsw_pr_hw_port_duplex_get(port, &duplex)) {
		ecmd->base.duplex = duplex == MVSW_PORT_DUPLEX_FULL ?
				    DUPLEX_FULL : DUPLEX_HALF;
	} else {
		ecmd->base.duplex = DUPLEX_UNKNOWN;
	}
}

static int mvsw_pr_port_autoneg_set(struct mvsw_pr_port *port, bool enable,
				    u64 link_modes, u8 fec)
{
	if (port->caps.type != MVSW_PORT_TYPE_TP)
		return enable ? -EINVAL : 0;

	if (port->autoneg == enable && port->adver_link_modes == link_modes &&
	    port->adver_fec == fec)
		return 0;

	if (mvsw_pr_hw_port_autoneg_set(port, enable, link_modes, fec))
		return -EINVAL;

	port->autoneg = enable;
	port->adver_link_modes = link_modes;
	port->adver_fec = fec;
	return 0;
}

static int mvsw_pr_port_nway_reset(struct net_device *dev)
{
	struct mvsw_pr_port *port = netdev_priv(dev);

	if (netif_running(dev) &&
	    port->caps.transceiver == MVSW_PORT_TRANSCEIVER_COPPER &&
	    port->caps.type == MVSW_PORT_TYPE_TP)
		return mvsw_pr_hw_port_autoneg_restart(port);

	return -EINVAL;
}

static int mvsw_pr_port_mdix_set(const struct ethtool_link_ksettings *ecmd,
				 struct mvsw_pr_port *port)
{
	if (ecmd->base.eth_tp_mdix_ctrl != ETH_TP_MDI_INVALID &&
	    port->caps.transceiver == MVSW_PORT_TRANSCEIVER_COPPER &&
	    port->caps.type == MVSW_PORT_TYPE_TP)
		return mvsw_pr_hw_port_mdix_set(port,
						ecmd->base.eth_tp_mdix_ctrl);
	return 0;
}

static int mvsw_pr_port_get_link_ksettings(struct net_device *dev,
					   struct ethtool_link_ksettings *ecmd)
{
	struct mvsw_pr_port *port = netdev_priv(dev);

	/* Dirty hook: Deinit ecmd.
	 * It caused by suspicious phylink_ethtool_ksettings_get()
	 * implementation, which can left "kset" uninitialized, when there is no
	 * SFP plugged
	 */
	ethtool_link_ksettings_zero_link_mode(ecmd, supported);
	ethtool_link_ksettings_zero_link_mode(ecmd, advertising);
	ethtool_link_ksettings_zero_link_mode(ecmd, lp_advertising);
	ecmd->base.speed = SPEED_UNKNOWN;
	ecmd->base.duplex = DUPLEX_UNKNOWN;
	ecmd->base.autoneg = AUTONEG_DISABLE;
#ifdef CONFIG_PHYLINK
	if (port->caps.transceiver == MVSW_PORT_TRANSCEIVER_SFP)
		return phylink_ethtool_ksettings_get(port->phy_link, ecmd);
#endif /* CONFIG_PHYLINK */

	mvsw_pr_port_supp_types_get(ecmd, port);

	mvsw_pr_port_autoneg_get(ecmd, port);

	if (port->autoneg && netif_carrier_ok(dev) &&
	    port->caps.transceiver == MVSW_PORT_TRANSCEIVER_COPPER)
		mvsw_pr_port_remote_cap_get(ecmd, port);

	if (netif_carrier_ok(dev)) {
		mvsw_pr_port_speed_get(ecmd, port);
		mvsw_pr_port_duplex_get(ecmd, port);
	} else {
		ecmd->base.speed = SPEED_UNKNOWN;
		ecmd->base.duplex = DUPLEX_UNKNOWN;
	}

	ecmd->base.port = mvsw_pr_port_type_get(port);

	if (port->caps.type == MVSW_PORT_TYPE_TP &&
	    port->caps.transceiver == MVSW_PORT_TRANSCEIVER_COPPER)
		mvsw_pr_hw_port_mdix_get(port, &ecmd->base.eth_tp_mdix,
					 &ecmd->base.eth_tp_mdix_ctrl);

	return 0;
}

static int mvsw_pr_port_set_link_ksettings(struct net_device *dev,
					   const struct ethtool_link_ksettings
					   *ecmd)
{
	struct mvsw_pr_port *port = netdev_priv(dev);
	u64 adver_modes = 0;
	u8 adver_fec = 0;
	int err;

#ifdef CONFIG_PHYLINK
	if (port->caps.transceiver == MVSW_PORT_TRANSCEIVER_SFP)
		return phylink_ethtool_ksettings_set(port->phy_link, ecmd);
#endif /* CONFIG_PHYLINK */

	err = mvsw_pr_port_type_set(ecmd, port);
	if (err)
		return err;

	if (port->caps.transceiver == MVSW_PORT_TRANSCEIVER_COPPER) {
		err = mvsw_pr_port_mdix_set(ecmd, port);
		if (err)
			return err;
	}

	if (ecmd->base.autoneg == AUTONEG_ENABLE) {
		if (mvsw_modes_from_eth(port, ecmd->link_modes.advertising,
					ecmd->link_modes.supported,
					&adver_modes, &adver_fec))
			return -EINVAL;
		if (!port->autoneg && !adver_modes)
			adver_modes = port->caps.supp_link_modes;
	} else {
		adver_modes = port->adver_link_modes;
		adver_fec = port->adver_fec;
	}

	err = mvsw_pr_port_autoneg_set(port,
				       ecmd->base.autoneg == AUTONEG_ENABLE,
				       adver_modes, adver_fec);
	if (err)
		return err;

	if (ecmd->base.autoneg == AUTONEG_DISABLE) {
		err = mvsw_pr_port_speed_duplex_set(ecmd, port);
		if (err)
			return err;
	}

	return 0;
}

static int mvsw_pr_port_get_fecparam(struct net_device *dev,
				     struct ethtool_fecparam *fecparam)
{
	struct mvsw_pr_port *port = netdev_priv(dev);
	u32 mode;
	u8 active;
	int err;

	err = mvsw_pr_hw_port_fec_get(port, &active);
	if (err)
		return err;

	fecparam->fec = 0;
	for (mode = 0; mode < MVSW_PORT_FEC_MAX; mode++) {
		if ((mvsw_pr_fec_caps[mode].pr_fec & port->caps.supp_fec) == 0)
			continue;
		fecparam->fec |= mvsw_pr_fec_caps[mode].eth_fec;
	}

	if (active < MVSW_PORT_FEC_MAX)
		fecparam->active_fec = mvsw_pr_fec_caps[active].eth_fec;
	else
		fecparam->active_fec = ETHTOOL_FEC_AUTO;

	return 0;
}

static int mvsw_pr_port_set_fecparam(struct net_device *dev,
				     struct ethtool_fecparam *fecparam)
{
	struct mvsw_pr_port *port = netdev_priv(dev);
	u8 fec, active;
	u32 mode;
	int err;

	if (port->autoneg) {
		netdev_err(dev, "FEC set is not allowed while autoneg is on\n");
		return -EINVAL;
	}

	err = mvsw_pr_hw_port_fec_get(port, &active);
	if (err)
		return err;

	fec = MVSW_PORT_FEC_MAX;
	for (mode = 0; mode < MVSW_PORT_FEC_MAX; mode++) {
		if ((mvsw_pr_fec_caps[mode].eth_fec & fecparam->fec) &&
		    (mvsw_pr_fec_caps[mode].pr_fec & port->caps.supp_fec)) {
			fec = mode;
			break;
		}
	}

	if (fec == active)
		return 0;

	if (fec == MVSW_PORT_FEC_MAX) {
		netdev_err(dev, "Unsupported FEC requested");
		return -EINVAL;
	}

	return mvsw_pr_hw_port_fec_set(port, fec);
}

static void mvsw_pr_port_get_ethtool_stats(struct net_device *dev,
					   struct ethtool_stats *stats,
					   u64 *data)
{
	struct mvsw_pr_port *port = netdev_priv(dev);
	struct mvsw_pr_port_stats *port_stats = &port->cached_hw_stats.stats;

	memcpy((u8 *)data, port_stats, sizeof(*port_stats));
}

static void mvsw_pr_port_get_strings(struct net_device *dev,
				     u32 stringset, u8 *data)
{
	if (stringset != ETH_SS_STATS)
		return;

	memcpy(data, *mvsw_pr_port_cnt_name, sizeof(mvsw_pr_port_cnt_name));
}

static int mvsw_pr_port_get_sset_count(struct net_device *dev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return PORT_STATS_CNT;
	default:
		return -EOPNOTSUPP;
	}
}

static const struct ethtool_ops mvsw_pr_ethtool_ops = {
	.get_drvinfo = mvsw_pr_port_get_drvinfo,
	.get_link_ksettings = mvsw_pr_port_get_link_ksettings,
	.set_link_ksettings = mvsw_pr_port_set_link_ksettings,
	.get_fecparam = mvsw_pr_port_get_fecparam,
	.set_fecparam = mvsw_pr_port_set_fecparam,
	.get_sset_count = mvsw_pr_port_get_sset_count,
	.get_strings = mvsw_pr_port_get_strings,
	.get_ethtool_stats = mvsw_pr_port_get_ethtool_stats,
	.get_link = ethtool_op_get_link,
	.nway_reset = mvsw_pr_port_nway_reset
};

int mvsw_pr_port_learning_set(struct mvsw_pr_port *port, bool learn)
{
	return mvsw_pr_hw_port_learning_set(port, learn);
}

int mvsw_pr_port_uc_flood_set(struct mvsw_pr_port *port, bool flood)
{
	return mvsw_pr_hw_port_uc_flood_set(port, flood);
}

int mvsw_pr_port_mc_flood_set(struct mvsw_pr_port *port, bool flood)
{
	return mvsw_pr_hw_port_mc_flood_set(port, flood);
}

int mvsw_pr_port_pvid_set(struct mvsw_pr_port *port, u16 vid)
{
	int err;

	if (!vid) {
		err = mvsw_pr_hw_port_accept_frame_type_set
		    (port, MVSW_ACCEPT_FRAME_TYPE_TAGGED);
		if (err)
			return err;
	} else {
		err = mvsw_pr_hw_vlan_port_vid_set(port, vid);
		if (err)
			return err;
		err = mvsw_pr_hw_port_accept_frame_type_set
		    (port, MVSW_ACCEPT_FRAME_TYPE_ALL);
		if (err)
			goto err_port_allow_untagged_set;
	}

	port->pvid = vid;
	return 0;

err_port_allow_untagged_set:
	mvsw_pr_hw_vlan_port_vid_set(port, port->pvid);
	return err;
}

int mvsw_pr_port_vid_stp_set(struct mvsw_pr_port *port, u16 vid, u8 state)
{
	u8 hw_state = state;

	switch (state) {
	case BR_STATE_DISABLED:
		hw_state = MVSW_STP_DISABLED;
		break;

	case BR_STATE_BLOCKING:
	case BR_STATE_LISTENING:
		hw_state = MVSW_STP_BLOCK_LISTEN;
		break;

	case BR_STATE_LEARNING:
		hw_state = MVSW_STP_LEARN;
		break;

	case BR_STATE_FORWARDING:
		hw_state = MVSW_STP_FORWARD;
		break;

	default:
		return -EINVAL;
	}

	return mvsw_pr_hw_port_vid_stp_set(port, vid, hw_state);
}

struct mvsw_pr_port_vlan*
mvsw_pr_port_vlan_find_by_vid(const struct mvsw_pr_port *port, u16 vid)
{
	struct mvsw_pr_port_vlan *port_vlan;

	list_for_each_entry(port_vlan, &port->vlans_list, list) {
		if (port_vlan->vid == vid)
			return port_vlan;
	}

	return NULL;
}

struct mvsw_pr_port_vlan*
mvsw_pr_port_vlan_create(struct mvsw_pr_port *port, u16 vid, bool untagged)
{
	struct mvsw_pr_port_vlan *port_vlan;
	int err;

	port_vlan = mvsw_pr_port_vlan_find_by_vid(port, vid);
	if (port_vlan)
		return ERR_PTR(-EEXIST);

	err = mvsw_pr_port_vlan_set(port, vid, true, untagged);
	if (err)
		return ERR_PTR(err);

	port_vlan = kzalloc(sizeof(*port_vlan), GFP_KERNEL);
	if (!port_vlan) {
		err = -ENOMEM;
		goto err_port_vlan_alloc;
	}

	port_vlan->mvsw_pr_port = port;
	port_vlan->vid = vid;

	list_add(&port_vlan->list, &port->vlans_list);

	return port_vlan;

err_port_vlan_alloc:
	mvsw_pr_port_vlan_set(port, vid, false, false);
	return ERR_PTR(err);
}

static void
mvsw_pr_port_vlan_cleanup(struct mvsw_pr_port_vlan *port_vlan)
{
	if (port_vlan->bridge_port)
		mvsw_pr_port_vlan_bridge_leave(port_vlan);
}

void mvsw_pr_port_vlan_destroy(struct mvsw_pr_port_vlan *port_vlan)
{
	struct mvsw_pr_port *port = port_vlan->mvsw_pr_port;
	u16 vid = port_vlan->vid;

	mvsw_pr_port_vlan_cleanup(port_vlan);
	list_del(&port_vlan->list);
	kfree(port_vlan);
	mvsw_pr_hw_vlan_port_set(port, vid, false, false);
}

int mvsw_pr_port_vlan_set(struct mvsw_pr_port *port, u16 vid,
			  bool is_member, bool untagged)
{
	return mvsw_pr_hw_vlan_port_set(port, vid, is_member, untagged);
}

#ifdef CONFIG_PHYLINK
static void mvsw_pr_link_validate(struct phylink_config *config,
	unsigned long *supported,
	struct phylink_link_state *state)
{
	__ETHTOOL_DECLARE_LINK_MODE_MASK(mask) = {0,};

	if (state->interface != PHY_INTERFACE_MODE_NA &&
	    state->interface != PHY_INTERFACE_MODE_10GBASER &&
	    state->interface != PHY_INTERFACE_MODE_SGMII &&
	    !phy_interface_mode_is_8023z(state->interface)) {
		bitmap_zero(supported, __ETHTOOL_LINK_MODE_MASK_NBITS);
		return;
	}

	switch (state->interface) {
	case PHY_INTERFACE_MODE_10GBASER:
	case PHY_INTERFACE_MODE_NA:
		phylink_set(mask, 10000baseT_Full);
		phylink_set(mask, 10000baseCR_Full);
		phylink_set(mask, 10000baseSR_Full);
		phylink_set(mask, 10000baseLR_Full);
		phylink_set(mask, 10000baseLRM_Full);
		phylink_set(mask, 10000baseER_Full);
		phylink_set(mask, 10000baseKR_Full);
		phylink_set(mask, 10000baseKX4_Full);
		phylink_set(mask, 10000baseR_FEC);

		if (state->interface != PHY_INTERFACE_MODE_NA)
			break;
		/* Fall-through */
	case PHY_INTERFACE_MODE_SGMII:
		phylink_set(mask, 10baseT_Full);
		phylink_set(mask, 100baseT_Full);
		phylink_set(mask, 1000baseT_Full);
		if (state->interface != PHY_INTERFACE_MODE_NA) {
			phylink_set(mask, Autoneg);
			break;
		}
		/* Fall-through */
	case PHY_INTERFACE_MODE_2500BASEX:
		phylink_set(mask, 2500baseT_Full);
		phylink_set(mask, 2500baseX_Full);
		if (state->interface != PHY_INTERFACE_MODE_NA)
			break;
		/* Fall-through */
	case PHY_INTERFACE_MODE_1000BASEX:
		phylink_set(mask, 1000baseT_Full);
		phylink_set(mask, 1000baseX_Full);
		break;
	default:
		goto empty_set;
	}

	phylink_set_port_modes(mask);

	bitmap_and(supported, supported, mask,
		__ETHTOOL_LINK_MODE_MASK_NBITS);
	bitmap_and(state->advertising, state->advertising, mask,
		__ETHTOOL_LINK_MODE_MASK_NBITS);

	phylink_helper_basex_speed(state);

	return;

empty_set:
	bitmap_zero(supported, __ETHTOOL_LINK_MODE_MASK_NBITS);

}

static void mvsw_pr_mac_pcs_get_state(struct phylink_config *config,
				      struct phylink_link_state *state)
{
	struct net_device *ndev = to_net_dev(config->dev);
	struct mvsw_pr_port *port = netdev_priv(ndev);

	state->link = !!(port->hw_oper_state);
	state->pause = 0;

	if (port->hw_oper_state) {
		/* AN is completed, when port is up */
		state->an_complete = port->autoneg;

		state->speed = port->hw_speed;
		state->duplex = (port->hw_duplex == MVSW_PORT_DUPLEX_FULL) ?
					DUPLEX_FULL : DUPLEX_HALF;
	} else {
		state->an_complete = false;
		state->speed = SPEED_UNKNOWN;
		state->duplex = DUPLEX_UNKNOWN;
	}
}

static void mvsw_pr_mac_config(struct phylink_config *config,
			       unsigned int an_mode,
			       const struct phylink_link_state *state)
{
	struct net_device *ndev = to_net_dev(config->dev);
	struct mvsw_pr_port *port = netdev_priv(ndev);
	u32 mode;

	/* See sfp_select_interface... fIt */
	switch (state->interface) {
	case PHY_INTERFACE_MODE_10GBASER:
		/* Or SR... doesn't matter */
		mode = MVSW_LINK_MODE_10GbaseLR_Full_BIT;
		if (state->speed == SPEED_1000)
			mode = MVSW_LINK_MODE_1000baseX_Full_BIT;
		if (state->speed == SPEED_2500)
			mode = MVSW_LINK_MODE_2500baseX_Full_BIT;
		break;
	case PHY_INTERFACE_MODE_2500BASEX:
		/* But it seems to be not supported in HW */
		mode = MVSW_LINK_MODE_2500baseX_Full_BIT;
		break;
	case PHY_INTERFACE_MODE_SGMII:
		/* Can be T or X. But for HW is no difference. */
		mode = MVSW_LINK_MODE_1000baseT_Full_BIT;
		break;
	case PHY_INTERFACE_MODE_1000BASEX:
		mode = MVSW_LINK_MODE_1000baseX_Full_BIT;
		break;
	default:
		mode = MVSW_LINK_MODE_1000baseX_Full_BIT;
	}

	mvsw_pr_hw_port_link_mode_set(port, mode);

	/* NOTE: we suppose, that inband autoneg is primary used for
	 * modes, which support only FC autonegotiation. But we don't support
	 * FC. So inband autoneg always be disabled.
	 */

	if (phylink_autoneg_inband(an_mode))
		mvsw_pr_port_autoneg_set(port, false, 0, 0);
	else
		mvsw_pr_port_autoneg_set(port, false, 0, 0);
}

static void mvsw_pr_mac_an_restart(struct phylink_config *config)
{
	/* No need to restart autoneg as it is always with the same parameters,
	 * because e.g. as for 1000baseX FC isn't supported. And for 1000baseT
	 * autoneg provided by external tranciever
	 */
}

static void mvsw_pr_mac_link_down(struct phylink_config *config,
				  unsigned int mode, phy_interface_t interface)
{
}

static void mvsw_pr_mac_link_up(struct phylink_config *config,
				struct phy_device *phy,
				unsigned int mode, phy_interface_t interface,
				int speed, int duplex,
				bool tx_pause, bool rx_pause)
{
}

static const struct phylink_mac_ops mvsw_pr_mac_ops = {
	.validate = mvsw_pr_link_validate,
	.mac_pcs_get_state = mvsw_pr_mac_pcs_get_state,
	.mac_config = mvsw_pr_mac_config,
	.mac_an_restart = mvsw_pr_mac_an_restart,
	.mac_link_down = mvsw_pr_mac_link_down,
	.mac_link_up = mvsw_pr_mac_link_up,
};

static int mvsw_pr_port_sfp_bind(struct mvsw_pr_port *port)
{
	struct mvsw_pr_switch *sw = port->sw;
	struct device_node *ports, *node;
	struct fwnode_handle *fwnode;
	struct phylink *phy_link;
	int err;

	if (!sw->np)
		return 0;

	of_node_get(sw->np);

	ports = of_find_node_by_name(sw->np, "ports");

	for_each_child_of_node(ports, node) {
		int num;

		err = of_property_read_u32(node, "prestera,port-num", &num);
		if (err) {
			dev_err(sw->dev->dev,
				"device node %pOF has no valid reg property: %d\n",
				node, err);
			return err;
		}

		if (port->fp_id != num)
			continue;

		port->phy_config.dev = &port->net_dev->dev;
		port->phy_config.type = PHYLINK_NETDEV;
		port->phy_config.pcs_poll = false;

		fwnode = of_fwnode_handle(node);

		phy_link = phylink_create(&port->phy_config, fwnode,
					  PHY_INTERFACE_MODE_INTERNAL,
					  &mvsw_pr_mac_ops);
		if (IS_ERR(phy_link)) {
			netdev_err(port->net_dev, "failed to create phylink\n");
			return PTR_ERR(phy_link);
		}

		port->phy_link = phy_link;
		break;
	}

	return 0;
}
#else
static int mvsw_pr_port_sfp_bind(struct mvsw_pr_port *port)
{
	return 0;
}
#endif

static int mvsw_pr_port_create(struct mvsw_pr_switch *sw, u32 id)
{
	struct net_device *net_dev;
	struct mvsw_pr_port *port;
	char *mac;
	int err;

	net_dev = alloc_etherdev(sizeof(*port));
	if (!net_dev)
		return -ENOMEM;

	port = netdev_priv(net_dev);

	INIT_LIST_HEAD(&port->vlans_list);
	port->pvid = MVSW_PR_DEFAULT_VID;
	port->net_dev = net_dev;
	port->id = id;
	port->sw = sw;
	port->lag_id = sw->lag_max;

	err = mvsw_pr_hw_port_info_get(port, &port->fp_id,
				       &port->hw_id, &port->dev_id);
	if (err) {
		dev_err(mvsw_dev(sw), "Failed to get port(%u) info\n", id);
		goto err_free_netdev;
	}

	err = prestera_devlink_port_register(port);
	if (err)
		goto err_devl_port_reg;

	net_dev->needed_headroom = MVSW_PR_DSA_HLEN + 4;

	net_dev->netdev_ops = &mvsw_pr_netdev_ops;
	net_dev->ethtool_ops = &mvsw_pr_ethtool_ops;
	net_dev->features |= NETIF_F_NETNS_LOCAL | NETIF_F_HW_TC;
	net_dev->hw_features |= NETIF_F_HW_TC;
	net_dev->ethtool_ops = &mvsw_pr_ethtool_ops;
	net_dev->netdev_ops = &mvsw_pr_netdev_ops;
	SET_NETDEV_DEV(net_dev, sw->dev->dev);

	net_dev->mtu = min_t(unsigned int, sw->mtu_max, MVSW_PR_MTU_DEFAULT);
	net_dev->min_mtu = sw->mtu_min;
	net_dev->max_mtu = sw->mtu_max;

	err = mvsw_pr_hw_port_mtu_set(port, net_dev->mtu);
	if (err) {
		dev_err(mvsw_dev(sw), "Failed to set port(%u) mtu\n", id);
		goto err_port_init;
	}

	/* Only 0xFF mac addrs are supported */
	if (port->fp_id >= 0xFF)
		goto err_port_init;

	mac = net_dev->dev_addr;
	memcpy(mac, sw->base_mac, net_dev->addr_len);
	mac[net_dev->addr_len - 1] += port->fp_id + MVSW_PR_MAC_ADDR_OFFSET;

	err = mvsw_pr_hw_port_mac_set(port, mac);
	if (err) {
		dev_err(mvsw_dev(sw), "Failed to set port(%u) mac addr\n", id);
		goto err_port_init;
	}

	err = mvsw_pr_hw_port_cap_get(port, &port->caps);
	if (err) {
		dev_err(mvsw_dev(sw), "Failed to get port(%u) caps\n", id);
		goto err_port_init;
	}

#ifdef CONFIG_PHYLINK
	if (port->caps.transceiver != MVSW_PORT_TRANSCEIVER_SFP)
		netif_carrier_off(net_dev);
#else
	netif_carrier_off(net_dev);
#endif

	port->adver_link_modes = 0;
	port->adver_fec = 0;
	port->autoneg = false;
	mvsw_pr_port_autoneg_set(port, true, port->caps.supp_link_modes,
				 BIT(MVSW_PORT_FEC_OFF_BIT));

	err = mvsw_pr_hw_port_state_set(port, false);
	if (err) {
		dev_err(mvsw_dev(sw), "Failed to set port(%u) down\n", id);
		goto err_port_init;
	}

	INIT_DELAYED_WORK(&port->cached_hw_stats.caching_dw,
			  &update_stats_cache);

	err = register_netdev(net_dev);
	if (err)
		goto err_port_init;

	if (port->caps.transceiver == MVSW_PORT_TRANSCEIVER_SFP) {
		err = mvsw_pr_port_sfp_bind(port);
		if (err)
			goto err_sfp_bind;
	}

	list_add(&port->list, &sw->port_list);

	mvsw_pr_port_uc_flood_set(port, false);
	mvsw_pr_port_mc_flood_set(port, false);

	prestera_devlink_port_set(port);

	return 0;

err_sfp_bind:
	unregister_netdev(net_dev);
	prestera_devlink_port_unregister(port);
err_port_init:
err_devl_port_reg:
err_free_netdev:
	free_netdev(net_dev);
	return err;
}

static void mvsw_pr_port_vlan_flush(struct mvsw_pr_port *port,
				    bool flush_default)
{
	struct mvsw_pr_port_vlan *port_vlan, *tmp;

	list_for_each_entry_safe(port_vlan, tmp, &port->vlans_list, list) {
		if (!flush_default && port_vlan->vid == MVSW_PR_DEFAULT_VID)
			continue;

		mvsw_pr_port_vlan_destroy(port_vlan);
	}
}

int mvsw_pr_8021d_bridge_create(struct mvsw_pr_switch *sw, u16 *bridge_id)
{
	return mvsw_pr_hw_bridge_create(sw, bridge_id);
}

int mvsw_pr_8021d_bridge_delete(struct mvsw_pr_switch *sw, u16 bridge_id)
{
	return mvsw_pr_hw_bridge_delete(sw, bridge_id);
}

int mvsw_pr_8021d_bridge_port_add(struct mvsw_pr_port *port, u16 bridge_id)
{
	return mvsw_pr_hw_bridge_port_add(port, bridge_id);
}

int mvsw_pr_8021d_bridge_port_delete(struct mvsw_pr_port *port, u16 bridge_id)
{
	return mvsw_pr_hw_bridge_port_delete(port, bridge_id);
}

int mvsw_pr_switch_ageing_set(struct mvsw_pr_switch *sw, u32 ageing_time)
{
	return mvsw_pr_hw_switch_ageing_set(sw, ageing_time / 1000);
}

int mvsw_pr_dev_if_type(const struct net_device *dev)
{
	struct macvlan_dev *vlan;

	if (is_vlan_dev(dev) && netif_is_bridge_master(vlan_dev_real_dev(dev)))
		return MVSW_IF_VID_E;
	else if (netif_is_bridge_master(dev))
		return MVSW_IF_VID_E;
	else if (netif_is_lag_master(dev))
		return MVSW_IF_LAG_E;
	else if (netif_is_macvlan(dev)) {
		vlan = netdev_priv(dev);
		return mvsw_pr_dev_if_type(vlan->lowerdev);
	}
	else
		return MVSW_IF_PORT_E;
}

int mvsw_pr_lpm_add(struct mvsw_pr_switch *sw, u16 hw_vr_id,
		    struct mvsw_pr_ip_addr *addr, u32 prefix_len, u32 grp_id)
{
	/* Dont waste time on hw requests,
	 * if router (and probably vr) aborted
	 */
	if (sw->router->aborted)
		return -ENOENT;

	/* TODO: ipv6 key type check before call designated hw cb */
	return mvsw_pr_hw_lpm_add(sw, hw_vr_id, addr->u.ipv4,
				  prefix_len, grp_id);
}

int mvsw_pr_lpm_del(struct mvsw_pr_switch *sw, u16 hw_vr_id,
		    struct mvsw_pr_ip_addr *addr, u32 prefix_len)
{
	/* Dont waste time on hw requests,
	 * if router (and probably vr) aborted
	 */
	if (sw->router->aborted)
		return -ENOENT;

	/* TODO: ipv6 key type check before call designated hw cb */
	return mvsw_pr_hw_lpm_del(sw, hw_vr_id, addr->u.ipv4,
				  prefix_len);
}

int mvsw_pr_nh_entries_set(const struct mvsw_pr_switch *sw, int count,
			   struct mvsw_pr_neigh_info *nhs, u32 grp_id)
{
	/* Dont waste time on hw requests,
	 * if router (and probably vr) aborted
	 */
	if (sw->router->aborted)
		return -ENOENT;

	return mvsw_pr_hw_nh_entries_set(sw, count, nhs, grp_id);
}

int mvsw_pr_nh_entries_get(const struct mvsw_pr_switch *sw, int count,
			   struct mvsw_pr_neigh_info *nhs, u32 grp_id)
{
	/* Dont waste time on hw requests,
	 * if router (and probably vr) aborted
	 */
	if (sw->router->aborted)
		return -ENOENT;

	return mvsw_pr_hw_nh_entries_get(sw, count, nhs, grp_id);
}

int mvsw_pr_nh_group_create(const struct mvsw_pr_switch *sw, u16 nh_count,
			    u32 *grp_id)
{
	/* Dont waste time on hw requests,
	 * if router (and probably vr) aborted
	 */
	if (sw->router->aborted)
		return -ENOENT;

	return mvsw_pr_hw_nh_group_create(sw, nh_count, grp_id);
}

int mvsw_pr_nh_group_delete(const struct mvsw_pr_switch *sw, u16 nh_count,
			    u32 grp_id)
{
	/* Dont waste time on hw requests,
	 * if router (and probably vr) aborted
	 */
	if (sw->router->aborted)
		return -ENOENT;

	return mvsw_pr_hw_nh_group_delete(sw, nh_count, grp_id);
}

int mvsw_pr_mp4_hash_set(const struct mvsw_pr_switch *sw, u8 hash_policy)
{
	return mvsw_pr_hw_mp4_hash_set(sw, hash_policy);
}

int mvsw_pr_fdb_flush_vlan(struct mvsw_pr_switch *sw, u16 vid,
			   enum mvsw_pr_fdb_flush_mode mode)
{
	return mvsw_pr_hw_fdb_flush_vlan(sw, vid, mode);
}

int mvsw_pr_fdb_flush_port_vlan(struct mvsw_pr_port *port, u16 vid,
				enum mvsw_pr_fdb_flush_mode mode)
{
	if (mvsw_pr_port_is_lag_member(port))
		return mvsw_pr_hw_fdb_flush_lag_vlan(port->sw, port->lag_id,
						     vid, mode);
	else
		return mvsw_pr_hw_fdb_flush_port_vlan(port, vid, mode);
}

int mvsw_pr_fdb_flush_port(struct mvsw_pr_port *port,
			   enum mvsw_pr_fdb_flush_mode mode)
{
	if (mvsw_pr_port_is_lag_member(port))
		return mvsw_pr_hw_fdb_flush_lag(port->sw, port->lag_id, mode);
	else
		return mvsw_pr_hw_fdb_flush_port(port, mode);
}

int mvsw_pr_macvlan_add(const struct mvsw_pr_switch *sw, u16 vr_id,
			const u8 *mac, u16 vid)
{
	return mvsw_pr_hw_macvlan_add(sw, vr_id, mac,  vid);
}

int mvsw_pr_macvlan_del(const struct mvsw_pr_switch *sw, u16 vr_id,
			const u8 *mac, u16 vid)
{
	return mvsw_pr_hw_macvlan_del(sw, vr_id, mac,  vid);
}

static struct prestera_lag *
prestera_lag_get(struct mvsw_pr_switch *sw, u8 id)
{
	return id < sw->lag_max ? &sw->lags[id] : NULL;
}

static void mvsw_pr_port_lag_create(struct mvsw_pr_switch *sw, u16 lag_id,
				    struct net_device *lag_dev)
{
	INIT_LIST_HEAD(&sw->lags[lag_id].members);
	sw->lags[lag_id].dev = lag_dev;
}

static void mvsw_pr_port_lag_destroy(struct mvsw_pr_switch *sw, u16 lag_id)
{
	WARN_ON(!list_empty(&sw->lags[lag_id].members));
	sw->lags[lag_id].dev = NULL;
	sw->lags[lag_id].member_count = 0;
}

int prestera_lag_member_add(struct mvsw_pr_port *port,
			    struct net_device *lag_dev, u16 lag_id)
{
	struct mvsw_pr_switch *sw = port->sw;
	struct prestera_lag_member *member;
	struct prestera_lag *lag;

	lag = prestera_lag_get(sw, lag_id);

	if (lag->member_count >= sw->lag_member_max)
		return -ENOSPC;
	else if (!lag->member_count)
		mvsw_pr_port_lag_create(sw, lag_id, lag_dev);

	member = kzalloc(sizeof(*member), GFP_KERNEL);
	if (!member)
		return -ENOMEM;

	if (mvsw_pr_hw_lag_member_add(port, lag_id)) {
		kfree(member);
		if (!lag->member_count)
			mvsw_pr_port_lag_destroy(sw, lag_id);
		return -EBUSY;
	}

	member->port = port;
	list_add(&member->list, &lag->members);
	lag->member_count++;
	port->lag_id = lag_id;
	return 0;
}

int prestera_lag_member_del(struct mvsw_pr_port *port)
{
	struct mvsw_pr_switch *sw = port->sw;
	struct prestera_lag_member *member;
	struct list_head *pos, *n;
	u16 lag_id = port->lag_id;
	struct prestera_lag *lag;
	int err;

	lag = prestera_lag_get(sw, lag_id);
	if (!lag || !lag->member_count)
		return -EINVAL;

	err = mvsw_pr_hw_lag_member_del(port, lag_id);
	if (err)
		return err;

	lag->member_count--;
	port->lag_id = sw->lag_max;

	list_for_each_safe(pos, n, &lag->members) {
		member = list_entry(pos, typeof(*member), list);
		if (member->port->id == port->id) {
			list_del(&member->list);
			kfree(member);
			break;
		}
	}

	if (!lag->member_count) {
		prestera_lag_router_leave(sw, lag->dev);
		mvsw_pr_port_lag_destroy(sw, lag_id);
	}

	return 0;
}

int prestera_lag_member_enable(struct mvsw_pr_port *port, bool enable)
{
	return mvsw_pr_hw_lag_member_enable(port, port->lag_id, enable);
}

bool mvsw_pr_port_is_lag_member(const struct mvsw_pr_port *port)
{
	return port->lag_id < port->sw->lag_max;
}

int prestera_lag_id_find(struct mvsw_pr_switch *sw, struct net_device *lag_dev,
			 u16 *lag_id)
{
	struct prestera_lag *lag;
	int free_id = -1;
	int id;

	for (id = 0; id < sw->lag_max; id++) {
		lag = prestera_lag_get(sw, id);
		if (lag->member_count) {
			if (lag->dev == lag_dev) {
				*lag_id = id;
				return 0;
			}
		} else if (free_id < 0) {
			free_id = id;
		}
	}
	if (free_id < 0)
		return -ENOSPC;
	*lag_id = free_id;
	return 0;
}

void prestera_lag_member_rif_leave(const struct mvsw_pr_port *port,
				   u16 lag_id, u16 vr_id)
{
	mvsw_pr_hw_lag_member_rif_leave(port, lag_id, vr_id);
}

static int prestera_lag_init(struct mvsw_pr_switch *sw)
{
	sw->lags = kcalloc(sw->lag_max, sizeof(*sw->lags), GFP_KERNEL);
	return sw->lags ? 0 : -ENOMEM;
}

static void prestera_lag_fini(struct mvsw_pr_switch *sw)
{
	u8 idx;

	for (idx = 0; idx < sw->lag_max; idx++)
		WARN_ON(sw->lags[idx].member_count);

	kfree(sw->lags);
}

static int mvsw_pr_clear_ports(struct mvsw_pr_switch *sw)
{
	struct net_device *net_dev;
	struct list_head *pos, *n;
	struct mvsw_pr_port *port;

	list_for_each_safe(pos, n, &sw->port_list) {
		port = list_entry(pos, typeof(*port), list);
		net_dev = port->net_dev;

		cancel_delayed_work_sync(&port->cached_hw_stats.caching_dw);
		prestera_devlink_port_clear(port);
		unregister_netdev(net_dev);
#ifdef CONFIG_PHYLINK
		if (port->phy_link)
			phylink_destroy(port->phy_link);
#endif
		mvsw_pr_port_vlan_flush(port, true);
		WARN_ON_ONCE(!list_empty(&port->vlans_list));
		mvsw_pr_port_router_leave(port);
		prestera_devlink_port_unregister(port);
		free_netdev(net_dev);
		list_del(pos);
	}
	return (!list_empty(&sw->port_list));
}

static void mvsw_pr_port_handle_event(struct mvsw_pr_switch *sw,
				      struct mvsw_pr_event *evt, void *arg)
{
	struct mvsw_pr_port *port;
	struct delayed_work *caching_dw;

	port = __find_pr_port(sw, evt->port_evt.port_id);
	if (!port)
		return;

	caching_dw = &port->cached_hw_stats.caching_dw;

	switch (evt->id) {
	case MVSW_PORT_EVENT_STATE_CHANGED:
		port->hw_oper_state = evt->port_evt.data.oper_state;

		if (port->hw_oper_state) {
			port->hw_duplex = evt->port_evt.data.duplex;
			port->hw_speed = evt->port_evt.data.speed;
#ifdef CONFIG_PHYLINK
			if (port->caps.transceiver ==
			    MVSW_PORT_TRANSCEIVER_SFP)
				phylink_mac_change(port->phy_link, true);
			else
				netif_carrier_on(port->net_dev);
#else
			netif_carrier_on(port->net_dev);
#endif

			if (!delayed_work_pending(caching_dw))
				queue_delayed_work(mvsw_pr_wq, caching_dw, 0);
		} else {
			port->hw_duplex = 0;
			port->hw_speed = 0;
#ifdef CONFIG_PHYLINK
			if (port->caps.transceiver ==
			    MVSW_PORT_TRANSCEIVER_SFP)
				phylink_mac_change(port->phy_link, false);
			else
				netif_carrier_off(port->net_dev);
#else
			netif_carrier_off(port->net_dev);
#endif

			if (delayed_work_pending(caching_dw))
				cancel_delayed_work(caching_dw);
		}
		break;
	}
}

static bool prestera_lag_exists(const struct mvsw_pr_switch *sw, u16 lag_id)
{
	return lag_id < sw->lag_max &&
	       sw->lags[lag_id].member_count != 0;
}

static void mvsw_pr_fdb_handle_event(struct mvsw_pr_switch *sw,
				     struct mvsw_pr_event *evt, void *arg)
{
	struct switchdev_notifier_fdb_info info;
	struct net_device *dev = NULL;
	struct mvsw_pr_port *port;
	u16 lag_id;

	switch (evt->fdb_evt.type) {
	case MVSW_PR_FDB_ENTRY_TYPE_REG_PORT:
		port = __find_pr_port(sw, evt->fdb_evt.dest.port_id);
		if (port)
			dev = port->net_dev;
		break;
	case MVSW_PR_FDB_ENTRY_TYPE_LAG:
		lag_id = evt->fdb_evt.dest.lag_id;
		if (prestera_lag_exists(sw, lag_id))
			dev = sw->lags[lag_id].dev;
		break;
	default:
		return;
	}

	if (!dev)
		return;

	info.addr = evt->fdb_evt.data.mac;
	info.vid = evt->fdb_evt.vid;
	info.offloaded = true;

	rtnl_lock();
	switch (evt->id) {
	case MVSW_FDB_EVENT_LEARNED:
		call_switchdev_notifiers(SWITCHDEV_FDB_ADD_TO_BRIDGE,
					 dev, &info.info, NULL);
		break;
	case MVSW_FDB_EVENT_AGED:
		call_switchdev_notifiers(SWITCHDEV_FDB_DEL_TO_BRIDGE,
					 dev, &info.info, NULL);
		break;
	}
	rtnl_unlock();
}

int mvsw_pr_fdb_add(struct mvsw_pr_port *port, const unsigned char *mac,
		    u16 vid, bool dynamic)
{
	if (mvsw_pr_port_is_lag_member(port))
		return mvsw_pr_hw_lag_fdb_add(port->sw, port->lag_id,
					      mac, vid, dynamic);
	else
		return mvsw_pr_hw_fdb_add(port, mac, vid, dynamic);
}

int mvsw_pr_fdb_del(struct mvsw_pr_port *port, const unsigned char *mac,
		    u16 vid)
{
	if (mvsw_pr_port_is_lag_member(port))
		return mvsw_pr_hw_lag_fdb_del(port->sw, port->lag_id,
					      mac, vid);
	else
		return mvsw_pr_hw_fdb_del(port, mac, vid);
}

static void mvsw_pr_fdb_event_handler_unregister(struct mvsw_pr_switch *sw)
{
	mvsw_pr_hw_event_handler_unregister(sw, MVSW_EVENT_TYPE_FDB);
}

static void mvsw_pr_port_event_handler_unregister(struct mvsw_pr_switch *sw)
{
	mvsw_pr_hw_event_handler_unregister(sw, MVSW_EVENT_TYPE_PORT);
}

static void mvsw_pr_event_handlers_unregister(struct mvsw_pr_switch *sw)
{
	mvsw_pr_fdb_event_handler_unregister(sw);
	mvsw_pr_port_event_handler_unregister(sw);
}

static int mvsw_pr_fdb_event_handler_register(struct mvsw_pr_switch *sw)
{
	return mvsw_pr_hw_event_handler_register(sw, MVSW_EVENT_TYPE_FDB,
						 mvsw_pr_fdb_handle_event,
						 NULL);
}

static int mvsw_pr_port_event_handler_register(struct mvsw_pr_switch *sw)
{
	return mvsw_pr_hw_event_handler_register(sw, MVSW_EVENT_TYPE_PORT,
						 mvsw_pr_port_handle_event,
						 NULL);
}

static int mvsw_pr_event_handlers_register(struct mvsw_pr_switch *sw)
{
	int err;

	err = mvsw_pr_port_event_handler_register(sw);
	if (err)
		return err;

	err = mvsw_pr_fdb_event_handler_register(sw);
	if (err)
		goto err_fdb_handler_register;

	return 0;

err_fdb_handler_register:
	mvsw_pr_port_event_handler_unregister(sw);
	return err;
}

int mvsw_pr_schedule_dw(struct delayed_work *dwork, unsigned long delay)
{
	return queue_delayed_work(mvsw_pr_wq, dwork, delay);
}

const struct mvsw_pr_port *mvsw_pr_port_find(u32 dev_hw_id, u32 port_hw_id)
{
	struct mvsw_pr_port *port = NULL;
	struct mvsw_pr_switch *sw;

	list_for_each_entry(sw, &switches_registered, list) {
		list_for_each_entry(port, &sw->port_list, list) {
			if (port->hw_id == port_hw_id &&
			    port->dev_id == dev_hw_id)
				return port;
		}
	}
	return NULL;
}

static int mvsw_pr_sw_init_base_mac(struct mvsw_pr_switch *sw)
{
	struct device_node *mac_dev_np;
	u32 lsb;
	int err;

	if (sw->np) {
		mac_dev_np = of_parse_phandle(sw->np, "base-mac-provider", 0);
		if (mac_dev_np) {
			const char *base_mac;

			base_mac = of_get_mac_address(mac_dev_np);
			if (!IS_ERR(base_mac))
				ether_addr_copy(sw->base_mac, base_mac);
		}
	}

	if (!is_valid_ether_addr(sw->base_mac))
		eth_random_addr(sw->base_mac);

	lsb = sw->base_mac[ETH_ALEN - 1];
	if (lsb + sw->port_count + MVSW_PR_MAC_ADDR_OFFSET > 0xFF)
		sw->base_mac[ETH_ALEN - 1] = 0;

	err = mvsw_pr_hw_switch_mac_set(sw, sw->base_mac);
	if (err)
		return err;

	return 0;
}

static int mvsw_pr_init(struct mvsw_pr_switch *sw)
{
	u32 port;
	int err;

	sw->np = of_find_compatible_node(NULL, NULL, "marvell,prestera");

	err = mvsw_pr_hw_switch_init(sw);
	if (err) {
		dev_err(mvsw_dev(sw), "Failed to init Switch device\n");
		return err;
	}

	err = mvsw_pr_hw_switch_trap_policer_set(sw, trap_policer_profile);
	if (err) {
		dev_err(mvsw_dev(sw), "Failed to set trap policer profile\n");
		return err;
	}

	err = mvsw_pr_sw_init_base_mac(sw);
	if (err)
		return err;

	dev_info(mvsw_dev(sw), "Initialized Switch device\n");

	err = prestera_lag_init(sw);
	if (err)
		return err;

	err = prestera_switchdev_register(sw);
	if (err)
		return err;

	err = prestera_devlink_register(sw);
	if (err)
		goto err_devl_reg;

	INIT_LIST_HEAD(&sw->port_list);

	for (port = 0; port < sw->port_count; port++) {
		err = mvsw_pr_port_create(sw, port);
		if (err)
			goto err_ports_init;
	}

	err = mvsw_pr_rxtx_switch_init(sw);
	if (err)
		goto err_rxtx_init;

	err = mvsw_pr_event_handlers_register(sw);
	if (err)
		goto err_event_handlers;

	err = mvsw_pr_debugfs_init(sw);
	if (err)
		goto err_debugfs_init;

	err = prestera_acl_init(sw);
	if (err)
		goto err_acl_init;

	return 0;

err_acl_init:
err_debugfs_init:
	mvsw_pr_event_handlers_unregister(sw);
err_event_handlers:
	mvsw_pr_rxtx_switch_fini(sw);
err_rxtx_init:
err_ports_init:
	mvsw_pr_clear_ports(sw);
err_devl_reg:
	prestera_switchdev_unregister(sw);
	return err;
}

static void mvsw_pr_fini(struct mvsw_pr_switch *sw)
{
	mvsw_pr_debugfs_fini(sw);

	mvsw_pr_event_handlers_unregister(sw);

	mvsw_pr_clear_ports(sw);
	mvsw_pr_rxtx_switch_fini(sw);
	prestera_devlink_unregister(sw);
	prestera_switchdev_unregister(sw);
	prestera_acl_fini(sw);
	prestera_lag_fini(sw);
	of_node_put(sw->np);
}

int prestera_device_register(struct prestera_device *dev)
{
	struct mvsw_pr_switch *sw;
	int err;

	sw = prestera_devlink_alloc();
	if (!sw)
		return -ENOMEM;

	dev->priv = sw;
	sw->dev = dev;

	err = mvsw_pr_init(sw);
	if (err) {
		prestera_devlink_free(sw);
		return err;
	}

	list_add(&sw->list, &switches_registered);

	return 0;
}
EXPORT_SYMBOL(prestera_device_register);

void prestera_device_unregister(struct prestera_device *dev)
{
	struct mvsw_pr_switch *sw = dev->priv;

	list_del(&sw->list);
	mvsw_pr_fini(sw);
	prestera_devlink_free(sw);
}
EXPORT_SYMBOL(prestera_device_unregister);

static int __init mvsw_pr_module_init(void)
{
	int err;

	INIT_LIST_HEAD(&switches_registered);

	mvsw_pr_wq = alloc_workqueue(mvsw_driver_name, 0, 0);
	if (!mvsw_pr_wq)
		return -ENOMEM;

	err = mvsw_pr_rxtx_init();
	if (err) {
		pr_err("failed to initialize prestera rxtx\n");
		destroy_workqueue(mvsw_pr_wq);
		return err;
	}

	pr_info("Loading Marvell Prestera Switch Driver\n");
	return 0;
}

static void __exit mvsw_pr_module_exit(void)
{
	destroy_workqueue(mvsw_pr_wq);
	mvsw_pr_rxtx_fini();

	pr_info("Unloading Marvell Prestera Switch Driver\n");
}

module_init(mvsw_pr_module_init);
module_exit(mvsw_pr_module_exit);

MODULE_AUTHOR("Marvell Semi.");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Marvell Prestera switch driver");
MODULE_VERSION(PRESTERA_DRV_VER);

module_param(trap_policer_profile, byte, 0444);
