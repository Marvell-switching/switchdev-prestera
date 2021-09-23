// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

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
#include "prestera_ethtool.h"
#include "prestera_dsa.h"
#include "prestera_rxtx.h"
#include "prestera_drv_ver.h"
#include "prestera_counter.h"

static u8 trap_policer_profile = 1;

#define PRESTERA_MTU_DEFAULT 1536
#define PRESTERA_MAC_ADDR_OFFSET 4

#define PORT_STATS_CACHE_TIMEOUT_MS	(msecs_to_jiffies(1000))

static struct list_head switches_registered;

static const char prestera_driver_name[] = "mvsw_switchdev";

#define prestera_dev(sw)	((sw)->dev->dev)

static struct workqueue_struct *prestera_wq;

struct prestera_span_entry {
	struct list_head list;
	struct prestera_port *port;
	refcount_t ref_count;
	u8 id;
};

struct prestera_span {
	struct prestera_switch *sw;
	struct list_head entries;
};

struct prestera_port *dev_to_prestera_port(struct device *dev)
{
	struct net_device *net_dev;

	net_dev = container_of(dev, struct net_device, dev);

	return netdev_priv(net_dev);
}

static struct prestera_port *__find_pr_port(const struct prestera_switch *sw,
					    u32 port_id)
{
	struct prestera_port *port;

	list_for_each_entry(port, &sw->port_list, list) {
		if (port->id == port_id)
			return port;
	}

	return NULL;
}

static int prestera_port_open(struct net_device *dev)
{
	int err = 0;
#ifdef CONFIG_PHYLINK
	struct prestera_port *port = netdev_priv(dev);

	if (port->phy_link) {
		phylink_start(port->phy_link);
		/* port became up once mac_config called */
	} else {
		port->cfg_phy.admin = true;
		err = mvsw_pr_hw_port_phy_mode_set(port, true, port->autoneg,
						   port->cfg_phy.mode,
						   port->adver_link_modes);
	}
#else
	pr_err("Can't operate without phylink");
#endif

	netif_start_queue(dev);
	return err;
}

static int prestera_port_close(struct net_device *dev)
{
	int err = 0;
	struct prestera_port *port = netdev_priv(dev);
#ifdef CONFIG_PHYLINK
	struct prestera_port_mac_config cfg_mac;

	if (port->phy_link) {
		phylink_stop(port->phy_link);
		phylink_disconnect_phy(port->phy_link);
		/* TODO: can we use somethink, like phylink callback ? */
		/* ensure, that link is down */
		/* TODO: use macros for operations like admin down-up ? */
		prestera_port_cfg_mac_read(port, &cfg_mac);
		cfg_mac.admin = false;
		prestera_port_cfg_mac_write(port, &cfg_mac);
	} else {
		port->cfg_phy.admin = false;
		err = mvsw_pr_hw_port_phy_mode_set(port, false, port->autoneg,
						   port->cfg_phy.mode,
						   port->adver_link_modes);
	}
#else
	pr_err("Can't operate without phylink");
#endif

	prestera_fdb_flush_port(port, MVSW_PR_FDB_FLUSH_MODE_DYNAMIC);

	netif_stop_queue(dev);
	return err;
}

static netdev_tx_t prestera_port_xmit(struct sk_buff *skb,
				      struct net_device *dev)
{
	return prestera_rxtx_xmit(skb, netdev_priv(dev));
}

static int prestera_setup_tc(struct net_device *dev, enum tc_setup_type type,
			     void *type_data)
{
	struct prestera_port *port = netdev_priv(dev);

	switch (type) {
	case TC_SETUP_BLOCK:
		return prestera_setup_tc_block(port, type_data);
	default:
		return -EOPNOTSUPP;
	}
}

static void prestera_set_rx_mode(struct net_device *dev)
{
	/* TO DO: add implementation */
}

static int prestera_valid_mac_addr(struct prestera_port *port, u8 *addr)
{
	int err;

	if (!is_valid_ether_addr(addr))
		return -EADDRNOTAVAIL;

	err = memcmp(port->sw->base_mac, addr, ETH_ALEN - 1);
	if (err)
		return -EINVAL;

	return 0;
}

static int prestera_port_set_mac_address(struct net_device *dev, void *p)
{
	struct prestera_port *port = netdev_priv(dev);
	struct sockaddr *addr = p;
	int err;

	err = prestera_valid_mac_addr(port, addr->sa_data);
	if (err)
		return err;

	err = mvsw_pr_hw_port_mac_set(port, addr->sa_data);
	if (!err)
		memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);

	return err;
}

static int prestera_port_change_mtu(struct net_device *dev, int mtu)
{
	struct prestera_port *port = netdev_priv(dev);
	int err;

	if (port->sw->mtu_min <= mtu && mtu <= port->sw->mtu_max)
		err = mvsw_pr_hw_port_mtu_set(port, mtu);
	else
		err = -EINVAL;

	if (!err)
		dev->mtu = mtu;

	return err;
}

static void prestera_port_get_stats64(struct net_device *dev,
				      struct rtnl_link_stats64 *stats)
{
	struct prestera_port *port = netdev_priv(dev);
	struct prestera_port_stats *port_stats = &port->cached_hw_stats.stats;

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

static void prestera_port_get_hw_stats(struct prestera_port *port)
{
	mvsw_pr_hw_port_stats_get(port, &port->cached_hw_stats.stats);
}

static void update_stats_cache(struct work_struct *work)
{
	struct prestera_port *port =
		container_of(work, struct prestera_port,
			     cached_hw_stats.caching_dw.work);

	rtnl_lock();
	prestera_port_get_hw_stats(port);
	rtnl_unlock();

	queue_delayed_work(prestera_wq, &port->cached_hw_stats.caching_dw,
			   PORT_STATS_CACHE_TIMEOUT_MS);
}

static int prestera_port_get_stats_cpu_hit(const struct net_device *dev,
					   struct rtnl_link_stats64 *stats)
{
	struct prestera_port *port = netdev_priv(dev);
	u64 rx_packets, rx_bytes, tx_packets, tx_bytes;
	struct prestera_rxtx_stats *p;
	u32 tx_dropped = 0;
	unsigned int start;
	int i;

	for_each_possible_cpu(i) {
		p = per_cpu_ptr(port->rxtx_stats, i);
		do {
			start = u64_stats_fetch_begin_irq(&p->syncp);
			rx_packets = p->rx_packets;
			rx_bytes = p->rx_bytes;
			tx_packets = p->tx_packets;
			tx_bytes = p->tx_bytes;
		} while (u64_stats_fetch_retry_irq(&p->syncp, start));

		stats->rx_packets += rx_packets;
		stats->rx_bytes += rx_bytes;
		stats->tx_packets += tx_packets;
		stats->tx_bytes += tx_bytes;
		/* tx_dropped is u32, updated without syncp protection. */
		tx_dropped += p->tx_dropped;
	}
	stats->tx_dropped = tx_dropped;
	return 0;
}

static bool prestera_port_has_offload_stats(const struct net_device *dev,
					    int attr_id)
{
	return attr_id == IFLA_OFFLOAD_XSTATS_CPU_HIT;
}

static int prestera_port_get_offload_stats(int attr_id,
					   const struct net_device *dev,
					   void *sp)
{
	if (attr_id == IFLA_OFFLOAD_XSTATS_CPU_HIT)
		return prestera_port_get_stats_cpu_hit(dev, sp);

	return -EINVAL;
}

static int prestera_feature_hw_tc(struct net_device *dev, bool enable)
{
	struct prestera_port *port = netdev_priv(dev);

	if (!enable) {
		if (prestera_acl_block_rule_count(port->flow_block)) {
			netdev_err(dev, "Active offloaded tc filters, can't turn hw_tc_offload off\n");
			return -EINVAL;
		}
		prestera_acl_block_disable_inc(port->flow_block);
	} else {
		prestera_acl_block_disable_dec(port->flow_block);
	}
	return 0;
}

static int
prestera_handle_feature(struct net_device *dev,
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

static int prestera_set_features(struct net_device *dev,
				 netdev_features_t features)
{
	netdev_features_t oper_features = dev->features;
	int err = 0;

	err |= prestera_handle_feature(dev, features, NETIF_F_HW_TC,
				       prestera_feature_hw_tc);

	if (err) {
		dev->features = oper_features;
		return -EINVAL;
	}

	return 0;
}

static const struct net_device_ops prestera_netdev_ops = {
	.ndo_open = prestera_port_open,
	.ndo_stop = prestera_port_close,
	.ndo_start_xmit = prestera_port_xmit,
	.ndo_setup_tc = prestera_setup_tc,
	.ndo_change_mtu = prestera_port_change_mtu,
	.ndo_set_rx_mode = prestera_set_rx_mode,
	.ndo_get_stats64 = prestera_port_get_stats64,
	.ndo_set_features = prestera_set_features,
	.ndo_set_mac_address = prestera_port_set_mac_address,
	.ndo_has_offload_stats = prestera_port_has_offload_stats,
	.ndo_get_offload_stats = prestera_port_get_offload_stats,
	.ndo_get_devlink_port = prestera_devlink_get_port,
};

bool prestera_netdev_check(const struct net_device *dev)
{
	return dev->netdev_ops == &prestera_netdev_ops;
}

static int prestera_lower_dev_walk(struct net_device *dev,
				   struct netdev_nested_priv *priv)
{
	struct prestera_port **pport = (struct prestera_port **)priv->data;

	if (prestera_netdev_check(dev)) {
		*pport = netdev_priv(dev);
		return 1;
	}

	return 0;
}

struct prestera_port *prestera_port_dev_lower_find(struct net_device *dev)
{
	struct prestera_port *port = NULL;
	struct netdev_nested_priv priv = {
		.data = (void *)&port,
	};

	if (!dev)
		return NULL;

	if (prestera_netdev_check(dev))
		return netdev_priv(dev);

	netdev_walk_all_lower_dev(dev, prestera_lower_dev_walk, &priv);

	return port;
}

struct prestera_switch *prestera_switch_get(struct net_device *dev)
{
	struct prestera_port *port;

	port = prestera_port_dev_lower_find(dev);
	return port ? port->sw : NULL;
}

int prestera_port_cfg_mac_read(struct prestera_port *port,
			       struct prestera_port_mac_config *cfg)
{
	*cfg = port->cfg_mac;
	return 0;
}

int prestera_port_cfg_mac_write(struct prestera_port *port,
				struct prestera_port_mac_config *cfg)
{
	int err;

	err = mvsw_pr_hw_port_mac_mode_set(port, cfg->admin,
					   cfg->mode, cfg->inband, cfg->speed,
					   cfg->duplex, cfg->fec);
	if (err)
		return err;

	port->cfg_mac = *cfg;
	return 0;
}

/* TODO:  Rename, that it only for integral */
int prestera_port_autoneg_set(struct prestera_port *port, u64 link_modes)
{
	/* TODO: Need separate config flow
	 * for MAC-PHY link and PHY-PARTNER link
	 */
	if (port->autoneg == true && port->adver_link_modes == link_modes)
		return 0;

	if (mvsw_pr_hw_port_phy_mode_set(port, port->cfg_phy.admin,
					 true, 0, link_modes))
		return -EINVAL;

	/* TODO: move all this parameters to cfg_phy */
	port->autoneg = true;
	port->cfg_phy.mode = 0;
	port->adver_link_modes = link_modes;
	port->adver_fec = BIT(MVSW_PORT_FEC_OFF_BIT);
	return 0;
}

int prestera_port_learning_set(struct prestera_port *port, bool learn)
{
	return mvsw_pr_hw_port_learning_set(port, learn);
}

int prestera_port_uc_flood_set(struct prestera_port *port, bool flood)
{
	return mvsw_pr_hw_port_uc_flood_set(port, flood);
}

int prestera_port_mc_flood_set(struct prestera_port *port, bool flood)
{
	return mvsw_pr_hw_port_mc_flood_set(port, flood);
}

/* Isolation group - is set of ports,
 *  which can't comunicate with each other (symmetric).
 * On other hand - we can configure asymmetric isolation
 *  (when "default" and "filter" are equal).
 * But this feature (asymmetric) left for future.
 */
int prestera_port_isolation_grp_set(struct prestera_port *port,
				    u32 sourceid)
{
	int err;

	err = prestera_hw_port_srcid_default_set(port, sourceid);
	if (err)
		goto err_out;

	err = prestera_hw_port_srcid_filter_set(port, sourceid);
	if (err)
		goto err_out;

	return 0;

err_out:
	prestera_hw_port_srcid_default_set(port, PRESTERA_PORT_SRCID_ZERO);
	prestera_hw_port_srcid_filter_set(port, PRESTERA_PORT_SRCID_ZERO);
	return err;
}

int prestera_port_pvid_set(struct prestera_port *port, u16 vid)
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

int prestera_port_vid_stp_set(struct prestera_port *port, u16 vid, u8 state)
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

struct prestera_port_vlan*
prestera_port_vlan_find_by_vid(const struct prestera_port *port, u16 vid)
{
	struct prestera_port_vlan *port_vlan;

	list_for_each_entry(port_vlan, &port->vlans_list, list) {
		if (port_vlan->vid == vid)
			return port_vlan;
	}

	return NULL;
}

struct prestera_port_vlan*
prestera_port_vlan_create(struct prestera_port *port, u16 vid, bool untagged)
{
	struct prestera_port_vlan *port_vlan;
	int err;

	port_vlan = prestera_port_vlan_find_by_vid(port, vid);
	if (port_vlan)
		return ERR_PTR(-EEXIST);

	err = prestera_port_vlan_set(port, vid, true, untagged);
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
	prestera_port_vlan_set(port, vid, false, false);
	return ERR_PTR(err);
}

static void
prestera_port_vlan_cleanup(struct prestera_port_vlan *port_vlan)
{
	if (port_vlan->bridge_port)
		prestera_port_vlan_bridge_leave(port_vlan);
}

void prestera_port_vlan_destroy(struct prestera_port_vlan *port_vlan)
{
	struct prestera_port *port = port_vlan->mvsw_pr_port;
	u16 vid = port_vlan->vid;

	prestera_port_vlan_cleanup(port_vlan);
	list_del(&port_vlan->list);
	kfree(port_vlan);
	mvsw_pr_hw_vlan_port_set(port, vid, false, false);
}

int prestera_port_vlan_set(struct prestera_port *port, u16 vid,
			   bool is_member, bool untagged)
{
	return mvsw_pr_hw_vlan_port_set(port, vid, is_member, untagged);
}

#ifdef CONFIG_PHYLINK
static void prestera_link_validate(struct phylink_config *config,
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
		if (state->interface != PHY_INTERFACE_MODE_NA)
			phylink_set(mask, Autoneg);
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

static void prestera_mac_pcs_get_state(struct phylink_config *config,
				       struct phylink_link_state *state)
{
	struct net_device *ndev = to_net_dev(config->dev);
	struct prestera_port *port = netdev_priv(ndev);

	state->link = port->link_params.oper_state;
	state->pause = 0;

	if (port->link_params.oper_state) {
		/* AN is completed, when port is up */
		state->an_complete = port->autoneg;

		state->speed = port->link_params.speed;
		state->duplex = port->link_params.duplex;
	} else {
		state->an_complete = false;
		state->speed = SPEED_UNKNOWN;
		state->duplex = DUPLEX_UNKNOWN;
	}
}

static void prestera_mac_config(struct phylink_config *config,
				unsigned int an_mode,
				const struct phylink_link_state *state)
{
	struct net_device *ndev = to_net_dev(config->dev);
	struct prestera_port *port = netdev_priv(ndev);
	struct prestera_port_mac_config cfg_mac;

	prestera_port_cfg_mac_read(port, &cfg_mac);
	cfg_mac.admin = true;
	cfg_mac.mode = PRESTERA_MAC_MODE_MAX;
	cfg_mac.inband = false;
	cfg_mac.speed = 0;
	cfg_mac.duplex = DUPLEX_UNKNOWN;
	cfg_mac.fec = MVSW_PORT_FEC_OFF_BIT;

	/* See sfp_select_interface... fIt */
	switch (state->interface) {
	case PHY_INTERFACE_MODE_10GBASER:
		cfg_mac.mode = PRESTERA_MAC_MODE_SR_LR;
		cfg_mac.speed = SPEED_10000;
		if (state->speed == SPEED_1000)
			cfg_mac.mode = PRESTERA_MAC_MODE_1000BASE_X;
		if (state->speed == SPEED_2500) {
			cfg_mac.mode = PRESTERA_MAC_MODE_SGMII;
			cfg_mac.inband = true;
			cfg_mac.speed = SPEED_2500;
			cfg_mac.duplex = DUPLEX_FULL;
		}
		break;
	case PHY_INTERFACE_MODE_2500BASEX:
		/* But it seems to be not supported in HW */
		cfg_mac.mode = PRESTERA_MAC_MODE_SGMII;
		cfg_mac.inband = true;
		cfg_mac.speed = SPEED_2500;
		cfg_mac.duplex = DUPLEX_FULL;
		break;
	case PHY_INTERFACE_MODE_SGMII:
		cfg_mac.mode = PRESTERA_MAC_MODE_SGMII;
		cfg_mac.inband = true;
		break;
	case PHY_INTERFACE_MODE_1000BASEX:
		cfg_mac.mode = PRESTERA_MAC_MODE_1000BASE_X;
		cfg_mac.inband = state->an_enabled;
		break;
	default:
		cfg_mac.mode = PRESTERA_MAC_MODE_1000BASE_X;
	}

	prestera_port_cfg_mac_write(port, &cfg_mac);
}

int prestera_mac_finish(struct phylink_config *config, unsigned int mode,
			phy_interface_t iface)
{
	return 0;
}

static void prestera_mac_an_restart(struct phylink_config *config)
{
	/* No need to restart autoneg as it is always with the same parameters,
	 * because e.g. as for 1000baseX FC isn't supported. And for 1000baseT
	 * autoneg provided by external tranciever
	 */
}

static void prestera_mac_link_down(struct phylink_config *config,
				   unsigned int mode, phy_interface_t interface)
{
}

static void prestera_mac_link_up(struct phylink_config *config,
				 struct phy_device *phy,
				 unsigned int mode, phy_interface_t interface,
				 int speed, int duplex,
				 bool tx_pause, bool rx_pause)
{
}

static const struct phylink_mac_ops prestera_mac_ops = {
	.validate = prestera_link_validate,
	.mac_pcs_get_state = prestera_mac_pcs_get_state,
	.mac_config = prestera_mac_config,
	.mac_finish = prestera_mac_finish,
	.mac_an_restart = prestera_mac_an_restart,
	.mac_link_down = prestera_mac_link_down,
	.mac_link_up = prestera_mac_link_up,
};

static int prestera_port_sfp_bind(struct prestera_port *port)
{
	struct prestera_switch *sw = port->sw;
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
					  &prestera_mac_ops);
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
static int prestera_port_sfp_bind(struct prestera_port *port)
{
	return 0;
}
#endif

static void __prestera_ports_free(struct prestera_switch *sw);
static void __prestera_ports_unregister(struct prestera_switch *sw);

/* alloc structures and configure HW */
static int __prestera_ports_alloc(struct prestera_switch *sw)
{
	struct net_device *net_dev;
	struct prestera_port *port;
	struct prestera_port_mac_config cfg_mac;
	char *mac;
	int err;
	u32 id;

	for (id = 0; id < sw->port_count; id++) {
		net_dev = alloc_etherdev(sizeof(*port));
		if (!net_dev) {
			err = -ENOMEM;
			goto err_alloc_etherdev;
		}

		port = netdev_priv(net_dev);

		port->rxtx_stats =
			netdev_alloc_pcpu_stats(struct prestera_rxtx_stats);
		if (!port->rxtx_stats) {
			err = -ENOMEM;
			goto err_alloc_stats;
		}

		INIT_LIST_HEAD(&port->vlans_list);
		port->pvid = PRESTERA_DEFAULT_VID;
		port->net_dev = net_dev;
		port->id = id;
		port->sw = sw;
		port->lag_id = sw->lag_max;

		err = mvsw_pr_hw_port_info_get(port, &port->fp_id,
					       &port->hw_id, &port->dev_id);
		if (err) {
			dev_err(prestera_dev(sw),
				"Failed to get port(%u) info\n", id);
			goto err_port_info_get;
		}

		net_dev->needed_headroom = MVSW_PR_DSA_HLEN + 4;

		net_dev->features |= NETIF_F_NETNS_LOCAL | NETIF_F_HW_TC;
		net_dev->hw_features |= NETIF_F_HW_TC;
		net_dev->ethtool_ops = &prestera_ethtool_ops;
		net_dev->netdev_ops = &prestera_netdev_ops;
		SET_NETDEV_DEV(net_dev, sw->dev->dev);

		net_dev->mtu = min_t(unsigned int, sw->mtu_max,
				     PRESTERA_MTU_DEFAULT);
		net_dev->min_mtu = sw->mtu_min;
		net_dev->max_mtu = sw->mtu_max;

		err = mvsw_pr_hw_port_mtu_set(port, net_dev->mtu);
		if (err) {
			dev_err(prestera_dev(sw),
				"Failed to set port(%u) mtu\n", id);
			goto err_mtu_set;
		}

		/* Only 0xFF mac addrs are supported */
		if (port->fp_id >= 0xFF) {
			err = -ENOTSUPP;
			goto err_fp_check;
		}

		mac = net_dev->dev_addr;
		memcpy(mac, sw->base_mac, net_dev->addr_len);
		mac[net_dev->addr_len - 1] += port->fp_id +
					      PRESTERA_MAC_ADDR_OFFSET;

		err = mvsw_pr_hw_port_mac_set(port, mac);
		if (err) {
			dev_err(prestera_dev(sw),
				"Failed to set port(%u) mac addr\n", id);
			goto err_mac_set;
		}

		err = mvsw_pr_hw_port_cap_get(port, &port->caps);
		if (err) {
			dev_err(prestera_dev(sw),
				"Failed to get port(%u) caps\n", id);
			goto err_cap_set;
		}

#ifdef CONFIG_PHYLINK
		if (port->caps.transceiver != MVSW_PORT_TRANSCEIVER_SFP)
			netif_carrier_off(net_dev);
#else
		netif_carrier_off(net_dev);
#endif

		/* TODO: this is related only for phy */
		port->adver_link_modes = port->caps.supp_link_modes;
		port->adver_fec = 0;
		port->autoneg = true;

		/* initialize config mac */
		if (port->caps.transceiver != MVSW_PORT_TRANSCEIVER_SFP) {
			cfg_mac.admin = true;
			cfg_mac.mode = PRESTERA_MAC_MODE_INTERNAL;
		} else {
			cfg_mac.admin = false;
			cfg_mac.mode = PRESTERA_MAC_MODE_MAX;
		}
		cfg_mac.inband = false;
		cfg_mac.speed = 0;
		cfg_mac.duplex = DUPLEX_UNKNOWN;
		cfg_mac.fec = MVSW_PORT_FEC_OFF_BIT;

		err = prestera_port_cfg_mac_write(port, &cfg_mac);
		if (err) {
			dev_err(prestera_dev(sw),
				"Failed to set port(%u) mac mode\n", id);
			goto err_state_set;
		}

		/* initialize config phy (if this is inegral) */
		if (port->caps.transceiver != MVSW_PORT_TRANSCEIVER_SFP) {
			/* TODO: another parameters init */
			port->cfg_phy.admin = false;
			err = mvsw_pr_hw_port_phy_mode_set(port, false, false,
							   0, 0);
			if (err) {
				dev_err(prestera_dev(sw),
					"Failed to set port(%u) phy mode\n",
					id);
				goto err_state_set;
			}
		}

		prestera_port_uc_flood_set(port, false);
		prestera_port_mc_flood_set(port, false);

		INIT_DELAYED_WORK(&port->cached_hw_stats.caching_dw,
				  &update_stats_cache);

		/* We can list_add before netdev_register,
		 * as it done in deinit seq
		 */
		list_add_tail(&port->list, &sw->port_list);
	}

	return 0;

	/* rollback */
err_alloc_etherdev:
	while (!list_empty(&sw->port_list)) {
		port = list_last_entry(&sw->port_list, typeof(*port), list);
		net_dev = port->net_dev;

		list_del(&port->list);
err_state_set:
err_cap_set:
err_mac_set:
err_fp_check:
err_mtu_set:
err_port_info_get:
		free_percpu(port->rxtx_stats);
err_alloc_stats:
		free_netdev(net_dev);
	}

	return err;
}

/* propagate port to kernel */
static int __prestera_ports_register(struct prestera_switch *sw)
{
	struct prestera_port *port;
	int err;

	list_for_each_entry(port, &sw->port_list, list) {
		/* Believe, that traffic cannot be received on port before
		 * this point
		 */
		err = prestera_devlink_port_register(port);
		if (err)
			goto err_devlink_register;
	}

	rtnl_lock();
	list_for_each_entry(port, &sw->port_list, list) {
		err = register_netdevice(port->net_dev);
		if (err)
			goto err_register_netdevice;
	}
	rtnl_unlock();

	list_for_each_entry(port, &sw->port_list, list) {
		if (port->caps.transceiver == MVSW_PORT_TRANSCEIVER_SFP) {
			err = prestera_port_sfp_bind(port);
			if (err)
				goto err_sfp_bind;
		}

		prestera_devlink_port_set(port);
	}

	return 0;

err_sfp_bind:
	/* rollback */
	list_for_each_entry_continue_reverse(port, &sw->port_list, list)
		prestera_devlink_port_clear(port);

	rtnl_lock();
err_register_netdevice:
	/* rollback */
	list_for_each_entry_continue_reverse(port, &sw->port_list, list)
		unregister_netdevice(port->net_dev);
	rtnl_unlock();

err_devlink_register:
	/* rollback */
	list_for_each_entry_continue_reverse(port, &sw->port_list, list) {
#ifdef CONFIG_PHYLINK
		if (port->phy_link)
			phylink_destroy(port->phy_link);
#endif
		prestera_devlink_port_unregister(port);
	}

	return -ENOTSUPP;
}

static int prestera_ports_create(struct prestera_switch *sw)
{
	int err;

	err = __prestera_ports_alloc(sw);
	if (err)
		goto err_alloc;

	err = __prestera_ports_register(sw);
	if (err)
		goto err_register;

	return 0;

err_register:
	__prestera_ports_free(sw);
err_alloc:
	return err;
}

static void prestera_port_vlan_flush(struct prestera_port *port,
				     bool flush_default)
{
	struct prestera_port_vlan *port_vlan, *tmp;

	list_for_each_entry_safe(port_vlan, tmp, &port->vlans_list, list) {
		if (!flush_default && port_vlan->vid == PRESTERA_DEFAULT_VID)
			continue;

		prestera_port_vlan_destroy(port_vlan);
	}
}

int prestera_8021d_bridge_create(struct prestera_switch *sw, u16 *bridge_id)
{
	return mvsw_pr_hw_bridge_create(sw, bridge_id);
}

int prestera_8021d_bridge_delete(struct prestera_switch *sw, u16 bridge_id)
{
	return mvsw_pr_hw_bridge_delete(sw, bridge_id);
}

int prestera_8021d_bridge_port_add(struct prestera_port *port, u16 bridge_id)
{
	return mvsw_pr_hw_bridge_port_add(port, bridge_id);
}

int prestera_8021d_bridge_port_delete(struct prestera_port *port, u16 bridge_id)
{
	return mvsw_pr_hw_bridge_port_delete(port, bridge_id);
}

int prestera_switch_ageing_set(struct prestera_switch *sw, u32 ageing_time)
{
	return mvsw_pr_hw_switch_ageing_set(sw, ageing_time / 1000);
}

struct prestera_port *prestera_port_find_by_fp_id(u32 fp_id)
{
	struct prestera_port *port = NULL;
	struct prestera_switch *sw;

	list_for_each_entry(sw, &switches_registered, list) {
		list_for_each_entry(port, &sw->port_list, list) {
			if (port->fp_id == fp_id)
				return port;
		}
	}
	return NULL;
}

int prestera_dev_if_type(const struct net_device *dev)
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
		return prestera_dev_if_type(vlan->lowerdev);
	}
	else
		return MVSW_IF_PORT_E;
}

int prestera_lpm_add(struct prestera_switch *sw, u16 hw_vr_id,
		     struct prestera_ip_addr *addr, u32 prefix_len, u32 grp_id)
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

int prestera_lpm_del(struct prestera_switch *sw, u16 hw_vr_id,
		     struct prestera_ip_addr *addr, u32 prefix_len)
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

int prestera_nh_entries_set(const struct prestera_switch *sw, int count,
			    struct prestera_neigh_info *nhs, u32 grp_id)
{
	/* Dont waste time on hw requests,
	 * if router (and probably vr) aborted
	 */
	if (sw->router->aborted)
		return -ENOENT;

	return mvsw_pr_hw_nh_entries_set(sw, count, nhs, grp_id);
}

int prestera_nh_entries_get(const struct prestera_switch *sw, int count,
			    struct prestera_neigh_info *nhs, u32 grp_id)
{
	/* Dont waste time on hw requests,
	 * if router (and probably vr) aborted
	 */
	if (sw->router->aborted)
		return -ENOENT;

	return mvsw_pr_hw_nh_entries_get(sw, count, nhs, grp_id);
}

int prestera_nhgrp_blk_get(const struct prestera_switch *sw, u8 *hw_state,
			   u32 buf_size)
{
	/* Dont waste time on hw requests,
	 * if router (and probably vr) aborted
	 */
	if (sw->router->aborted)
		return -ENOENT;

	return mvsw_pr_hw_nhgrp_blk_get(sw, hw_state, buf_size);
}

int prestera_nh_group_create(const struct prestera_switch *sw, u16 nh_count,
			     u32 *grp_id)
{
	/* Dont waste time on hw requests,
	 * if router (and probably vr) aborted
	 */
	if (sw->router->aborted)
		return -ENOENT;

	return mvsw_pr_hw_nh_group_create(sw, nh_count, grp_id);
}

int prestera_nh_group_delete(const struct prestera_switch *sw, u16 nh_count,
			     u32 grp_id)
{
	/* Dont waste time on hw requests,
	 * if router (and probably vr) aborted
	 */
	if (sw->router->aborted)
		return -ENOENT;

	return mvsw_pr_hw_nh_group_delete(sw, nh_count, grp_id);
}

int prestera_mp4_hash_set(const struct prestera_switch *sw, u8 hash_policy)
{
	return mvsw_pr_hw_mp4_hash_set(sw, hash_policy);
}

int prestera_fdb_flush_vlan(struct prestera_switch *sw, u16 vid,
			    enum prestera_fdb_flush_mode mode)
{
	return mvsw_pr_hw_fdb_flush_vlan(sw, vid, mode);
}

int prestera_fdb_flush_port_vlan(struct prestera_port *port, u16 vid,
				 enum prestera_fdb_flush_mode mode)
{
	if (prestera_port_is_lag_member(port))
		return mvsw_pr_hw_fdb_flush_lag_vlan(port->sw, port->lag_id,
						     vid, mode);
	else
		return mvsw_pr_hw_fdb_flush_port_vlan(port, vid, mode);
}

int prestera_fdb_flush_port(struct prestera_port *port,
			    enum prestera_fdb_flush_mode mode)
{
	if (prestera_port_is_lag_member(port))
		return mvsw_pr_hw_fdb_flush_lag(port->sw, port->lag_id, mode);
	else
		return mvsw_pr_hw_fdb_flush_port(port, mode);
}

int prestera_macvlan_add(const struct prestera_switch *sw, u16 vr_id,
			 const u8 *mac, u16 vid)
{
	return mvsw_pr_hw_macvlan_add(sw, vr_id, mac,  vid);
}

int prestera_macvlan_del(const struct prestera_switch *sw, u16 vr_id,
			 const u8 *mac, u16 vid)
{
	return mvsw_pr_hw_macvlan_del(sw, vr_id, mac,  vid);
}

struct prestera_lag *prestera_lag_get(struct prestera_switch *sw, u8 id)
{
	return id < sw->lag_max ? &sw->lags[id] : NULL;
}

static void prestera_port_lag_create(struct prestera_switch *sw, u16 lag_id,
				     struct net_device *lag_dev)
{
	INIT_LIST_HEAD(&sw->lags[lag_id].members);
	sw->lags[lag_id].dev = lag_dev;
}

static void prestera_port_lag_destroy(struct prestera_switch *sw, u16 lag_id)
{
	WARN_ON(!list_empty(&sw->lags[lag_id].members));
	sw->lags[lag_id].dev = NULL;
	sw->lags[lag_id].member_count = 0;
}

int prestera_lag_member_add(struct prestera_port *port,
			    struct net_device *lag_dev, u16 lag_id)
{
	struct prestera_switch *sw = port->sw;
	struct prestera_lag_member *member;
	struct prestera_lag *lag;

	lag = prestera_lag_get(sw, lag_id);

	if (lag->member_count >= sw->lag_member_max)
		return -ENOSPC;
	else if (!lag->member_count)
		prestera_port_lag_create(sw, lag_id, lag_dev);

	member = kzalloc(sizeof(*member), GFP_KERNEL);
	if (!member)
		return -ENOMEM;

	if (mvsw_pr_hw_lag_member_add(port, lag_id)) {
		kfree(member);
		if (!lag->member_count)
			prestera_port_lag_destroy(sw, lag_id);
		return -EBUSY;
	}

	member->port = port;
	list_add(&member->list, &lag->members);
	lag->member_count++;
	port->lag_id = lag_id;
	return 0;
}

int prestera_lag_member_del(struct prestera_port *port)
{
	struct prestera_switch *sw = port->sw;
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
		prestera_port_lag_destroy(sw, lag_id);
	}

	return 0;
}

int prestera_lag_member_enable(struct prestera_port *port, bool enable)
{
	return mvsw_pr_hw_lag_member_enable(port, port->lag_id, enable);
}

bool prestera_port_is_lag_member(const struct prestera_port *port)
{
	return port->lag_id < port->sw->lag_max;
}

int prestera_lag_id_find(struct prestera_switch *sw, struct net_device *lag_dev,
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

void prestera_lag_member_rif_leave(const struct prestera_port *port,
				   u16 lag_id, u16 vr_id)
{
	mvsw_pr_hw_lag_member_rif_leave(port, lag_id, vr_id);
}

static int prestera_lag_init(struct prestera_switch *sw)
{
	sw->lags = kcalloc(sw->lag_max, sizeof(*sw->lags), GFP_KERNEL);
	return sw->lags ? 0 : -ENOMEM;
}

static void prestera_lag_fini(struct prestera_switch *sw)
{
	u8 idx;

	for (idx = 0; idx < sw->lag_max; idx++)
		WARN_ON(sw->lags[idx].member_count);

	kfree(sw->lags);
}

static int prestera_span_init(struct prestera_switch *sw)
{
	struct prestera_span *span;

	span = kzalloc(sizeof(*span), GFP_KERNEL);
	if (!span)
		return -ENOMEM;

	INIT_LIST_HEAD(&span->entries);

	sw->span = span;
	span->sw = sw;

	return 0;
}

static void prestera_span_fini(struct prestera_switch *sw)
{
	struct prestera_span *span = sw->span;

	WARN_ON(!list_empty(&span->entries));
	kfree(span);
}

static struct prestera_span_entry *
prestera_span_entry_create(struct prestera_port *port, u8 span_id)
{
	struct prestera_span_entry *entry;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	refcount_set(&entry->ref_count, 1);
	entry->port = port;
	entry->id = span_id;
	list_add_tail(&entry->list, &port->sw->span->entries);

	return entry;
}

static void prestera_span_entry_del(struct prestera_span_entry *entry)
{
	list_del(&entry->list);
	kfree(entry);
}

static struct prestera_span_entry *
prestera_span_entry_find_by_id(struct prestera_span *span, u8 span_id)
{
	struct prestera_span_entry *entry;

	list_for_each_entry(entry, &span->entries, list) {
		if (entry->id == span_id)
			return entry;
	}

	return NULL;
}

static struct prestera_span_entry *
prestera_span_entry_find_by_port(struct prestera_span *span,
				 struct prestera_port *port)
{
	struct prestera_span_entry *entry;

	list_for_each_entry(entry, &span->entries, list) {
		if (entry->port == port)
			return entry;
	}

	return NULL;
}

int prestera_span_get(struct prestera_port *port, u8 *span_id)
{
	u8 new_span_id;
	struct prestera_switch *sw = port->sw;
	struct prestera_span_entry *entry;
	int err;

	entry = prestera_span_entry_find_by_port(sw->span, port);
	if (entry) {
		refcount_inc(&entry->ref_count);
		*span_id = entry->id;
		return 0;
	}

	err = prestera_hw_span_get(port, &new_span_id);
	if (err)
		return err;

	entry = prestera_span_entry_create(port, new_span_id);
	if (IS_ERR(entry)) {
		prestera_hw_span_release(sw, new_span_id);
		return PTR_ERR(entry);
	}

	*span_id = new_span_id;
	return 0;
}

int prestera_span_put(const struct prestera_switch *sw, u8 span_id)
{
	struct prestera_span_entry *entry;
	int err;

	entry = prestera_span_entry_find_by_id(sw->span, span_id);
	if (!entry)
		return false;

	if (!refcount_dec_and_test(&entry->ref_count))
		return 0;

	err = prestera_hw_span_release(sw, span_id);
	if (err)
		return err;

	prestera_span_entry_del(entry);
	return 0;
}

/* "free" opposite to "alloc" */
static void __prestera_ports_free(struct prestera_switch *sw)
{
	struct net_device *net_dev;
	struct list_head *pos, *n;
	struct prestera_port *port;

	list_for_each_safe(pos, n, &sw->port_list) {
		port = list_entry(pos, typeof(*port), list);
		net_dev = port->net_dev;

		/* This is assymetric to create */
		prestera_port_vlan_flush(port, true);
		WARN_ON_ONCE(!list_empty(&port->vlans_list));
		prestera_port_router_leave(port);

		list_del(pos);
		free_percpu(port->rxtx_stats);
		free_netdev(net_dev);
	}
	WARN_ON(!list_empty(&sw->port_list));
}

/* propagate port to kernel */
static void __prestera_ports_unregister(struct prestera_switch *sw)
{
	struct prestera_port *port;

	list_for_each_entry(port, &sw->port_list, list) {
		/* assymetric to create */
		cancel_delayed_work_sync(&port->cached_hw_stats.caching_dw);

		prestera_devlink_port_clear(port);
	}

	rtnl_lock();
	list_for_each_entry(port, &sw->port_list, list)
		unregister_netdevice(port->net_dev);
	rtnl_unlock();

	list_for_each_entry(port, &sw->port_list, list) {
#ifdef CONFIG_PHYLINK
		if (port->phy_link)
			phylink_destroy(port->phy_link);
#endif
		prestera_devlink_port_unregister(port);
	}
}

static void prestera_clear_ports(struct prestera_switch *sw)
{
	__prestera_ports_unregister(sw);
	__prestera_ports_free(sw);
}

static void prestera_port_handle_event(struct prestera_switch *sw,
				       struct prestera_event *evt, void *arg)
{
	struct prestera_port *port;
	struct delayed_work *caching_dw;

	port = __find_pr_port(sw, evt->port_evt.port_id);
	if (!port)
		return;

	caching_dw = &port->cached_hw_stats.caching_dw;

	prestera_ethtool_port_state_changed(port, &evt->port_evt);

	switch (evt->id) {
	case MVSW_PORT_EVENT_STATE_CHANGED:

		if (port->link_params.oper_state) {
#ifdef CONFIG_PHYLINK
			if (port->phy_link)
				phylink_mac_change(port->phy_link, true);
			else
				netif_carrier_on(port->net_dev);
#else
			netif_carrier_on(port->net_dev);
#endif

			if (!delayed_work_pending(caching_dw))
				queue_delayed_work(prestera_wq, caching_dw, 0);
		} else {
#ifdef CONFIG_PHYLINK
			if (port->phy_link)
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

static bool prestera_lag_exists(const struct prestera_switch *sw, u16 lag_id)
{
	return lag_id < sw->lag_max &&
	       sw->lags[lag_id].member_count != 0;
}

static void prestera_fdb_handle_event(struct prestera_switch *sw,
				      struct prestera_event *evt, void *arg)
{
	struct switchdev_notifier_fdb_info info;
	struct net_device *dev = NULL;
	struct prestera_port *port;
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

int prestera_fdb_add(struct prestera_port *port, const unsigned char *mac,
		     u16 vid, bool dynamic)
{
	if (prestera_port_is_lag_member(port))
		return mvsw_pr_hw_lag_fdb_add(port->sw, port->lag_id,
					      mac, vid, dynamic);
	else
		return mvsw_pr_hw_fdb_add(port, mac, vid, dynamic);
}

int prestera_fdb_del(struct prestera_port *port, const unsigned char *mac,
		     u16 vid)
{
	if (prestera_port_is_lag_member(port))
		return mvsw_pr_hw_lag_fdb_del(port->sw, port->lag_id,
					      mac, vid);
	else
		return mvsw_pr_hw_fdb_del(port, mac, vid);
}

static void prestera_fdb_event_handler_unregister(struct prestera_switch *sw)
{
	mvsw_pr_hw_event_handler_unregister(sw, MVSW_EVENT_TYPE_FDB);
}

static void prestera_port_event_handler_unregister(struct prestera_switch *sw)
{
	mvsw_pr_hw_event_handler_unregister(sw, MVSW_EVENT_TYPE_PORT);
}

static void prestera_event_handlers_unregister(struct prestera_switch *sw)
{
	prestera_fdb_event_handler_unregister(sw);
	prestera_port_event_handler_unregister(sw);
}

static int prestera_fdb_event_handler_register(struct prestera_switch *sw)
{
	return mvsw_pr_hw_event_handler_register(sw, MVSW_EVENT_TYPE_FDB,
						 prestera_fdb_handle_event,
						 NULL);
}

static int prestera_port_event_handler_register(struct prestera_switch *sw)
{
	return mvsw_pr_hw_event_handler_register(sw, MVSW_EVENT_TYPE_PORT,
						 prestera_port_handle_event,
						 NULL);
}

static int prestera_event_handlers_register(struct prestera_switch *sw)
{
	int err;

	err = prestera_port_event_handler_register(sw);
	if (err)
		return err;

	err = prestera_fdb_event_handler_register(sw);
	if (err)
		goto err_fdb_handler_register;

	return 0;

err_fdb_handler_register:
	prestera_port_event_handler_unregister(sw);
	return err;
}

struct prestera_port *prestera_port_find(u32 dev_hw_id, u32 port_hw_id)
{
	struct prestera_port *port = NULL;
	struct prestera_switch *sw;

	list_for_each_entry(sw, &switches_registered, list) {
		list_for_each_entry(port, &sw->port_list, list) {
			if (port->hw_id == port_hw_id &&
			    port->dev_id == dev_hw_id)
				return port;
		}
	}
	return NULL;
}

static int prestera_sw_init_base_mac(struct prestera_switch *sw)
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
	if (lsb + sw->port_count + PRESTERA_MAC_ADDR_OFFSET > 0xFF)
		sw->base_mac[ETH_ALEN - 1] = 0;

	err = mvsw_pr_hw_switch_mac_set(sw, sw->base_mac);
	if (err)
		return err;

	return 0;
}

static int prestera_init(struct prestera_switch *sw)
{
	int err;

	sw->np = of_find_compatible_node(NULL, NULL, "marvell,prestera");

	err = mvsw_pr_hw_switch_init(sw);
	if (err) {
		dev_err(prestera_dev(sw), "Failed to init Switch device\n");
		return err;
	}

	err = mvsw_pr_hw_switch_trap_policer_set(sw, trap_policer_profile);
	if (err) {
		dev_err(prestera_dev(sw),
			"Failed to set trap policer profile\n");
		return err;
	}

	err = prestera_sw_init_base_mac(sw);
	if (err)
		return err;

	dev_info(prestera_dev(sw), "Initialized Switch device\n");

	err = prestera_lag_init(sw);
	if (err)
		return err;

	err = prestera_switchdev_register(sw);
	if (err)
		return err;

	err = prestera_devlink_register(sw);
	if (err)
		goto err_devl_reg;

	err = prestera_counter_init(sw);
	if (err)
		goto err_counter_init;

	err = prestera_acl_init(sw);
	if (err)
		goto err_acl_init;

	err = prestera_span_init(sw);
	if (err)
		goto err_span_init;

	INIT_LIST_HEAD(&sw->port_list);

	err = prestera_ports_create(sw);
	if (err)
		goto err_ports_init;

	err = prestera_rxtx_switch_init(sw);
	if (err)
		goto err_rxtx_init;

	err = prestera_event_handlers_register(sw);
	if (err)
		goto err_event_handlers;

	err = prestera_debugfs_init(sw);
	if (err)
		goto err_debugfs_init;

	return 0;

err_debugfs_init:
	prestera_event_handlers_unregister(sw);
err_event_handlers:
	prestera_rxtx_switch_fini(sw);
err_rxtx_init:
	prestera_clear_ports(sw);
err_ports_init:
	prestera_span_fini(sw);
err_span_init:
	prestera_acl_fini(sw);
err_acl_init:
	prestera_counter_fini(sw);
err_counter_init:
	prestera_devlink_unregister(sw);
err_devl_reg:
	prestera_switchdev_unregister(sw);
	return err;
}

static void prestera_fini(struct prestera_switch *sw)
{
	prestera_debugfs_fini(sw);

	prestera_event_handlers_unregister(sw);

	prestera_clear_ports(sw);
	prestera_rxtx_switch_fini(sw);
	prestera_devlink_unregister(sw);
	prestera_switchdev_unregister(sw);
	prestera_span_fini(sw);
	prestera_acl_fini(sw);
	prestera_counter_fini(sw);
	prestera_lag_fini(sw);
	mvsw_pr_hw_keepalive_fini(sw);
	prestera_hw_switch_reset(sw);
	of_node_put(sw->np);
}

int prestera_device_register(struct prestera_device *dev)
{
	struct prestera_switch *sw;
	int err;

	sw = prestera_devlink_alloc();
	if (!sw)
		return -ENOMEM;

	dev->priv = sw;
	sw->dev = dev;

	err = prestera_init(sw);
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
	struct prestera_switch *sw = dev->priv;

	list_del(&sw->list);
	prestera_fini(sw);
	prestera_devlink_free(sw);
}
EXPORT_SYMBOL(prestera_device_unregister);

static int __init prestera_module_init(void)
{
	INIT_LIST_HEAD(&switches_registered);

	prestera_wq = alloc_workqueue(prestera_driver_name, 0, 0);
	if (!prestera_wq)
		return -ENOMEM;

	pr_info("Loading Marvell Prestera Switch Driver\n");
	return 0;
}

static void __exit prestera_module_exit(void)
{
	destroy_workqueue(prestera_wq);

	pr_info("Unloading Marvell Prestera Switch Driver\n");
}

module_init(prestera_module_init);
module_exit(prestera_module_exit);

MODULE_AUTHOR("Marvell Semi.");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Marvell Prestera switch driver");
MODULE_VERSION(PRESTERA_DRV_VER);

module_param(trap_policer_profile, byte, 0444);
