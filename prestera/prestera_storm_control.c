// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/* Copyright (c) 2019-2021 Marvell International Ltd. All rights reserved */

#include "prestera_storm_control.h"
#include "prestera_hw.h"

#define SYSFS_ATTR_MODE		0644

static ssize_t storm_control_attr_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t size);
static ssize_t storm_control_attr_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buf);

struct strom_control_attributes {
	u32 bc_kbyte_per_sec_rate;
	u32 unknown_uc_kbyte_per_sec_rate;
	u32 unreg_mc_kbyte_per_sec_rate;
};

struct prestera_storm_control {
	struct prestera_switch *sw;
	struct strom_control_attributes *attribute_values;
};

static DEVICE_ATTR(broadcast_kbyte_per_sec_rate, SYSFS_ATTR_MODE,
		   storm_control_attr_show, storm_control_attr_store);

static DEVICE_ATTR(unknown_unicast_kbyte_per_sec_rate, SYSFS_ATTR_MODE,
		   storm_control_attr_show, storm_control_attr_store);

static DEVICE_ATTR(unregistered_multicast_kbyte_per_sec_rate, SYSFS_ATTR_MODE,
		   storm_control_attr_show, storm_control_attr_store);

static struct attribute *prestera_sw_dev_attrs[] = {
	&dev_attr_broadcast_kbyte_per_sec_rate.attr,
	&dev_attr_unknown_unicast_kbyte_per_sec_rate.attr,
	&dev_attr_unregistered_multicast_kbyte_per_sec_rate.attr,
	NULL
};

static struct attribute_group prestera_sw_dev_attr_group = {
	.name = "storm_control", /* we want them in subdirectory */
	.attrs = prestera_sw_dev_attrs,
};

static ssize_t storm_control_attr_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t size)
{
	struct prestera_port *port = dev_to_prestera_port(dev);
	struct strom_control_attributes *sc_attr;
	struct prestera_storm_control *sc;
	u32 *attr_to_change = NULL;
	u32 kbyte_per_sec_rate;
	ssize_t ret = -EINVAL;
	u32 storm_type;

	if (!port)
		return -EINVAL;

	sc = port->sw->storm_control;
	sc_attr = &sc->attribute_values[port->fp_id];

	ret = kstrtou32(buf, 10, &kbyte_per_sec_rate);
	if (ret)
		return ret;

	if (!strcmp(attr->attr.name, "broadcast_kbyte_per_sec_rate")) {
		attr_to_change = &sc_attr->bc_kbyte_per_sec_rate;
		storm_type = PRESTERA_PORT_STORM_CTL_TYPE_BC;
	}

	if (!strcmp(attr->attr.name, "unknown_unicast_kbyte_per_sec_rate")) {
		attr_to_change = &sc_attr->unknown_uc_kbyte_per_sec_rate;
		storm_type = PRESTERA_PORT_STORM_CTL_TYPE_UC_UNK;
	}

	if (!strcmp(attr->attr.name,
		    "unregistered_multicast_kbyte_per_sec_rate")) {
		attr_to_change = &sc_attr->unreg_mc_kbyte_per_sec_rate;
		storm_type = PRESTERA_PORT_STORM_CTL_TYPE_MC;
	}

	if (!attr_to_change)
		return -EINVAL;

	if (kbyte_per_sec_rate != *attr_to_change)
		ret = prestera_hw_port_storm_control_cfg_set(port, storm_type,
							     kbyte_per_sec_rate);
	else
		return size;

	if (ret)
		return ret;

	*attr_to_change = kbyte_per_sec_rate;

	return size;
}

static ssize_t storm_control_attr_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	struct prestera_port *port = dev_to_prestera_port(dev);
	struct strom_control_attributes *sc_attr;
	struct prestera_storm_control *sc;

	if (!port)
		return -EINVAL;

	sc = port->sw->storm_control;

	sc_attr = &sc->attribute_values[port->fp_id];

	if (!strcmp(attr->attr.name, "broadcast_kbyte_per_sec_rate"))
		return sprintf(buf, "%u\n", sc_attr->bc_kbyte_per_sec_rate);

	if (!strcmp(attr->attr.name, "unknown_unicast_kbyte_per_sec_rate"))
		return sprintf(buf, "%u\n",
			       sc_attr->unknown_uc_kbyte_per_sec_rate);

	if (!strcmp(attr->attr.name,
		    "unregistered_multicast_kbyte_per_sec_rate"))
		return sprintf(buf, "%u\n",
			       sc_attr->unreg_mc_kbyte_per_sec_rate);

	return -EINVAL;
}

int prestera_storm_control_init(struct prestera_switch *sw)
{
	struct prestera_storm_control *sc;
	struct prestera_port *port;
	int err;

	sc = kzalloc(sizeof(*sc), GFP_KERNEL);
	if (!sc)
		return -ENOMEM;

	sc->attribute_values = kcalloc(sw->port_count,
				       sizeof(*sc->attribute_values),
				       GFP_KERNEL);
	if (!sc->attribute_values) {
		err = -ENOMEM;
		goto err_values_alloca;
	}

	list_for_each_entry(port, &sw->port_list, list) {
		err = sysfs_create_group(&port->net_dev->dev.kobj,
					 &prestera_sw_dev_attr_group);
		if (err) {
			pr_err("Failed to create sysfs group for %s\n",
			       dev_name(&port->net_dev->dev));
			goto err_group_create;
		}
	}

	sc->sw = sw;
	sw->storm_control = sc;

	return 0;

err_group_create:
	list_for_each_entry_continue_reverse(port, &sw->port_list, list) {
		sysfs_remove_group(&port->net_dev->dev.kobj,
				   &prestera_sw_dev_attr_group);
	}
	kfree(sc->attribute_values);
err_values_alloca:
	kfree(sc);
	return err;
}

void prestera_storm_control_fini(struct prestera_switch *sw)
{
	struct prestera_storm_control *sc = sw->storm_control;
	struct prestera_port *port;

	list_for_each_entry(port, &sw->port_list, list)
		sysfs_remove_group(&port->net_dev->dev.kobj,
				   &prestera_sw_dev_attr_group);

	kfree(sc->attribute_values);
	kfree(sc);
}

