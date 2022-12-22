# Switchdev-prestera
Marvell Prestera Switchdev Repository. 

For more information, please check our [wiki](../../wiki)

Features by Linux kernel version

| Kernel Version ||
| :-----------: | ------------- |
| 5.10 | Initial submition, support for Marvell Prestera 98DX326x. Features: [VLAN-aware/unaware bridge offloading, FDB](../../wiki/bridge-and-vlan), [Switchport configuration](../../wiki/switch-port-configuration)|
| 5.13 | Support for 98DX3265 |
| 5.14 | Add support for [LAG](../../wiki/link-aggregation-(lag)), [Devlink traps](../../wiki/Devlink), [ACL](../../wiki/ACL)|
| 5.17 | Migrate to new vTCAM api, ACL stats support, [flower template support](../../wiki/Chain-Support#chain-template-support), CPU routing |
| 5.18 | [Multi chain support](../../wiki/Chain-Support), Offload "local" and "blackhole" routes  |
| 5.19 | TC hardware stats support, [Traffic Policing](../../wiki/Traffic-Policing) |
| 6.0  | Bridge MDB offloading, [PhyLink support](https://www.kernel.org/doc/html/latest/networking/sfp-phylink.html),  Support for for Aldrin2 (98DX8525) |
| 6.1  | [L3 offloading](https://github.com/Marvell-switching/switchdev-prestera/wiki/l3-configuration) only for switchports |
| 6.2  | Support for AC5X family devices |

Features by driver version


| Driver Version ||
| ------------- | ------------- |
| 2.6.0(dentOS v1.0 Arthur) |  Based on Linux kernel 5.6    Features: [VLAN-aware/unaware bridge offloading, FDB](../../wiki/bridge-and-vlan), [Switchport configuration](../../wiki/switch-port-configuration), [LAG](../../wiki/link-aggregation-(lag)), [STP](../../wiki/STP-Configuration), [LLDP](../../wiki/link-layer-discovery-protocol-(lldp)), [IPv4 routing](../../wiki/static-route), [ECMP](../../wiki/equal-cost-multi-path-(ecmp)), [VRRP](../../wiki/virtual-router-redundancy-protocol-(vrrp)), [ACL](../../wiki/ACL), [Devlink traps](../../wiki/Devlink)|
| 3.1.1  (dentOS v2 Beeblebrox) | Based on Linux Kernel 5.10  New Features: [NAT](../../wiki/NAT-overview), [Multi chain support](../../wiki/Chain-Support) [Chain Templates](../../wiki/Chain-Support#chain-template-support), [PhyLink support](https://www.kernel.org/doc/html/latest/networking/sfp-phylink.html) |
| 3.2.2 (dentOS v2.5) | Based on Linux Kernel 5.15  Feature equivalent to DENT 2.5 |
| 4.0.3| Based on Linux Kernel 5.15 [DHCP](https://github.com/Marvell-switching/switchdev-prestera/wiki/DHCP), [Port Isolation](https://github.com/Marvell-switching/switchdev-prestera/wiki/port-isolation), [IGMP Snooping MDB](https://github.com/Marvell-switching/switchdev-prestera/wiki/IGMP-Snooping-MDB), [SPAN](https://github.com/Marvell-switching/switchdev-prestera/wiki/SPAN), [IPv6](https://github.com/Marvell-switching/switchdev-prestera/wiki/l3-configuration#ipv6), [QoS](https://github.com/Marvell-switching/switchdev-prestera/wiki/QoS) |

Please use GitHub [issues](../../issues) to report issues/request new enhancements.
