# Switchdev-prestera
Marvell Prestera Switchdev Repository. 

https://github.com/Marvell-switching/Switchdev-prestera/wiki

Features by Linux kernel version

| Kernel Version ||
| ------------- | ------------- |
| 5.10 | Initial submition, support for Marvell Prestera 98DX326x. Features: [VLAN-aware/unaware bridge offloading, FDB](https://github.com/Marvell-switching/switchdev-prestera/wiki/bridge-and-vlan), [Switchport configuration](https://github.com/Marvell-switching/switchdev-prestera/wiki/switch-port-configuration)
  |
| 5.13 | Support for 98DX3265 |
| 5.14 | Add support for [LAG](https://github.com/Marvell-switching/switchdev-prestera/wiki/link-aggregation-(lag)), [Devlink traps](https://github.com/Marvell-switching/switchdev-prestera/wiki/Devlink), [ACL](https://github.com/Marvell-switching/switchdev-prestera/wiki/ACL)|
| 5.17|migrate to new vTCAM api, ACL stats support, [flower template support](https://github.com/Marvell-switching/switchdev-prestera/wiki/Chain-Support#chain-template-support), CPU routing |

Features by driver version


| Driver Version ||
| ------------- | ------------- |
| 2.6.0(dentOS v1.0 Arthur) |  Based on Linux kernel 5.6    Features: [VLAN-aware/unaware bridge offloading, FDB](https://github.com/Marvell-switching/switchdev-prestera/wiki/bridge-and-vlan), [Switchport configuration](https://github.com/Marvell-switching/switchdev-prestera/wiki/switch-port-configuration), [LAG](https://github.com/Marvell-switching/switchdev-prestera/wiki/link-aggregation-(lag)), [STP](https://github.com/Marvell-switching/switchdev-prestera/wiki/STP-Configuration), [LLDP](https://github.com/Marvell-switching/switchdev-prestera/wiki/link-layer-discovery-protocol-(lldp)), [IPv4 routing](https://github.com/Marvell-switching/switchdev-prestera/wiki/static-route), [ECMP](https://github.com/Marvell-switching/switchdev-prestera/wiki/equal-cost-multi-path-(ecmp)), [VRRP](https://github.com/Marvell-switching/switchdev-prestera/wiki/virtual-router-redundancy-protocol-(vrrp)), [ACL](https://github.com/Marvell-switching/switchdev-prestera/wiki/ACL), [Devlink traps](https://github.com/Marvell-switching/switchdev-prestera/wiki/Devlink)|
| 3.1.1  (dentOS v2 Beeblebrox) | Based on Linux Kernel 5.10  New Features: [NAT](https://github.com/Marvell-switching/switchdev-prestera/wiki/NAT-overview), [Multi chain support](https://github.com/Marvell-switching/switchdev-prestera/wiki/Chain-Support) [Chain Templates](https://github.com/Marvell-switching/switchdev-prestera/wiki/Chain-Support#chain-template-support), [PhyLink support](https://www.kernel.org/doc/html/latest/networking/sfp-phylink.html) |

Please use github [issues](https://github.com/Marvell-switching/switchdev-prestera/issues) to report issues/request a feature