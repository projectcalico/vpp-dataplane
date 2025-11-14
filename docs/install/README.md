# Installing Calico/VPP

The generally recommanded installation for CalicoVPP is
with an operator. There is extensive documentation and
platform specific guides available on the [Calico documentation](https://docs.tigera.io/calico/latest/getting-started/kubernetes/vpp/getting-started).

## Node requirements

When Calico/VPP is deployed, one of the things that happens is that the
uplink interface vanishes from the root network namespace. Depending on the
uplink driver used, it is either moved to a different network namespace or it
vanishes completely from the kernel/os, and it gets replaced with a tap
interface with the same name, mac address and other attributes. This **Houdini Act**
may confuse the likes of `systemd-udevd`, `systemd-networkd` and `NetworkManager`
and produce undesirable effects impacting the deployment and/or the functioning
of the cluster.

Therefore, for successful deployment and functioning, Calico/VPP may require
some changes in the configuration of system services pertaining to networking:

- [udevd](udevd.md)
- [systemd-networkd](systemd-networkd.md)
- [NetworkManager](NetworkManager.md)

## Special installation usecases

Find non-operator, migration and developper installation
steps below.

- [Installing with a manifest](manifest_based_install.md)
- [Migrating to CalicoVPP](migrate_to_calicovpp.md)
- [Developper installation](../dev/developper_guide.md)
- [calicovppctl](calicovppctl.md)
