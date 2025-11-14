# Weird DHCP/DNS issue - systemd-networkd

Usually, the `[Match]` section of the `.network` file is configured with either
the **MACAddress** or the interface **Name** keys:

```bash
[Match]
MACAddress=0a:bb:f2:cf:bb:01
```

```bash
[Match]
Name=ens5
```

So, when the uplink interface gets replaced with the tap interface and since the
tap interface has the same attributes as the uplink interface, `systemd-networkd`
is happy and things are ok.

But when the `[Match]` section is configured with something like
**PermanentMACAddress** key

```bash
[Match]
PermanentMACAddress=0a:bb:f2:cf:bb:01
```

which is not supported with virtual interfaces like tap/tun

```bash
$ ethtool -P ens5
Permanent address: not set
$
```

then the match will fail and `systemd-networkd` will not **manage** the tap interface,

```bash
$ networkctl
IDX LINK    TYPE     OPERATIONAL SETUP
  1 lo      loopback carrier     unmanaged
  3 docker0 bridge   no-carrier  unmanaged
  4 ens5    ether    routable    unmanaged

3 links listed.
$
```

This can lead to two very undesirable consequences:

1. DNS config is wiped off leading to DNS failures
2. If uplink is configured using **dhcp** then upon lease expiry, since `systemd-networkd`
   is not **managing** the interface, it will not do the dhcp lease renewal thus
   ultimately **bricking** the node.

In order to prevent the above from happening, create a `.network` file for the
tap interface under `/etc/systemd/network` and configure the `[Match]` section
with either the interface **Name** or **MACAddress** key. For example, say, the uplink
interface is `ens5` and its `.network` file is `/run/systemd/network/10-netplan-ens5.network`
then first copy this file to `/etc/systemd/network` and rename it:

```bash
sudo cp /run/systemd/network/10-netplan-ens5.network /etc/systemd/network/ens5.network
```

Secondly, in the file `/etc/systemd/network/ens5.network`, remove the
**PermanentMACAddress** key in the `[Match]` section and add the **Name** key
if not present already:

```bash
$ sdiff /run/systemd/network/10-netplan-ens5.network    /etc/systemd/network/ens5.network

[Match]                            [Match]
PermanentMACAddress=0a:bb:f2:cf:bb:01         <
Name=ens5                           Name=ens5

[Network]                           [Network]
DHCP=ipv4                           DHCP=ipv4
LinkLocalAddressing=ipv6                 LinkLocalAddressing=ipv6

[DHCP]                            [DHCP]
RouteMetric=100                       RouteMetric=100
UseMTU=true                           UseMTU=true
$
```

And then

```bash
sudo systemctl daemon-reload
sudo systemctl restart systemd-networkd
```
