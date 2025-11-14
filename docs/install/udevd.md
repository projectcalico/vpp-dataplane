# Introduction

Calico/VPP deployment replaces the uplink interface with a tap interface which
has the same name, mac address and other attributes. Most of the time there are no
issues.

However, with certain NICs (Intel **E810**, for example) and when **multiple workers**
are configured in `VPP` and when **MACAddressPolicy=persistent** is set in the
`.link` file, then there's a potential race condition between `udevd` and `VPP`
in setting the mac address of the tap interface which causes network connectivity
issues ultimately leading to cluster deployment failure.

## Pre-requisite conditions for the race condition

- uplink interface of cluster uses problematic NIC (eg, Intel **E810**)
- `VPP` configured with multiple workers, for e.g.,

   ```bash
   cpu { workers 2 }
   ```

- **MACAddressPolicy=persistent** in the NIC's or the system default `.link`
  file, for e.g.,

  ```bash
  $ cat /usr/lib/systemd/network/99-default.link
  [Match]
  OriginalName=*

  [Link]
  NamePolicy=keep kernel database onboard slot path
  AlternativeNamesPolicy=database onboard slot path
  MACAddressPolicy=persistent
  $
  ```

## Race-condition

During Calico/VPP deployment, when `VPP` gets to run first, it sets the mac
address of the tap interface and then `udevd` runs and sees that mac address is
already set and it prods along and the cluster comes up fine:

```text
Nov 04 14:24:59 vpp-m7-9 systemd-udevd[43843]: ens2f0: MAC on the device
already set by userspace
```

But when `udevd` runs first, **MACAddressPolicy=persistent** causes it to
generate a **persistent** mac address for the tap interface:

```text
Nov 04 14:26:51 vpp-m7-9 systemd-udevd[44477]: ens2f0: Using generated
persistent MAC address
```

Now, the udevd generated mac address is different from the uplink's original
mac address which is programmed inside `VPP` and this mis-match causes packets
to be dropped resulting in network connectivity failure.

## What needs to be done?

Setting the **MACAddressPolicy=none** for the problematic NIC prevents `udevd`
from trying to generate mac address preventing the race-condition.

Create a `.link` file for the NIC under `/etc/systemd/network/` dir with
**MACAddressPolicy=none** and **Driver=tun** under the `[Match]` section. For
  e.g.,

  ```bash
  $ sudo cat /etc/systemd/network/10-ens2f0.link
   [Match]
   Driver=tun

   [Link]
   NamePolicy=keep
   MACAddressPolicy=none
  $
  ```

And finally,

```bash
sudo systemctl daemon-reload
sudo systemctl restart systemd-udevd
```

**Note:** The **MACAddressPolicy=persistent** was not present in Ubuntu 20.04
and seems to have been introduced from Ubuntu 22.04.
