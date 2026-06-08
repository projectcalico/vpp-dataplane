# Weird DHCP/DNS issue - NetworkManager

As described in the [installation overview](README.md), Calico/VPP replaces the
uplink interface with a tap interface that has the same name, mac address and
other attributes. When `NetworkManager` manages the uplink, it re-processes this
"new" interface and can interfere with DNS and DHCP. This applies to any distro
that uses NetworkManager (Fedora/RHEL/CentOS/Rocky/AlmaLinux, and Debian/Ubuntu
when NetworkManager is the renderer).

## Symptom

After the uplink is replaced, `NetworkManager` may drop the DNS configuration
that was in effect on the original uplink, so name resolution stops working on
the node. Because container images and Calico components are pulled by name,
this typically surfaces as image-pull / registry-resolution failures exactly
when the dataplane comes up. If the uplink uses **dhcp**, the same loss of
management can extend to the address lease: on renewal `NetworkManager` may fail
to refresh the lease on the tap, ultimately **bricking** the node — the same
failure mode described for [systemd-networkd](systemd-networkd.md).

How the DNS loss manifests depends on the resolver stack:

- Where `NetworkManager` writes `/etc/resolv.conf` directly (typical on
  Fedora/RHEL/CentOS/Rocky/AlmaLinux), the file loses its `nameserver` entries.
- Where `systemd-resolved` owns `/etc/resolv.conf` (default on Debian/Ubuntu),
  `/etc/resolv.conf` is a symlink to a resolved stub and `NetworkManager` feeds
  DNS to `systemd-resolved`; the disruption is in what NM hands to resolved.

## Fix (recommended): keep NetworkManager from dropping DNS

**Per-connection (works on every distro, incl. systemd-resolved):** tell
`NetworkManager` to ignore DHCP-provided DNS on the uplink and set the resolvers
explicitly, so they survive the interface swap:

```bash
sudo nmcli connection modify <uplink-con> \
  ipv4.ignore-auto-dns yes ipv6.ignore-auto-dns yes
sudo nmcli connection modify <uplink-con> ipv4.dns "<your-resolver>"
sudo nmcli connection up <uplink-con>
```

**Fedora/RHEL family (NetworkManager writes resolv.conf):** alternatively stop
`NetworkManager` from rewriting the file and manage it yourself:

```bash
# /etc/NetworkManager/conf.d/90-dns-none.conf
[main]
dns=none
```

```bash
sudo systemctl reload NetworkManager
printf 'nameserver <your-resolver>\n' | sudo tee /etc/resolv.conf
```

**Debian/Ubuntu (systemd-resolved):** do not use `dns=none` or edit
`/etc/resolv.conf` (it is a symlink owned by `systemd-resolved`). Keep NM's
`systemd-resolved` integration and set the resolvers on the connection as in the
per-connection example above, or configure them in netplan when netplan renders
via NetworkManager (`renderer: NetworkManager`).

## Workaround (last resort): make resolv.conf immutable

On distros where `NetworkManager` writes `/etc/resolv.conf` directly, if it
keeps clobbering the file you can pin it:

```bash
sudo chattr +i /etc/resolv.conf
```

This is a blunt instrument — remember to `sudo chattr -i /etc/resolv.conf`
before any legitimate DNS change. Do **not** do this on systemd-resolved systems
(Debian/Ubuntu), where `/etc/resolv.conf` is a managed symlink.

## Static addressing before the dataplane is up

If a node needs a fixed address before Calico/VPP is running (for example the
node IP used as the kubeadm control-plane endpoint), add it to the
`NetworkManager` connection rather than relying on the dataplane. Use the
`ipv4` or `ipv6` keys to match your cluster's address family:

```bash
# IPv4
sudo nmcli connection modify <uplink-con> +ipv4.addresses <addr>/<prefix>
# IPv6 (e.g. a ULA in an IPv6 single-stack cluster)
sudo nmcli connection modify <uplink-con> +ipv6.addresses <addr>/<prefix>
sudo nmcli connection up <uplink-con>
```
