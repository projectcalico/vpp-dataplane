# Troubleshooting BGP in CalicoVPP

*This document assumes that you have installed [calicovppctl](../install/calicovppctl.md)*

If you suspect a routing issue in CalicoVPP, here are the CLIs
you should use to  print the status of VPP's FIB.

You can find [diagrams of the networking model here](README.md)

## Printing the available VRFs

- Table ``0`` is the default VRF (uplink and tunnels to other nodes)
- Table ``punt-table-ip4`` is the PUNT table (traffic to the host or to VCL pods)
- Table ``calico-pods-ip4`` is the indirection table preventing asymetric
traffic from pods to nodeIPs
- Each pod then has its own VRF, and an extra ``RPF`` VRF for uRPF checks

```bash
$ calicovppctl vppctl -node worker-1 show ip table
[0] table_id:0 ipv4-VRF:0
[1] table_id:1 punt-table-ip4
[2] table_id:2 calico-pods-ip4
[3] table_id:1013904223 host-tap-eth0-ip4
[4] table_id:3519870697 lRt7kASY-4-eth0-cni-e7889c4d-23e7-aca2-63c8-f3fd2fb1be7e
[5] table_id:1649599747 +rASbR73-4-eth0RPF-cni-e7889c4d-23e7-aca2-63c8-f3fd2fb1be7e

$ calicovppctl vppctl -node worker-1 show ip6 table
[0] table_id:0 ipv6-VRF:0
[1] table_id:1 punt-table-ip6
[2] table_id:2 calico-pods-ip6
[3] table_id:4294967295 IP6-link-local:host-eth0
[4] table_id:1196435762 host-tap-eth0-ip6
[5] table_id:4294967295 IP6-link-local:tap0
[6] table_id:2868466484 yyGDpSt6-6-eth0-cni-e7889c4d-23e7-aca2-63c8-f3fd2fb1be7e
[7] table_id:4294967295 IP6-link-local:loop0
[8] table_id:2670642822 CKupykOV-6-eth0RPF-cni-e7889c4d-23e7-aca2-63c8-f3fd2fb1be7e
 ^     ^
 |     |_table_id
 |__fib index
```

### Finding a pod fib index by IP

In order to find a pod's VRF knowing its IP address, you should use the fib-index
As an example, searching for ``11.0.0.1`` yields ``fib-idex 4`` (in IPV4)
You should ignore the output for table-id which has a formatting issue.

````bash
$ calicovppctl vppctl -node worker-1 show int addr | grep 11.0.0.1
  L3 11.0.0.1/32 ip4 table-id -775096599 fib-idx 4
  L3 11.0.0.1/32 ip4 table-id -775096599 fib-idx 4
````

## Showing routes

### Pod VRF routes

Below are typical routes in a given pod VRF, ``default route lookup in calico-pods-ip{46}``
The ``dpo-drop`` are expected.

````bash
$ calicovppctl vppctl show ip fib index 4
lRt7kASY-4-eth0-cni-e7889c4d-23e7-aca2-63c8-f3fd2fb1be7e, fib_index:4, 
flow hash:[src dst sport dport proto flowlabel ] epoch:0 flags:none
locks:[interface:2, API:1, ]
0.0.0.0/0
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:63 buckets:1 uRPF:86 to:[0:0]]
    [0] [@12]: dst-address,unicast lookup in calico-pods-ip4
0.0.0.0/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:64 buckets:1 uRPF:77 to:[0:0]]
    [0] [@0]: dpo-drop ip4
224.0.0.0/4
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:66 buckets:1 uRPF:79 to:[0:0]]
    [0] [@0]: dpo-drop ip4
240.0.0.0/4
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:65 buckets:1 uRPF:78 to:[0:0]]
    [0] [@0]: dpo-drop ip4
255.255.255.255/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:67 buckets:1 uRPF:80 to:[0:0]]
    [0] [@0]: dpo-drop ip4

$ calicovppctl vppctl show ip6 fib index 6
yyGDpSt6-6-eth0-cni-e7889c4d-23e7-aca2-63c8-f3fd2fb1be7e, fib_index:6,
flow hash:[src dst sport dport proto flowlabel ] epoch:0 flags:none
locks:[interface:2, API:1, ]
::/0
  unicast-ip6-chain
  [@0]: dpo-load-balance: [proto:ip6 index:72 buckets:1 uRPF:88 to:[0:0]]
    [0] [@19]: dst-address,unicast lookup in calico-pods-ip6
fe80::/10
  unicast-ip6-chain
  [@0]: dpo-load-balance: [proto:ip6 index:73 buckets:1 uRPF:84 to:[0:0]]
    [0] [@14]: ip6-link-local
````

### Default VRF routes

````bash
calicovppctl vppctl show ip fib index 0
````

This yield the following routes :

````console
ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport proto flowlabel ]
epoch:0 flags:none locks:[adjacency:1, recursive-resolution:1, default-route:1,
session lookup:1, ]

0.0.0.0/0
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:1 buckets:1 uRPF:40 to:[8:3017]]
    [0] [@5]: ipv4 via 172.18.0.1 host-eth0: mtu:1500 next:5 flags:[features ]
0.0.0.0/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:2 buckets:1 uRPF:1 to:[0:0]]
    [0] [@0]: dpo-drop ip4
````

Route to local pods

````console
11.0.0.1/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:79 buckets:1 uRPF:90 to:[0:0]]
    [0] [@5]: ipv4 via 0.0.0.0 tun1: mtu:9216 next:8 flags:[features ]
````

Route to pods on a remote node, over IPIP

````console
11.0.0.64/26
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:101 buckets:1 uRPF:119 to:[0:0]]
    [0] [@6]: ipv4 [features] via 0.0.0.0 ipip1: mtu:9000 next:9 flags:[feat fixup-ip4o4]
        stacked-on entry:51:
          [@2]: ipv4 via 172.18.0.5 host-eth0: mtu:1500 next:5 flags:[feat ]
````

Legacy service VIP in FIB, now unused

````console
11.96.0.1/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:61 buckets:1 uRPF:75 to:[0:0]]
    [0] [@17]: [2] cnat-client:[11.96.0.1] tr:1 sess:0 locks:5 exclusive
````

Route to a remote node over the uplink, here ``host-eth0``

````console
172.18.0.2/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:102 buckets:1 uRPF:120 to:[4:208]]
    [0] [@5]: ipv4 via 172.18.0.2 host-eth0: mtu:1500 next:5 flags:[features ]
````

Glean route (ARP) for a prefix attached on the uplink

````console
172.18.0.0/16
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:26 buckets:1 uRPF:29 to:[3:278]]
    [0] [@4]: ipv4-glean: [src:172.18.0.0/16] host-eth0: mtu:1500 next:1 flags:[]
````

Local route (for me traffic)

````console
172.18.0.4/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:29 buckets:1 uRPF:34 to:[459429:81477399]]
    [0] [@15]: dpo-receive: 172.18.0.4 on host-eth0
````

Expected drop routes

````console
224.0.0.0/4
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:4 buckets:1 uRPF:3 to:[0:0]]
    [0] [@0]: dpo-drop ip4
240.0.0.0/4
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:3 buckets:1 uRPF:2 to:[0:0]]
    [0] [@0]: dpo-drop ip4
255.255.255.255/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:5 buckets:1 uRPF:4 to:[0:0]]
    [0] [@0]: dpo-drop ip4
````

You can also ask for a specific prefix in a given table using

````console
$ calicovppctl vppctl show ip fib index 0 172.18.0.2
ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport proto flowlabel ]
epoch:0 flags:none locks:[adjacency:1, recursive-resolution:1, default-route:1,
session lookup:1, ]

172.18.0.2/32 fib:0 index:95 locks:2
  adjacency refs:1 entry-flags:attached, src-flags:added,contributing,active, cover:24
    path-list:[143] locks:2 uPRF-list:120 len:1 itfs:[1, ]
      path:[161] pl-index:143 ip4 weight=1 pref=0 attached-nexthop:  oper-flags:resolved,
        172.18.0.2 host-eth0
      [@0]: ipv4 via 172.18.0.2 host-eth0: mtu:1500 next:5 flags:[features ] 0283a146e2024e5535e51f770800
    Extensions:
     path:161 adj-flags:[refines-cover]
 forwarding:   unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:102 buckets:1 uRPF:120 to:[4:208]]
    [0] [@5]: ipv4 via 172.18.0.2 host-eth0: mtu:1500 next:5 flags:[features ] 0283a146e2024e5535e51f770800
````
