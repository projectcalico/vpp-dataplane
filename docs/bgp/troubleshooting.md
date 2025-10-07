# Troubleshooting BGP in CalicoVPP

*This document assumes that you have installed [calicovppctl](../install/calicovppctl.md)*

## Printing out peerings

The following CLI will print out BGP peers on a given node.

- established peerings will show up as ``Establ``
- unsuccessful connections will show up as ``Opened`` with ``0``
in ``#Received  Accepted``
- CalicoVPP learns about new peers using the kubernetes API. If peers are
missing from this list, there might be an issue accessing this API

```bash
$ calicovppctl sh -node worker-1 -component agent
$ gobgp neigh
Peer                     AS  Up/Down State       |#Received  Accepted
172.18.0.3            64512 04:05:26 Establ      |        1         1
172.18.0.5            64512 04:05:22 Establ      |        1         1
fc00:f853:ccd:e793::3 64512 01:05:33 Establ      |        1         1
fc00:f853:ccd:e793::5 64512 03:47:40 Establ      |        1         1
```

## Showing node BGP information

This shows the information goBGP advertises to peers

```bash
$ calicovppctl sh -node worker-1 -component agent
$ gobgp global
AS:        64512
Router-ID: 172.18.0.4
Listening Port: 179, Addresses: fc00:f853:ccd:e793::4, 172.18.0.4
```

## Showing routing table info

This prints out the prefixes adverstised by peers, Next Hop being
the peer's IP.

```bash
$ calicovppctl sh -node worker-1 -component agent
$ gobgp global rib -a 4
   Network                       Next Hop              Age       Attrs
*> 11.0.0.0/26                   172.18.0.4            04:10:10  [{Origin: i}]
*> 11.0.0.1/32                   172.18.0.4            04:10:10  [{Origin: i}]
*> 11.0.0.64/26                  172.18.0.5            04:09:53  [{Origin: i}]
*> 11.0.0.128/26                 172.18.0.3            04:09:57  [{Origin: i}]
$ gobgp global rib -a 6
   Network                       Next Hop              Age       Attrs
*> fd20::352a:e9ea:a977:6680/122 fc00:f853:ccd:e793::3 01:10:02  [{Origin: i}]
*> fd20::97de:47c:45f6:c00/122   fc00:f853:ccd:e793::4 04:10:08  [{Origin: i}]
*> fd20::97de:47c:45f6:c00/128   fc00:f853:ccd:e793::4 04:10:08  [{Origin: i}]
*> fd20::a36f:997d:9b64:f940/122 fc00:f853:ccd:e793::5 03:52:09  [{Origin: i}]
$ gobgp global rib 11.0.0.65
   Network                       Next Hop              Age       Attrs
*> 11.0.0.64/26                  172.18.0.5            04:12:51  [{Origin: i}]
```

## Broader CLI syntax documentation

Go [here for a more extensive documentation of the goBGP CLI](https://github.com/osrg/gobgp/blob/master/docs/sources/cli-command-syntax.md)
