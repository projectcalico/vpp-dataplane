# Pod interface Troubleshooting

*This document assumes that you have installed [calicovppctl](../install/calicovppctl.md)*

For general networking and routing related issues, check
[the network troubleshooting guide](../network/troubleshooting.md)

## Troubleshooting tuntap interfaces

To validate that the tun is properly configured in VPP
you can use the following CLIs

First search for the tun interface by IP address.

````bash
$ calicovppctl vppctl -node worker-1 show int addr | grep tun -A 2
tun10 (up):
  unnumbered, use loop9
  L3 192.168.189.6/32 ip4 table-id -100501683 fib-idx 22
````

Knowing the interface name, you can then fetch interface details
(number of queues, buffers, offloads) issuing

````bash
$ calicovppctl vppctl -node worker-1 show tun | grep tun10 -A 40
Interface: tun10 (ifindex 23)
  name "eth0"
  host-ns "/var/run/netns/cni-fa68a216-bdc4-47ff-a2ec-20f526c85442"
  host-mtu-size "1480"
  host-carrier-up: 1
  vhost-fds 176 177 178 179 180
  tap-fds 175
  gso-enabled 1
  csum-enabled 0
  packet-coalesce 1
  packet-buffering 0
  rss-enabled 0
  Device instance: 10
  flags 0x1
    admin-up (0)
  features 0x110008000
    VIRTIO_NET_F_MRG_RXBUF (15)
    VIRTIO_RING_F_INDIRECT_DESC (28)
    VIRTIO_F_VERSION_1 (32)
  remote-features 0x1033d008000
    VIRTIO_NET_F_MRG_RXBUF (15)
    VIRTIO_F_NOTIFY_ON_EMPTY (24)
    VHOST_F_LOG_ALL (26)
    VIRTIO_F_ANY_LAYOUT (27)
    VIRTIO_RING_F_INDIRECT_DESC (28)
    VIRTIO_RING_F_EVENT_IDX (29)
    VIRTIO_F_VERSION_1 (32)
    VIRTIO_F_IOMMU_PLATFORM (33)
    VIRTIO_NET_F_RING_RESET (40)
  Number of RX Virtqueue  1
  Number of TX Virtqueue  5
  Virtqueue (RX) 0
    qsz 1024, last_used_idx 496, desc_next 384, desc_in_use 912
    avail.flags 0x0 avail.idx 1408 used.flags 0x1 used.idx 496
    kickfd 182, callfd 181
  Virtqueue (TX) 1
    qsz 1024, last_used_idx 0, desc_next 0, desc_in_use 0
    avail.flags 0x1 avail.idx 0 used.flags 0x0 used.idx 0
    kickfd 183, callfd -1
    packet-coalesce: enable
      flow-table: size 0 gro-total-vectors 0 gro-n-vectors 0 gro-average-rate 0.00
````

You can also find extra details issuing

````bash
$ calicovppctl vppctl -node worker-1 show tun | grep tun10 -A 40
tun10                              15     up   tun4
  Link speed: unknown
  RX Queues:
    queue thread         mode
    0     vpp_wk_3 (4)   adaptive
  TX Queues:
    TX Hash: [name: hash-eth-l34 priority: 50 description: Hash ethernet L34 headers]
    queue shared thread(s)
    0     no     0
    1     no     1
    2     no     2
    3     no     3
    4     no     4
  tun-device
  VIRTIO interface
     instance 6
       RX QUEUE : Total Packets
              0 : 101776049
       TX QUEUE : Total Packets
              0 : 0
              1 : 0
              2 : 49
              3 : 64
              4 : 102177023
````

## Troubleshooting memif interfaces

### memif pod-side connectivity

If the client fails to connect or listen, there might be an issue in the pods
configuration, the memif socket might not be present.

To check abstract socket creation in linux, you can run the following command
on the pod using memif. You should see only the listen socket or both depending
whether your application is connected or not.

* using `lsof`

````bash
$ lsof -U | grep memif
vpp_main  ... @vpp/memif-eth0 type=SEQPACKET (LISTEN)
vpp_main  ... @vpp/memif-eth0 type=SEQPACKET (CONNECTED)
````

* using `ss`

````bash
$ ss -l | grep memif
u_seq LISTEN 0      5      @vpp/memif-eth0 57062815             * 0
$ ss | grep memif
u_seq ESTAB 0      0      @vpp/memif-eth0 84202976            * 84250551
````

* using `netstat`

````bash
$ netstat -l | grep memif
unix  2      [ ACC ]     SEQPACKET  LISTENING     57062815 @vpp/memif-eth0
$ netstat | grep memif
unix  3      [ ]         SEQPACKET  CONNECTED     84202976 @vpp/memif-eth0
````

#### memif pod manifest configuration

In order to request a functional memif interface in a pod outside of
the multinet mode, you need to specify which protocols and ports
will be redirected the memif. The pod manifest should look like this

````yaml
apiVersion: v1
kind: Pod
metadata:
  name: samplepod
  annotations:
    "cni.projectcalico.org/vppExtraMemifPorts":  "tcp:4444-20000,udp:4444-20000"
````

This meaning that ports `4444` to `20000` in both UDP and TCP will
go to the memif interface while the rest of the traffic will flow
normally to the tuntap.

#### memif pod-side dummy interface

In multinet mode only, the memif will be assigned its own address, it will not
share it with the linux netdev (the regular `eth0`). As a consequence, VPP
creates a `dummy` linux netdev with the same name as the memif to indicate
that memif is properly configured, and so that the controlplane can determine
the memif's assigned IP.

In PBL mode, the memif interface carrying the same address as the tuntap,
this is not needed.

### memif vpp-side connectivity

To validate that the memif is properly configured in VPP
you can use the following CLI

First search for the memif interface by IP address.
The memif interface will share the address of the pod with
the tuntap interface.

````bash
$ calicovppctl vppctl -node worker-1 show int addr | grep memif -A 2
memif3167820124/0 (up):
  unnumbered, use loop0
  L3 192.168.189.40/32 ip4 table-id 546252705 fib-idx 10
````

You can validate that the memif is `admin-up` with the following CLI

````bash
$ calicovppctl vppctl -node worker-1 show memif
sockets
  id  listener  filename
  0   no        /run/vpp/memif.sock
  101 yes (1)   abstract:memif1,netns_name=/var/run/netns/cni-75e61-4119-0b004

interface memif1013904223/0
  socket-id 1013904223 id 0 mode ethernet
  flags admin-up
  listener-fd 41 conn-fd 0
  num-s2m-rings 0 num-m2s-rings 0 buffer-size 0 num-regions 0
````

the `hardware-interface` section will have interesting info about buffers and errors

````bash
$ calicovppctl vppctl -node worker-1 show hardware-interface | grep memif -A10
memif3167820124/0                 11     up   memif3167820124/0
  Link speed: unknown
  RX Queues:
    queue thread         mode
    0     vpp_wk_0 (1)   polling
  TX Queues:
    TX Hash: [name: hash-eth-l34 priority: 50 description: Hash ethernet L34 headers]
    queue shared thread(s)
    0     yes    0-4
  memif-ip
  MEMIF interface
     instance 0
       master-to-slave ring 0
         packets sent: 0
         no tx slot: 0
         max no tx slot: 0
       slave-to-master ring 0
         packets received: 0
````

#### Memif - tuntap forks, pbl

As the memif interface and the tuntap share the same address outside
of multinet mode, we expose memif interface using a packet classifier,
that chooses one (tuntap) or the other (memif) based on destination
ports and protocols.

This is configured using a pod annotation like

````yaml
apiVersion: v1
kind: Pod
metadata:
  name: samplepod
  annotations:
    "cni.projectcalico.org/vppExtraMemifPorts":  "udp:6081"
````

You can validate that VPP is configured properly using the
following CLI

````bash
$ calicovppctl vppctl -node worker-1 show pbl client
[0] pbl-client: 192.168.189.40 clone:1
[1] pbl-client: 192.168.189.40
  TCP ports:(empty)
  UDP ports: 6081
  matched dpo
    [@2]: ipv4 via 0.0.0.0 memif3167820124/0: mtu:9216 next:12 flags:[features ]
  default dpo
    [@2]: ipv4 via 0.0.0.0 tun1: mtu:9216 next:11 flags:[features ]
````

Which means here that UDP packets to port `6081` will be going (`matched dpo`)
to the memif `memif3167820124`, and the rest (`default dpo`) going to the tun `tun1`.

It is worth validating that both routes are `up`, that is not `dpo-drop`.
Be aware that a memif that is not connected (client down) will show up
as `dpo-drop`.

#### memif events

The memif driver outputs logs when connection and disconnections happen.
You can find the corresponding trail running:

````bash
$ calicovppctl vppctl -node worker-1 show log | tail
2025/10/02 14:30:07:056 error memif_plugin memif3/0: default_socket_recvmsg: disconnected
2025/10/02 14:50:24:597 error memif_plugin memif3/0: default_socket_recvmsg: disconnected
2025/10/02 15:11:28:938 error memif_plugin memif3/0: default_socket_recvmsg: disconnected
````

## VCL, Hoststack Troubleshooting

### VCL pod-side connectivity

If the client fails to connect or listen, there might be an issue in the pods
configuration. Either the VCL socket is not present or configuration is missing

#### VCL pod socket status

In order to validate that the pod side of the VCL interface is properly
configured, you can run the following commands on the pod running vcl
to ensure that the abstract socket `@vpp/session` is present.
You should see only the listen socket or both depending
whether your application is connected or not.

* Using `lsof`:

````bash
$ lsof -U | grep session
vpp_main  ... @vpp/session type=SEQPACKET (LISTEN)
vpp_main  ... @vpp/session type=SEQPACKET (CONNECTED)
````

* Using `ss`:

````bash
$ ss -l | grep session
u_seq LISTEN 0      5         @vpp/session 57062816  * 0
$ ss | grep session
u_seq ESTAB  0      0         @vpp/session 84202972  * 84260755
````

* Using `netstat`:

````bash
$ netstat -l | grep session
unix  2      [ ACC ]     SEQPACKET  LISTENING     57062816 @vpp/session
$ netstat | grep session
unix  3      [ ]         SEQPACKET  CONNECTED     84202975 @vpp/session
````

#### VCL pod config

In order to validate that the pod is properly configured it is worth checking
that the environment variable `VCL_CONFIG` is set to a file name that contains
something like

````console
vcl {
    app-socket-api abstract:vpp/session
    app-scope-global
    app-scope-local
    use-mq-eventfd
    multi-thread-workers
}
````

If your application is using `LD_PRELOAD`, also make sure that the environment variable
`LD_PRELOAD` points to `libvcl_ldpreload.so` on the disk.

Setting environement variables `LDP_DEBUG` and `VCL_DEBUG` to e.g. `2` will
also output troubleshooting info.

### VCL vpp-side connectivity

VPP side status of the Hoststack can be checked with the following commands

The CLI below lists the applications namespaces currently set up.
For each pod requesting VCL support, you should see a loopback `loop10`
interace with its corresponding abstract socket attached in the pod
network namespace.

````bash
$ calicovppctl vppctl -node worker-1 show app ns
Index Secret Interface            Id                                      Socket
0     0      DELETED (4294967295) default                                 /run/vpp/app_ns_sockets/default
2     0      loop10               app-ns-netns:/var/run/netns/cni-1de21b1 abstract:vpp/session,netns_name=/var/run/netns/cni-1de21b1
````

When the application attaches to VPP over the `@vpp/session` socket,
you should see it coming up in the following CLI

````bash
$ calicovppctl vppctl -node worker-1 show app
Index     Name                Namespace
3         pod-application     app-ns-netns:/var/run/netns/cni-0afbc682
````

When the application listens, connects or accepts, you should see a session
coming up in the output of the CLI below

> ⚠️ The output might be huge on live systems with a lot of
connections! it's preferable to grep specific output.

````bash
$ calicovppctl vppctl -node worker-1 show session verbose
Connection                                     State          Rx-f      Tx-f
[0:2][U] 192.168.0.1:443->0.0.0.0:0            LISTEN         0         0
[0:1][T] 192.168.0.1:443->0.0.0.0:0            LISTEN         0         0
[0:2][U] 192.168.0.1:443->0.0.0.0:0            LISTEN         0         0
Thread 0: active sessions 3

Connection                                     State          Rx-f      Tx-f
[1:92][U] 192.168.0.1:443->192.168.0.2:18924   OPENED         0         0
[1:102][T] 192.168.0.1:443->192.168.0.2:15757  ESTABLISHED    0         0
[1:110][T] 192.168.0.1:443->192.168.0.2:50095  ESTABLISHED    0         0
...
Thread 1: active sessions 8

[1:110][T] 192.168.0.1:443->192.168.0.2:50095  ESTABLISHED    0         0
 ^  ^   ^
 |  |   |_(T)CP (U)DP                          
 |  |_session index on thread
 |_thread index
````

* The sessions are displayed per thread
* `Rx-f` and `Tx-f` indicate the current pending sizes of fifos,
that is the queues between VPP and the application. Stale data in
queues will indicate an issue in VPP's Hoststack

You can drill even more into a specific session by providing the thread
and the index to `show session`. Thread and index being the two parts
of the `[1:92]` prefix of lines in the output above

````bash
$ calicovppctl vppctl -node worker-1 show session thread 1 index 92
[4:2][U] 192.168.189.40:443->192.168.189.51:57322           OPENED
 index 1 cfg:  flags: CONNECTED, OWNS_PORT
 fib_index 10 next_node 0 opaque 0 sw_if_index 9 mss 1472 duration 49395.755
 stats: in dgrams 6073898 bytes 7369777360 err 443928
        out dgrams 19722730 bytes 22860676810
 transport: flags: descheduled
 Rx fifo: cursize 0 nitems 1048576 has_event 0 min_alloc 65536
          head 3360283270 tail 3360283270 segment manager 7
          vpp session 2 thread 4 app session 9 thread 0
          ooo pool 0 active elts newest 4294967295
 Tx fifo: cursize 0 nitems 1048576 has_event 0 min_alloc 65536
          head 2312808640 tail 2312808640 segment manager 7
          vpp session 2 thread 4 app session 9 thread 0
          ooo pool 0 active elts newest 0
 session: state: ready opaque: 0x9 flags: migrating
````

## Common commands

For all interface you can verify queue placement on workers
and consumption mode (adaptive, polling, interrupt) using the
following CLI

```bash
$ calicovppctl vppctl -node worker-1 show int rx-placement
Thread 1 (vpp_wk_0):
 node memif-input:
    memif3167820124/0 queue 0 (polling)
 node dpdk-input:
    FortyGigabitEthernetd8/0/0 queue 0 (polling)
 node virtio-input:
    tap0 queue 0 (adaptive)
    tun3 queue 0 (adaptive)
Thread 2 (vpp_wk_1):
    tun7 queue 0 (adaptive)
    tun13 queue 0 (adaptive)
````
