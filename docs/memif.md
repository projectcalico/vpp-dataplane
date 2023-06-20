
## Introduction and Overview

Memif interfaces are efficient packet interfaces designed for seamless packet exchange between two processes. These interfaces rely on a shared memory segment, allowing for fast and direct packet communication. Remarkably, a single thread can achieve impressive transmission and reception rates of up to 15 million packets per second (Mpps) when utilizing a memif interface. Memif interfaces offer support for both Layer 2 and Layer 3 modes, enhancing their versatility and applicability in various networking scenarios. 

Using memif interfaces is ideal for packet processing workloads as they scale to much higher pps than the kernel interfaces.

## Memif feature in CalicoVPP

### Memif mode in CalicoVPP

Using memif comes in two different modes: client mode and server mode. In client mode, our application acts as the memif client, establishing a connection with the memif server process. In server mode, our application acts as the memif server, accepting incoming connections from client processes and handling packet exchanges accordingly. At the level of our CalicoVpp Infra, memif is always a server mode interface. So the user needs to have a client attached to the memif pod interface.

### Enabling Memif in CalicoVPP

To enable memif in your calicoVPP cluster, make sure parameter is set here:

```yaml
# dedicated configmap for VPP settings
kind: ConfigMap
apiVersion: v1
metadata:
  name: calico-vpp-config
  namespace: calico-vpp-dataplane
data:
  CALICOVPP_FEATURE_GATES: |-
  {
    "memifEnabled": true
  }
```

### Creating Memif interfaces

Using memif in CalicoVPP is possible in two different flavors:

* In multinet: secondary interfaces for a pod can be given a name starting with `memif`, in which case a memory interface will be created in VPP for that pod in that network. This interface is created on top of a dummy interface created in linux.
[multinet documentation](multinet.md) contains more details about memif in multinet.
You can add the memif interface in secondary network as well as its spec, using annotations:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: samplepod
  annotations:
    k8s.v1.cni.cncf.io/networks: network-blue-conf@memif-eth1
    cni.projectcalico.org/vppInterfacesSpec: |-
    {
      "memif-eth1": {"rx": 1, "tx": 2, "isl3": true }
    }
```

* In single interface pods: A memif interface can be created next to the tun/tap interface, sharing the same address. In this case, memif interface is going to be used for traffic using particular ports specified via the following annotation in the pod:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: samplepod
  annotations:
    "cni.projectcalico.org/vppExtraMemifPorts":  "tcp:4444-20000,udp:4444-20000"
```
This is called PBL (Port based balancer).

### Sockets

Memif interfaces use a socketfile: a Unix domain socket used for communication between the memif endpoints. This allows server/client interfaces to communicate together.
We use an abstract socket for our interface. This socket address is usually represented as an abstract name beginning with a null byte followed by the desired name, typically "@mysocket".
VPP api has a particular syntax for abstract sockets: using the keyword `abstract:` then `netns_name:`. 
For example: `abstract:memif1,netns_name=/var/run/netns/cni-75e26661-4119-90a4-b9d2-0b00489f76f3`. This syntax appears in vppctl.

## Troubleshooting memif interface creation

To check abstract socket creation in linux, you can run the following command on the pod using memif:

```bash
lsof -U | grep memif
vpp_main 420448 root   41u  unix 0xffff9eaeb1942200      0t0 308588503 @memif1 type=SEQPACKET
```

To check it in vpp cli:

```bash
   _______    _        _   _____  ___ 
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/    

vpp# sh memif
sockets
  id  listener    filename
  0   no          /run/vpp/memif.sock
  101 yes (1)     abstract:memif1,netns_name=/var/run/netns/cni-75e26661-4119-90a4-b9d2-0b00489f76f3

interface memif1013904223/0
  socket-id 1013904223 id 0 mode ethernet
  flags admin-up
  listener-fd 41 conn-fd 0
  num-s2m-rings 0 num-m2s-rings 0 buffer-size 0 num-regions 0
```
To check memif interface creation:
```bash
vpp# sh int addr
...
...
memif1013904223/0 (up): 
  unnumbered, use loop4
  L3 11.0.0.195/32 ip4 table-id 1649346937 fib-idx 12
  L3 fd20::58fd:b191:5c13:9cc2/128 ip6 table-id -1526094716 fib-idx 16
...
```
In multinet case, this interface has a unique address and it attaches to a dummy interface.
However, in PBL, memif interface is attached to the same interface as tun/tap.

To check dummy interface created in multinet/memif, connect to the memif pod then type `ip address` to find memif dummy interfaces.

## Testing memif feature

Testing depends on the way memif interface is consumed. We present three possible client interface 


* To create a Container with a VPP in it attached to the memif pod interface, here is [mvpp](../test/yaml/mvpp) deployment.
* To use [testpmd](../test/yaml/testpmd): DPDK tool used for traffic generation and performance testing.
* To use [trex](../test/yaml/trex) traffic generator.