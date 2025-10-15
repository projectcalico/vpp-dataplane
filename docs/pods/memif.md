# Memif support in containers

## Introduction and Overview

Memif interfaces are efficient packet interfaces designed for seamless packet
exchange between two processes. These interfaces rely on a shared memory
segment, allowing for fast and direct packet communication. Remarkably, a
single thread can achieve impressive transmission and reception rates of up to
15 million packets per second (Mpps) when utilizing a memif interface. Memif
interfaces offer support for both Layer 2 and Layer 3 modes, enhancing their
versatility and applicability in various networking scenarios.

Using memif interfaces is ideal for packet processing workloads as they scale
to much higher pps than the kernel interfaces.

## Memif feature in CalicoVPP

### Memif mode in CalicoVPP

Using memif comes in two different modes: client mode and server mode. In
client mode, our application acts as the memif client, establishing a
connection with the memif server process. In server mode, our application
acts as the memif server, accepting incoming connections from client
processes and handling packet exchanges accordingly. At the level of our
CalicoVpp Infra, memif is always a server mode interface. So the user needs
to have a client attached to the memif pod interface.

### Enabling Memif in CalicoVPP

To enable memif in your calicoVPP cluster, make sure parameter is set here:

````yaml
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
````

### Creating Memif interfaces

Using memif in CalicoVPP is possible in two different flavors:

* In multinet: secondary interfaces for a pod can be given a name starting
with `memif`, in which case a memory interface will be created in VPP for that
pod in that network. This interface is created on top of a dummy interface
created in linux.
[multinet documentation](multinet.md) contains more details about memif in
multinet.
You can add the memif interface in secondary network as well as its spec,
using annotations:

````yaml
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
````

* In single interface pods: A memif interface can be created next to the
tun/tap interface, sharing the same address. In this case, memif interface is
going to be used for traffic using particular ports specified via the
following annotation in the pod:

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

This is called PBL (Port based balancer).

A pod supports having both memif and [vcl](vcl.md) interfaces at the same time
by adding both annotations.

### Sockets

Memif interfaces use a socketfile: a Unix domain socket used for communication
between the memif endpoints. This allows server/client interfaces to
communicate together.
We use an abstract socket for our interface. This socket address is usually
represented as an abstract name beginning with a null byte followed by the
desired name, typically "@mysocket".
VPP api has a particular syntax for abstract sockets: using the keyword
`abstract:` then `netns_name:`.
For example: `abstract:memif1,netns_name=/var/run/netns/cni-75e26661-4119-90a4-b9d2-0b00489f76f3`.
This syntax appears in vppctl.

## Testing memif feature

Testing depends on the way memif interface is consumed. We present three
possible client interface

* To create a Container with a VPP in it attached to the memif pod interface,
here is [mvpp](../test/yaml/mvpp) deployment.
* To use [testpmd](../test/yaml/testpmd): DPDK tool used for traffic generation
and performance testing.
* To use [trex](../test/yaml/trex) traffic generator.
