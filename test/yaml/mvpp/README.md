## Attaching to a memif exposed by Calico/VPP

### Prerequistes 

You need to make sure that Calico/VPP is installed with Memif support enabled. It is disabled by default.

When [installing Calico/VPP](https://projectcalico.docs.tigera.io/getting-started/kubernetes/vpp/getting-started) you can edit the yaml to enable memif support.

````yaml
kind: DaemonSet
apiVersion: apps/v1
metadata:
  name: calico-vpp-node
  namespace: calico-vpp-dataplane
spec:
  template:
    spec:
      containers:
        - name: agent
          image: calicovpp/agent:latest
          env:
            - name: CALICOVPP_ENABLE_MEMIF
              value: "true"
````

### Pod creation

To create a Container with a VPP in it attached to the memif pod interface requested in the yaml do as follows :

First create the pod `mvpp`

````bash
kubectl create ns mvpp
kubectl apply -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/test/yaml/mvpp/test.yaml
````

Then wait for the pod to start, attach to it with e.g. bash

````bash
kubectl -n mvpp exec -it mvpp -- bash
````

Create the VPP CLIs to be executed on startup.

````bash
mkdir -p /run/vpp

INTADDR=$(ip addr show dev eth0 | grep 'inet ' | awk '{print $2}')
echo "
create memif socket id 1 filename @vpp/memif
create interface memif socket-id 1 id 0 slave buffer-size 4096 rx-queues 1 tx-queues 1
set int ip addr memif1/0 ${INTADDR}
set interface mac address memif1/0 02:00:00:00:00:01
set int st memif1/0 up
" > /run/vpp/vppstartup.conf
````

Then the VPP startup config file. Here we run without hugepages on a single worker

⚠ Be sure that `main-core 1` corresponds to a CPU that's available on your machine, and not used by another VPP


````bash
echo "
unix {
  interactive
  exec /run/vpp/vppstartup.conf
}
buffers {
  buffers-per-numa 8192
  default data-size 2048
  page-size 4K
}
cpu {
  main-core 1
  workers 0
}
plugins {
  plugin default { enable }
  plugin dpdk_plugin.so { disable }
}
" > /etc/vpp/vpp.conf
````

And then start VPP

````bash
vpp -c /etc/vpp/vpp.conf
````

You should then see a VPP prompt, and `sh int` should display a configured `memif1/0` interface.
Trace should show you packets received on the memif interface.

````
vpp# trace add memif-input 5
vpp# sh trace
------------------- Start of thread 0 vpp_main -------------------
Packet 1

00:00:10:677649: memif-input
  memif: hw_if_index 1 next-index 4
    slot: ring 0
00:00:10:677659: ethernet-input
  IP4: 02:fe:a0:37:ab:93 -> 02:00:00:00:00:01
00:00:10:677664: ip4-input
  TCP: 172.18.0.3 -> 11.0.0.173
    tos 0x00, ttl 62, length 60, checksum 0x7cb7 dscp CS0 ecn NON_ECN
    fragment id 0x0843, flags DONT_FRAGMENT
  TCP: 54390 -> 5555
    seq. 0x253ebdee ack 0x00000000
    flags 0x02 SYN, tcp header: 40 bytes
    window 64400, checksum 0xb309

````

Exit with `quit` or `Ctrl-C`, then type `reset` to regain a proper shell


