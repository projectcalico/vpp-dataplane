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

attach to the pod with e.g. bash

````bash
kubectl exec -it memifpod -- bash
````

Create the VPP CLIs to be executed on startup.

````bash
mkdir -p /run/vpp

INTADDR=$(ip addr show dev memif1 | grep 'inet ' | awk '{print $2}')
echo "
create memif socket id 1 filename @vpp/memif-memif1
create interface memif socket-id 1 id 0 slave buffer-size 4096 rx-queues 1 tx-queues 1
set int ip addr memif1/0 ${INTADDR}
set interface mac address memif1/0 02:00:00:00:00:01
ip route add 0.0.0.0/0 via 127.0.0.1 memif1/0
ip neighbor memif1/0 127.0.0.1 02:fe:e6:5b:3a:44
set int st memif1/0 up
" > /run/vpp/vppstartup.conf
````

Then the VPP startup config file. Here we run without hugepages on a single worker

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
To test that, ping from the other pod in the same network.

Exit with `quit` or `Ctrl-C`, then type `reset` to regain a proper shell


