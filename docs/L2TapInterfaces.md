## We support L2 interfaces in pods 

Pods use an L3 interface per default (tun interface in VPP). However, we also support having L2 interfaces (tap), via this [annotation](config.md#L99):

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: samplepod
  annotations:
    cni.projectcalico.org/vppInterfacesSpec: |-
    {
      "eth0": {"isl3": false },
    }
```

This has a known limitation : the linux routing configuration is currently incomplete. A workaround for it is to have a cap admin capability on a privileged container:

```yaml
      securityContext:
        capabilities:
          add: [ "NET_ADMIN"]
```
and to run these commands on the container to have connectivity:

```bash
ip link set dev eth0 down
ip link set dev eth0 address 02:00:00:00:00:01
ip link set dev eth0 up
ip neigh add 169.0.254.1  lladdr 51:53:00:17:34:09 dev eth0
ip route add 169.0.254.1 dev eth0
ip route add default via 169.0.254.1 dev eth0
```
