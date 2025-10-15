# Pod Configuration

CalicoVPP exposes three types of interaces

- [tuntap](tuntap.md) - regular linux netdevs
- [memif](memif.md) - performance oriented packet interaces
- [vcl](vcl.md) - performance oriented host stack (TCP, UDP, TLS in VPP)

## Configuration

The pod interface sizing can be confiugred with annotations in the pod
manifest.

````yaml
apiVersion: v1
kind: Pod
metadata:
  name: samplepod
  annotations:
    cni.projectcalico.org/vppInterfacesSpec: |-
    {
      "eth0": {
          "rx": 1,
          "tx": 1,
          "rxqsz": 1024,
          "txqsz": 1024,
          "rxMode": "polling",
          "isl3": true
      }
    }
````

- `tx` and `rx` set the number of queues the interface receives in VPP
- `rxqsz` and `txqsz` set the number of buffers the interface receives in VPP
- `rxMode` sets the way VPP reads from this interface (`polling` `adaptive` or `interrupt`)
- `isL3` sets the interface mode L3 for `tun` (default) or L2 for `tap`

Here is the full [specification reference](https://github.com/projectcalico/vpp-dataplane/blob/master/config/config.go)
