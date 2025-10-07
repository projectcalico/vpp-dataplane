# Pod Configuration

CalicoVPP exposes three types of interaces

- [tuntap](tuntap.md)
- [memif](memif.md)
- [vcl](vcl.md)
- [tuntap](tuntap.md)

## Pod interface configuration

As part of user config, you can set specific configuration for pod interfaces
using pod annotations.

````yaml

apiVersion: v1
kind: Pod
metadata:
  name: samplepod
  annotations:
    cni.projectcalico.org/vppInterfacesSpec: |-
    {
      "eth0": {"rx": 1, "tx": 2, "isl3": true }
    }

````

Here is the full [specification reference](https://github.com/projectcalico/vpp-dataplane/blob/master/config/config.go)
