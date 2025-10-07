# Configuring Calico/VPP

## Agent configuration

Calico-Vpp components (vpp-manager and agent) are configured using a common
configMap. Here's an example of the configMap `calico-vpp-config` and the
different configuration options it contains:

Note: keys `CALICOVPP_INTERFACE` and `CALICOVPP_NATIVE_DRIVER` are being
deprecated, they are replaced by the first element of `uplinkInterfaces`
field of `CALICOVPP_INTERFACES`.
Please use `CALICOVPP_INTERFACES` instead.

````yaml
---
# dedicated configmap for VPP settings
kind: ConfigMap
apiVersion: v1
metadata:
  name: calico-vpp-config
  namespace: calico-vpp-dataplane
data:

  # Configure the name of VPP's physical interface
  CALICOVPP_INTERFACE: eth1 # deprecated

  # Configures how VPP grabs the physical interface
  # available values are :
  # - ""        : will select the fastest driver among those supported 
  #             : for this interface
  # - avf       : use the native AVF driver
  # - virtio    : use the native virtio driver (requires hugepages)
  # - af_xdp    : use AF_XDP sock family (require at least kernel 5.4)
  # - af_packet : use AF_PACKET sock family (slow but failsafe)
  # - none      : dont configure connectivity
  CALICOVPP_NATIVE_DRIVER: "af_packet" # deprecated

  # Configures parameters for calicovpp agent and vpp manager
  CALICOVPP_INTERFACES: |-
    {
      "maxPodIfSpec": {
        "rx": 10, "tx": 10, "rxqsz": 1024, "txqsz": 1024
      },
      "defaultPodIfSpec": {
        "rx": 1, "tx":1, "isl3": true
      },
      "vppHostTapSpec": {
        "rx": 1, "tx":1, "rxqsz": 1024, "txqsz": 1024, "isl3": false
      },
      "uplinkInterfaces": [
        {
          "interfaceName": "eth1",
          "vppDriver": "af_packet",
          "mtu": 1400,
          "rxMode": "adaptive",
          "physicalNetworkName": ""
        }
      ]
    }
  CALICOVPP_INITIAL_CONFIG: |-
    {
      "vppStartupSleepSeconds": 1,
      "corePattern": "/var/lib/vpp/vppcore.%e.%p",
      "defaultGWs": "192.168.0.1",
    }

  CALICOVPP_DEBUG: |-
  {
    "servicesEnabled": true,
    "gsoEnabled": true
  }

  CALICOVPP_IPSEC: -
  {
    "crossIPSecTunnels": true,
    "nbAsyncCryptoThreads": 10,
    "extraAddresses": 0
  }

  CALICOVPP_SRV6: |-
  {
    "policyPool": "cafe::/118",
    "localsidPool": "fcff::/48",
  }
  CALICOVPP_FEATURE_GATES: |-
  {
    "memifEnabled": true,
    "vclEnabled": false,
    "multinetEnabled": true,
    "srv6Enabled": false,
    "ipsecEnabled": false
  }
````

You can find the full specification for the environment variables
in [config/config.go](https://github.com/projectcalico/vpp-dataplane/blob/master/config/config.go)

## VPP specific configuration

VPP itself can be configured using a template that is set using
the ``CALICOVPP_CONFIG_TEMPLATE`` environment variable. Typically
we use something like below

````yaml
---
kind: ConfigMap
apiVersion: v1
metadata:
  name: calico-vpp-config
  namespace: calico-vpp-dataplane
data:
  CALICOVPP_CONFIG_TEMPLATE: |-
    unix {
      nodaemon
      full-coredump
      cli-listen /var/run/vpp/cli.sock
      pidfile /run/vpp/vpp.pid
      exec /etc/vpp/startup.exec
    }
    api-trace { on }
 cpu {
    main-core 0
    corelist-workers 2-3
    relative
 }
    socksvr {
        socket-name /var/run/vpp/vpp-api.sock
    }
    plugins {
        plugin default { enable }
        plugin dpdk_plugin.so { disable }
        plugin calico_plugin.so { enable }
        plugin ping_plugin.so { disable }
        plugin dispatch_trace_plugin.so { enable }
    }
````

This is the place where you can use DPDK, VCL, memory specific
knobs. You can find a more complete yet non exhaustive list
at [VPP conf/startup.conf](https://github.com/FDio/vpp/blob/master/src/vpp/conf/startup.conf)

We template this environment variable with the following replacements :

- ``__PCI_DEVICE_ID__`` the pci id of the first interface
- ``__PCI_DEVICE_ID_0__`` ; ``__PCI_DEVICE_ID_1__`` pci ids of all
interfaces (0 to N)
- ``__VPP_DATAPLANE_IF__`` the name of the first interace
- ``__VPP_DATAPLANE_IF_0__`` ; ``__VPP_DATAPLANE_IF_1__`` ; ordered name
if there are multiple
- ``__NODE_ANNOTATION:{annotationname}__`` for every node annotation
- ``__CPUSET_CPUS_FIRST__`` the contents of ``/sys/fs/cgroup/cpuset.cpus``
on the node. This now deprecated in favor of [VPP based corepinning](corepinning.md)

## CPU pinning

VPP usually runs in polling mode and is a huge consumer of caches,
which makes it a noisy neighbor for applications.
We recommend deploying it using one main thread (``main-core``) and an
even number of workers (``corelist-workers``) using sibling hyperthreads.

You can read more under [VPP based corepinning](corepinning.md)
