## Introduction and Overview

VCL stands for the [VPP Comms Library](https://wiki.fd.io/view/VPP/HostStack/VCL), it is a library that allows application to easily leverage the VPP [hoststack](https://wiki.fd.io/view/VPP/HostStack) (i.e. TCP, UDP, TLS, QUIC, ... stack implementation in VPP itself) in a similar way as the libc works for kernel hoststack syscalls.
It works by exposing a unix socket over which control messages exchanged and configurations negotiated.

## VCL feature in CalicoVPP

### Enabling VCL feature in CalicoVPP

To enable vcl in your calicoVPP cluster, make sure parameter is set here:

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
    "vclEnabled": true
  }
```

### Using VCL in pods:

To enable VCL on a pod, use the following annotation:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: samplepod
  annotations:
    "cni.projectcalico.org/vppVcl": "enable"
```
This will trigger vpp to create the VCL abstract socket. The session creation will happen when issuing listens or connects calls over the VCL [(test)](#testing-vcl-feature).

The VPP Hoststack exposes an abstract socket, it's a unix socket over which applications communicate with VPP - leveraging the VCL - in order to open or accept L4+ connections (e.g. TCP) directly in VPP.
Calico/VPP uses abstract socket, which being anchored to a network namespace are better suited for the CNI world rather than regular socket which are mounted on the filesystem. Their address are encoded as a name with a heading null byte, which is usually replaced by the @ sign when printed.
Calico/VPP exposes the @vpp/session abstract socket within the container, to which the VCL should be pointed.
VPP api has a particular syntax for abstract sockets: using the keyword `abstract:` then `netns_name:`. 
For example: `abstract:vpp/session,netns_name=/var/run/netns/cni-75e26661-4119-90a4-b9d2-0b00489f76f3`. This syntax appears in vppctl.

A pod supports having both vcl and [memif](memif.md) interfaces at the same time by adding both annotations.

## Testing VCL feature

### Using a pod supporting VCL:

VCL can be tested using iperf network performance tool.
here is a [deployment](../test/yaml/iperf3-vcl/test.yaml) example with client/server pods for tests.
```bash
kubectl create ns iperf3-vcl
kubectl apply -f test/yaml/iperf3-vcl/test.yaml
```
In an iperf3-vcl pod, at entrypoint, we have `test/yaml/iperf3-vcl/iperf3-vcl.sh` script that:
* Generates the `/etc/vpp/vcl.conf` configuration file which will be picked up by the VCL library as we did set `VCL_CONFIG=/etc/vpp/vcl.conf`
* Uses `LD_PRELOAD=/usr/local/lib/vpp/libvcl_ldpreload.so` which is roughly equivalent of dynamically linking the iperf3 binary against the VCL instead of the libc (so piping the connect() and accept() syscall to VPP instead of linux).
* performs `iperf3 -4 -s` which creates the listener session
 `[0:1][T] 11.0.0.139:5201->0.0.0.0:0 LISTEN`

### Using a sidecar container to support VCL in any pod:
Build your vpp libraries and rebuild your sidecar if needed using
```bash
cd test/yaml
VPP_DIR=/path-to-your-repo/vpp-manager/vpp_build/ make sidecar-vcl
```

To use VCL in your pod, you don't need to rebuild your pod image. You can use a sidecar container that has all the vcl requirements.

```bash
kubectl create ns iperf3-vclsidecar
kubectl apply -f test/yaml/iperf3-vclsidecar/test.yaml
```
You can change your vcl config in the configmap defined in the `test.yaml`.
The iperf3-vclsidecar pod should be able to use vcl directly by running:
```bash
LD_PRELOAD=/libraries/libvcl_ldpreload.so iperf3 -s -4
```
and
```bash
LD_PRELOAD=/libraries/libvcl_ldpreload.so iperf3 -c x.x.x.x
```

## Troubleshooting VCL

To check abstract socket creation in linux, you can run one of the following commands on the pod running vcl:

* Using `lsof`:
```bash
lsof -U | grep session
vpp_main 1460865 root   54u  unix 0xffff90a6df003300      0t0 18574585 @vpp/session type=SEQPACKET
```
* Using `ss`:
```bash
ss | grep session
u_seq ESTAB 0      0       @vpp/session 18574585            * 18842705
```
* Using `netstat`:
```bash
netstat | grep session
unix  3      [ ]         SEQPACKET  CONNECTED     18574585 @vpp/session
```
> **Warning**: The output might be huge on live systems with a lot of connections! it's preferable to grep specific output.

 Sessions created in vpp are listeners or established connections in various protocols. To check sessions in vpp cli:

```bash
    _______    _        _   _____  ___ 
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/    

vpp# sh session verbose
Connection                                                  State          Rx-f      Tx-f      
[0:0][CT:T] 0.0.0.0:5201->0.0.0.0:0                         LISTEN         0         0         
[0:1][T] 11.0.0.139:5201->0.0.0.0:0                         LISTEN         0         0         
[0:2][CT:T] 0.0.0.0:5201->0.0.0.0:0                         LISTEN         0         0         
[0:3][T] 11.0.0.140:5201->0.0.0.0:0                         LISTEN         0         0         
Thread 0: active sessions 4
```

## Known issues

* VCL currently only works for the primary interface when used in combination with multinet.
* Dataplane restart is currently not detected by the client application, this can be alleviated by making healthchecks travel over the VCL.
* Source address spoofing is not supported even when disabling uRPF at the pod level.