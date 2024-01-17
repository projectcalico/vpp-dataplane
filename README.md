# Calico VPP dataplane

<p float="left">
<img src="https://docs.tigera.io/img/favicon.png" width="100" height="100">
<img src="https://fd.io/img/fdio-color.svg" width="100" height="100">
</p>

This repository contains the source for Calico's VPP dataplane integration. The integration is in incubation status, with significant development in progress.

### Integration goals

The main goal of this integration is to accelerate the networking of k8s clusters that use Calico thanks to [FD.io VPP](https://fd.io/docs/vpp/master/). Nodes running the VPP dataplane provide faster networking to their pods, without requiring any changes to the applications running in the pods. 

This integration aims to be as transparent as possible. In particular, the VPP dataplane does not have any additional requirements compared to regular Calico. All the networking configuration, including traffic encapsulation, IP Pools, BGP Configuration, etc. is done through regular Calico means. As a result, the docs present in this repository will only describe the VPP-specific elements.

VPP-enabled nodes are entirely compatible with regular Calico nodes - meaning that it is possible to have a cluster with some VPP-enabled nodes and some regular nodes. This makes it easy to migrate a cluster from Linux or eBPF Calico networking to VPP-accelerated networking.

In addition to that, the VPP Dataplane provides some additional features that are not available in Calico. For instance : 
- We support very fast container traffic encryption with IPsec
- SRv6 is also supported for node to node transport 
- Network intensive applications can also require [memif packet interfaces](https://s3-docs.fd.io/vpp/23.02/interfacing/libmemif/index.html) for optimized user-space networking.
- Network intensive endpoint applications (using TCP, TLS, UDP, QUIC, ...) can consume the [VPP Hoststack](https://wiki.fd.io/view/VPP/HostStack) with the VPP Client Library [VCL](https://wiki.fd.io/view/VPP/HostStack/VCL)
- Containerized network functions requiring multiple high speed interfaces can leverage [multinet](docs/multinet.md)

Finally, our goal is to make the deployment of Calico-VPP as simple as applying a YAML file through kubectl.

## Get Started Using Calico/VPP

* Please see our [Getting started page](https://docs.tigera.io/calico/latest/getting-started/kubernetes/vpp/getting-started) for instructions on how to set it up on a cluster.
* If you want to learn more about Calico, see the documentation on [docs.tigera.io/calico](https://docs.tigera.io/calico).
* If you have questions, feel free to drop us a line in the [Calico Slack room #vpp](https://calicousers.slack.com/archives/C017220EXU1)
* Check out [Release notes](RELEASE_NOTES.md)

### Software Architecture

For technical details about the Calico-VPP integration, see the [VPP dataplane implementation details](https://docs.tigera.io/calico/latest/reference/vpp/technical-details).

### Contributing

Contributions to this code are welcome! 

Before starting, make sure you've read [the Calico contributor guide](CONTRIBUTING.md).

You can follow the [guide to setup a kind based development cluster](docs/developper_guide.md)

Or refer to the [developer documentation in this repository](docs)

## License

Calico binaries are licensed under the [Apache v2.0 license](LICENSE), with the exception of some [GPL licensed eBPF programs](https://github.com/projectcalico/calico/tree/master/felix/bpf-gpl/README).

Calico imports packages with a number of apache-compatible licenses. For more information, see [licenses](https://github.com/projectcalico/calico/blob/master/calico/LICENSE). In addition, the base container image contains pre-packaged software with a variety of licenses.
