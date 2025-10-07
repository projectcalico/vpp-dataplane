# Calico/VPP technical documentation

This folder contains Calico/VPP technical documentation.
This is this repository's counterpart of the documentation
available at [https://docs.tigera.io](https://docs.tigera.io/calico/latest/reference/vpp/technical-details)

It contains documentation specific to VPP, feature behaviour,
troubleshooting commands and tools.

## General feature documentation

- [Installation](install)
- [Configuration](config), [General troubleshooting](troubleshooting.md)
- [BGP with CalicoVPP](bgp), [troubleshooting BGP](bgp/troubleshooting.md)
- [network model](network), [troubleshooting networking](network/troubleshooting.md)
- [Pods connectivity](pods)
- [Services](services), [troubleshooting services](services/troubleshooting.md)
- [Policies](policies), [troubleshooting policies](policies/troubleshooting.md)
- [Metrics](metrics)

## Developper and graduating (alpha, beta) features

- [Developer documentation](dev)
- [(alpha) Multinet feature documentation](multinet.md)

## Additional resources and links

- [External resources](events.md) like events and presentations

## Pod and usage examples

- [A series of examples yamls](../test/yaml)
- [A Simple VCL client and server example](../test/yaml/simple-vcl)
- [A trex pod example](../test/yaml/trex)
- [A vpp client pod example](../test/yaml/mvpp)
- [An envoy pod example with optional VCL support](../test/yaml/envoy)
