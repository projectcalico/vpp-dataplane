### Calico-VPP v3.25.0
> 14 Feb 2023

* New features:
  - Configuration refactoring: standardize agent configs [see documentation for details](docs/config.md)
	* This allows controling the number queues, and queue sizes for each pod
	* Defaults & Limits are also available cluster-wide
  - Support for multinet-aware policies
  - Migrate to felix messages for node & route updates. This improves scalability preventing nodes to listen to all nodes updates.
  - Upgrade goBGP to v3.10.0
  - Update image base to ubuntu 22.04
  - Change capo CLI output to use RX/TX instead of ingress/egress
  - Add prometheus stats for memif
  - Add SCTP support for services

* Bug fixes
  - Multiple policies fixes (mostly host endpoint related)
  - Add startup script reporting an agent waiting for a condition 
  - CI: automation of tests & linting on every patch
  - Connectivity: fix cross-subnet logic
  - Disable RA on all uplink interfaces
  - Fix to greedy corefile cleanup
  - Multiple VPP af-pkt, GSO & cksum offload fixes
  - More kind customizations for development

### Calico-VPP v3.24.0
> 19 Sep 2022

* New features:
  - Multinet support (including attaching multiple networks to pods via tun/tap or memif, services support, preparation for policies integration).
  - Add strict RPF check for traffic originated from pods, with possibility to add exceptions with `allowSpoofing` annotation.
  - Uplink route and MTU monitoring move from vpp-manager to the agent. As a consequence, multi-uplink now supports differentiated MTUs.

* Bug fixes
  - Integrate VPP fix for interrupt mode support with ENA/dpdk.
  - Align with Wireguard v6 support added in Calico v3.24, and fix dual stack support for Wireguard.

* Focus on code quality, add integration tests, address linting issues.

#### Calico-VPP v3.24.1
> 7 Dec 2022

* GSO bug fixes
* BGP secret support

### Calico-VPP v3.23.0
> 11 May 2022

Calico/VPP has reached beta status !

* The versioning scheme changes to match Calico's release number to make it clearer. The assumption being that Calico/VPP version ``vA.B.X`` works with Calico version ``vA.B.Y`` in the event there are independent bugfix releases.
* Many bugfixes went in for this release :
  - Checking for IP address conflict before creating pods
  - Refactoring the etcd watcher logic to better handle expirations, and network failures.
  - For ipsec, cancel pending negotiation if we are switching the encapsulation type away from ipsec.
  - Fix disabling Wireguard on a per-node basis
  - Fix a NAT session creation race condition.
  - Fix af-packet interface locking due to a missing kick
  - Fix buffer accounting for pods
  - Reduce ipset resolution complexity
  - Expose interface tag for dpdk interfaces, to mark them as an uplink interface for the calico-vpp-agent (e.g. ``dpdk { dev 0000:d8:0a.0 { tag main-enp216s0f1 }``)
* Only keep the last two core dump files, as they can be quite huge in size (~1 GB)
* Try to print the last core dump stack trace when starting up, when gdb is installed. We will release images with gdb installed while in beta status, as it is relatively low footprint (~40MB additional space) and eases debugging.
* Improved the log output.
* Change the VRF tag to a hash (netns, ipversion) followed by the ip version, and the netns basename truncated to 63 chars
* Restart the agent on VPP's fault to simplify the state reconciliation process and avoid handling reprogramming failures.
* Move the main uplink interface
   - to a mounted & persistent netns if it is virtual (veth, tap), as the netns deletion would also trigger the interface deletion.
   - to the vpp process netns if it is physical, to rely on the kernel for auto restore on VPP fault
* Added better support for multiple TX queues per worker

### Calico-VPP v0.18.1
> 7 Jan 2022

* Fix issues when deploying on Kind
* Handle updates in the BGPConfiguration
* VPP bugfixes

### Calico-VPP v0.18.0
> 17 Dec 2021

* Add tests: kind environment, simple VCL container, testpmd serviceIP
* Use per tap VRF for host traffic
* Support BGPPeering features
* Add hostPort/hostIP support in pods
* Add support for host policies
* Watch available buffers for interfaces
* Partial support for multi tx infra

### Calico-VPP v0.17.0
> 15 Oct 2021

* Upgrade Calico to v3.20.2
* Add memif interface support for the pods
* Add support for exposing the VPP transport stack (host stack) in the pods
* Add prometheus exporter for pod network stats
* Add support for multiple interfaces in VPP
* Fix wireguard connectivity with node churn
* Enable compatibility with NSM
* Bind BGP listener to node address only (fixes a crash on nodes with IPv6 disabled)
* Fix packet drops with the af_packet driver and GRO

### Calico-VPP v0.16.0
> 23 Aug 2021

* Upgrade Calico to v3.20.0
* Add kind support
* Support service-based policy rules
* Fix MTU configuration in VPP
* Fix chained buffers handling with RDMA interfaces
* Fix IPsec support in interrupt mode in AWS

### Calico-VPP v0.15.0
> 25 Jun 2021

* Upgrade Calico to 3.19.1
* Support named ports in services
* Add RDMA and vmxnet3 drivers
* Use a launch template instead of a configuration container on EKS
* Add DPDK interrupt mode support for ENA on EKS
* Fix state reconciliation with VXLAN encapsulation
* Fixes for chained buffers with IPsec (IPsec now supports MTU > buffer size)

Known issues
* Chained buffers are not supported with RDMA interfaces. Ensure the MTU is smaller that the VPP buffer size (2048 bytes by default) when using RDMA interfaces (Mellanox CX series).
* IPsec is not supported with DPDK in interrupt mode on EKS

### Calico-VPP v0.14.0
> 29 Apr 2021

* Tech-preview release for Calico 3.19.0
* Changed deployment model to a daemonset separate from calico-node
* Changed uplink connectivity to L2 and to reuse the original interface name for better compatibility with pre-existing network configuration systems.
* Add async crypto support for IPsec
* Upgrade gobgp to v2.25.0
* Improved MTU handling

### Calico-VPP v0.13.0
> 9 Mar 2021

* Support for maglev load-balancing for services
* Checksum offloads fix
* Various bugfixes (ipsec, ping, interface deletion)

### Calico-VPP v0.12.1
> 19 Feb 2021

* Add interrupt mode support for the DPDK driver
* Fixes for IPsec encryption
* Checksum offload fix for virtio interfaces
* Graceful recovery if the number of queues cannot be configured with af_xdp

### Calico-VPP v0.12.0
> 4 Feb 2021

* Full calico policies support
* Support LoadBalancer / ExternalIP services
* Support externalTrafficPolicy=local for services
* Support MTU autodetection
* VPP: reduce CPU consumption
* Add IPv6 tests
* Fixes for AVF, af_packet and af_xdp drivers
* Support custom VXLan port

### Calico-VPP v0.11.1
> 8 Jan 2021

* Update to calico v3.17.1
* Fix bug on link-local address configuration on vpptap0
* Fix vpp-manager crash on config generation failure
* Improve / cleanup YAML deployment manifest

### Calico-VPP v0.11.0
> 16 Dec 2020

* Policies support
* Containerd compatibility

### Calico-VPP v0.10.0
> 7 Dec 2020

* MTU configuration
* Wireguard support (inter-operable with calico linux/eBPF nodes)
* Updated yaml templates

### Calico-VPP v0.9.0
> 19 Nov 2020

* Driver autodetection & unified integration
* Integrated support for VPP native AVF driver
* Calico Policies support alpha
* Usability improvements

### Calico-VPP v0.8.2
> 17 Nov 2020

* State reconciliation : allow calico-vpp agent restart
* Added several performance tuning parameters

### Calico-VPP v0.8.1
> 21 Sep 2020

* AF_XDP support
* ICMP translation support (natOutgoing, serviceIP errors)

### Calico-VPP v0.8.0
> 4 Sep 2020

* VXLAN support
* tun (L3) interfaces for containers instead of tap (L2)
* Support for natOutgoing for services with backends outside of the cluster (required for EKS)
* Fix default route installation and restoration on the nodes
* Fix UDP packet punting to the nodes

### Calico-VPP v0.7.1
> 20 Aug 2020
* Fix ipsec support in v6 and dualstack

### Calico-VPP v0.7.0
> 19 Aug 2020
* Support for natOugoing v4 & v6
* Support of Dualstack clusters (also with ipip or ipsec between nodes)
* More configuration params: default routes, buffer tuning, etc..

### Calico-VPP v0.6.1
> 28 Jul 2020

* Upgrade to Calico v3.15.1
* Support for virtio interfaces
* Smaller and simpler test setup (it can run on a laptop!)
* Kustomize-based configurations
* Automated end-to-end testing