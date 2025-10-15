# Calico-VPP versions

Starting with version ``v3.23.0``, the versioning scheme for Calico/VPP matches
that of Calico. Calico/VPP releases are done within a two weeks period after
the Calico release date.

As a Calico/VPP version works in conjunction with a Calico version, we offer
the guarantee that patch releases are compatible for any given minor revision.
Calico/VPP version ``vA.B.x`` will work with Calico version ``vA.B.y`` for any
``(x, y)``. This allows patch release to carry minor bugfixes.

## CalicoVPP - VPP mapping table

| CalicoVPP     | VPP                                                      |
| ------------- | -------------------------------------------------------- |
| v3.30.0       | v25.06  ~ 1573e751c5478d3914d26cdde153390967932d6b       |
| v3.29.3       | v25.06  ~ 1573e751c5478d3914d26cdde153390967932d6b       |
| v3.29.2       | v25.06  ~ 1573e751c5478d3914d26cdde153390967932d6b       |
| v3.29.1       | v25.06  ~ 1573e751c5478d3914d26cdde153390967932d6b       |
| v3.29.0       | v24.10  ~ cfa0953251cbab435307baf3dcd249fd95afaf1f       |
| v3.28.0       | v24.02+ ~ 2ae8f79b5087c8da7d30283693f22ca710a60347       |
| v3.27.0       | v24.02-rc0 ~ 7419bede7ad73544338fd4363da833b2d5fc89a5    |
| v3.26.4       | v25.06  ~ 1573e751c5478d3914d26cdde153390967932d6b       |
| v3.26.3       | v25.02                                                   |
| v3.26.2       | v25.02                                                   |
| v3.26.1       | v23.10-rc0 ~ a7dd04d73bf5abed944fb77a5e957bbad24e2750    |
| v3.26.0       | v23.10-rc0 ~ a7dd04d73bf5abed944fb77a5e957bbad24e2750    |
| v3.25.3       | v23.06 8a0fd0669047c90d410d2ed5cb508bfe778b932a          |
| v3.25.2       | v23.06 8a0fd0669047c90d410d2ed5cb508bfe778b932a          |
| v3.25.1       | v23.06 8a0fd0669047c90d410d2ed5cb508bfe778b932a          |
| v3.25.0       | v23.06 8a0fd0669047c90d410d2ed5cb508bfe778b932a          |
| ------------- | -------------------------------------------------------- |

## Releases

### Calico-VPP v3.30.0

> 15th October 2025

- Bugfixes
  - Fix the weird DHCP/DNS issue
  - Fix vclsidecar build missing .25.06 sos (#786)
  - Cherrypick hoststack fix for connectionless UDP
  - Fix CI vpp tarball caching issue (#788)
  - Fix log flooding issue with Prometheus (#768)
  - Fix prom stats overlap & RC
  - Fix makefile VPP_HASH cache invalidation
  - Fix endpoint watcher delete handler cast
  - Fix linter NewInformer deprecation & ipampool copy

- Features
  - build to debug docker images
  - Add make-kind directive
  - Cherry pick hoststack patches fixing session reuse (#803)
  - yaml: fix eks breakage in AL2023 (#794)
  - Add prefix to prometheus stats
  - Update prefix_watcher from clientv1 to clientv3
  - added TCP and session stats
  - Refactor prometheus exporter
  - Add VCL ldp cherrypick
  - convert vppdev.sh to Go binary
  - Merge pull request #757 from projectcalico/remove-policiesenabled-flag
  - Make vpp_clone_current ignore merged change-ids
  - cherry-pick certain patches only if cloning VPP 25.06
  - vpp: cherry pick the gso/cksum offload refactoring patches
  - Upgrade calico versions to v3.30.1
  - vpp: bump vpp version to 25.06
  - Use single pbl index per pod
  - Add vcl sidecar image
  - rename policy server into felix server
  - Add IP neighbor 30s aeging
  - behavior for hep not matching interface name
  - support v6 hostport pods
  - allow running 'make vpp' from an arbitrary directory
  - add policy description document
  - add makefile target to build VPP from master
  - add missing packages to dev image
  - vpp: bump vpp to 25.06 RC0 (25.06-rc0~247-gaf9fa5d40)
  - Disable memif if queue spread by default
  - Add auto corepining path
  - Add prometheusEnabled feature gate.
  - Make prometheus poll freq and port configurable
  - test: upgrade trex image to v3.06
  - yaml: increase buffers-per-numa for openshift scenario

### Calico-VPP v3.29.3

> 22nd September 2025

- Bugfixes:
  - Cherry pick hoststack patches fixing session reuse

### Calico-VPP v3.29.2

> 15th September 2025

- Bugfixes:
  - add vpp prefix to prometheus stats
  - Fix vclsidecar build missing .25.06 sos
  - Cherrypick hoststack fix for connectionless UDP
  - Fix CI vpp tarball caching issue

### Calico-VPP v3.29.1

> 8th September 2025

- Bugfixes:
  - Prometheus support:
    - Fix log flooding issue with Prometheus by @aritrbas in #770
    - Fix prometheus stats overlap & RC
    - Add prometheus stats for TCP and session
    - Add prometheusEnabled feature gate.
    - Make prometheus poll freq and port configurable
  - VPP changes
    - vpp: bump vpp to 25.06 RC0 (25.06-rc0~247-gaf9fa5d40)
    - vpp: cherry pick the gso/cksum offload refactoring patches
    - vpp: bump vpp version to 25.06
  - Add IP neighbor 30s aeging
  - Behavior for hep not matching interface name
  - Fix service bug in endpoint watcher delete handler
  - Use single pblIndex per pod
- Features backports:
  - Rename policy server into felix server
  - Support v6 hostport pods
  - Add VCL ldp cherrypick
  - Add vcl sidecar and document it
  - Disable memif if queue spread by default
  - agent: remove policies enabled debug flag
  - Add auto corepining path

[Full v3.29.1 release page](https://github.com/projectcalico/vpp-dataplane/releases/tag/v3.29.1)

### Calico-VPP v3.26.4

> 8th September 2025

- Bugfixes:
  - Fix prom stats overlap & RC by @sknat in #763
- Features backports:
  - vpp: bump vpp version to 25.06 by @sknat in #766

[Full v3.26.4 release page](https://github.com/projectcalico/vpp-dataplane/releases/tag/v3.26.4)

### Calico-VPP v3.26.3

> 25th July 2025

- Bugfixes:
  - Revert the fix for VPP checksum offload support in kind
  - Add relative core pinning cherry pick
  - Add IP neighbor 30s aeging
- Features backports:
  - Added TCP and session stats
  - Refactor prometheus exporter

[Full v3.26.3 release page](https://github.com/projectcalico/vpp-dataplane/releases/tag/v3.26.3)

### Calico-VPP v3.26.2

> 25th July 2025

- Bugfixes:
  - use single pbl index per pod
  - multiple Prometheus implementation fixes and feature gates
  - Fix for VPP checksum offload support in kind
  - Fix SpreadTxQueuesOnWorkers syntax
  - Disable memif intf spread by default
  - Agent: add rpf to rpf table tag
  - Fix nodeIP nil in cnat services
  - Support setting failsafepolicy net by @sknat in #691
  - Fix link watcher
  - Fix nodeport service snat
- Features backports:
  - Add redirect to host rules for DNS support in kind
  - Add VCL cherrypick

[Full v3.26.2 release page](https://github.com/projectcalico/vpp-dataplane/releases/tag/v3.26.2)

### Calico-VPP v3.29.0

> 8th Nov 2024

- New features:
  - Upgrade vpp to 24.10
    - Full release notes at [https://s3-docs.fd.io/vpp/24.10/aboutvpp/releasenotes/v24.10.html](https://s3-docs.fd.io/vpp/24.10/aboutvpp/releasenotes/v24.10.html)
    - DPDK bump to 24.07
    - Addition of automatic core pinning
    - vnet new device driver infra
  - GoBGP upgrade to v3.30.0
  - GoVPP upgrade to v0.11.0
- Feature graduation
  - memif support now default to enabled
- Fixes:
  - Ipv6 node connectivity was broken in previous version, this release
  fixes the behavior.

[Full v3.29.0 release page](https://github.com/projectcalico/vpp-dataplane/releases/tag/v3.29.0)

### Calico-VPP v3.28.0

> 31st May 2024

- New features:
  - Support using cidrs when setting failsafepolicies in felixconfig
  - Upgrade vpp to 24.02-rc0~186 which contains several bugfixes and the
  following features:
    - b1a1209ce dpdk: bump rdma-core to 49.0
    - 327c32306 dpdk: bump to DPDK 23.11
    - 006c071b0 dpdk: add Mellanox BlueField NICs
    - 029f039d5 dpdk: add ConnectX-6LX and ConnectX-7 support
    - 2d725c612 ena: Amazon Elastic Network Adapter (ENA) native driver
    - 67f03ba71 iavf: interrupt mode support
    - 47447f1f5 iavf: new driver using new dev infra
    - 29d07dbef af_packet: remove UNIX_FILE_EVENT_EDGE_TRIGGERED flag
    - 7f75e80f0 vppinfra: refactor interrupt code
    - ddf6cec37 dev: initial set of APIs
    - b8dd9815e dev: interrupt mode support
- Bug fixes:
  - vpp: include udp rx swifindex fix
  - update govpp dependancy to include memory leak fix

[Full v3.28.0 release page](https://github.com/projectcalico/vpp-dataplane/releases/tag/v3.28.0)

### Calico-VPP v3.27.0

> 19th December 2023

**Calico-VPP is now GA !**

- New features:
  - Lots of new documentation, take a look at [./docs](./docs)
  - Added deployment guide for Openshift, multiple fixes
  - Added support for v6 rules in BGPfilters
  - uRPF fib tables are now named 'RPF'
  - Added ``CALICOVPP_INITIAL_CONFIG`` option ``"redirectToHostRules"`` to
  redirect certain flows to the host instead of the uplink. This is needed
  for special cases (e.g. kind DNS) where you need to apply iptable rule to
  some control traffic.
  - Implement dataplane service hashconfig parametrization
  - vpp: upgrade to v24.02-rc0 (29 sept 23), Notable changes are
    - a181eaa59 - virtio: add support for tx-queue-size
    - 61ab09472 - dpdk: bump rdma-core to 46.1
    - 442189849 - dpdk: bump to DPDK 23.07

- Bug fixes:
  - Allow simultaneous usage of memif (PBL) and VCL
  - Fix nodeport service src NAT issue, we do need to src NAT nodeports when
  the service is not local
  - Fix DNS support in kind adding custom redirect rules
  - Fix vagrant yaml & flat mode
  - Fix cnat checksum offload update issue
  - Fix IPIP tunnel overlapping leading to traffic blackholing

[Full v3.27.0 release page](https://github.com/projectcalico/vpp-dataplane/releases/tag/v3.27.0)

### Calico-VPP v3.26.1

> 18th December 2023

- Bug fixes
  - allow simultaneous usage of PBL and VCL
  - Fix IPIP tunnel overlapping leading to traffic blackholing

[Full v3.26.1 release page](https://github.com/projectcalico/vpp-dataplane/releases/tag/v3.26.1)

### Calico-VPP v3.26.0

> 19th June 2023

- New features:
  - Automate build & integration test on each commit
  - Cluster scale testing, with [documented methodology](./test/scale/README.md)
  - Add [BGP filter support](https://docs.tigera.io/calico/latest/reference/resources/bgpfilter#bgp-filter-definition)
  leveraging [GoBGP Policies](https://github.com/osrg/gobgp/blob/master/docs/sources/policy.md)
  - Add service annotation controlling load-balancer type (ECMP, Maglev, DSR)
  - Automate Openshift testing
  - vpp: upgrade to v23.10
  - bump container base image to ubuntu 22.04
  - Add failsafe container termination 10s after component error (can be
  set with `CALICOVPP_GRACEFUL_SHUTDOWN_TIMEOUT`)
  - Add the ability to map uplinks to podNetworks

- Bug fixes
  - Use host ip as default host port address if not provided
  - Fix an error affetcing the multi-network watcher restart
  - Fix DNS issue impacting Openshift
  - Fix service of type=LoadBalancer support
  - Fix CNI startup race condition resulting in sporadic agent deadlocks
  - Add ip6 address of interfaces in the show capo int CLI
  - Fix an issue impacting wireguard in dualstack mode
  - Force enabliong ipv6 on container tuntap in case sysctl decided otherwise.
  - fix loopbacks leftover state in vxlan provider for multinet

[Full v3.26.0 release page](https://github.com/projectcalico/vpp-dataplane/releases/tag/v3.26.0)

### Calico-VPP v3.25.1

> 1st Mars 2023

- Bug fixes
  - Fix a deadlock that happened when cleaning conflicting addresses for pods
  - Upgrade build envs to ubuntu 22.04 or link statically to avoid glibc
  version mismatch

### Calico-VPP v3.25.0

> 14 Feb 2023

- New features:
  - Configuration refactoring: standardize agent configs
  [see documentation for details](docs/config.md)
    - This allows controling the number queues, and queue sizes for each pod
    - Defaults & Limits are also available cluster-wide
  - Support for multinet-aware policies
  - Migrate to felix messages for node & route updates. This improves
  scalability preventing nodes to listen to all nodes updates.
  - Upgrade goBGP to v3.10.0
  - Update image base to ubuntu 22.04
  - Change capo CLI output to use RX/TX instead of ingress/egress
  - Add prometheus stats for memif
  - Add SCTP support for services

- Bug fixes
  - Multiple policies fixes (mostly host endpoint related)
  - Add startup script reporting an agent waiting for a condition
  - CI: automation of tests & linting on every patch
  - Connectivity: fix cross-subnet logic
  - Disable RA on all uplink interfaces
  - Fix to greedy corefile cleanup
  - Multiple VPP af-pkt, GSO & cksum offload fixes
  - More kind customizations for development

### Calico-VPP v3.24.1

> 21 Mar 2023

- Features:
  - Support for BGP secrets

- Bug fixes
  - Dataplane fixes for GSO
  - Fix segfault in stats appearing with more than 4 workers & DPDK

### Calico-VPP v3.24.0

> 19 Sep 2022

- New features:
  - Multinet support (including attaching multiple networks to pods via
  tun/tap or memif, services support, preparation for policies integration).
  - Add strict RPF check for traffic originated from pods, with possibility to
  add exceptions with `allowSpoofing` annotation.
  - Uplink route and MTU monitoring move from vpp-manager to the agent. As a
  consequence, multi-uplink now supports differentiated MTUs.

- Bug fixes
  - Integrate VPP fix for interrupt mode support with ENA/dpdk.
  - Align with Wireguard v6 support added in Calico v3.24, and fix dual stack
  support for Wireguard.

- Focus on code quality, add integration tests, address linting issues.

### Calico-VPP v3.23.1

> 7 Dec 2022

- GSO bug fixes
- BGP secret support

### Calico-VPP v3.23.0

> 11 May 2022

Calico/VPP has reached beta status !

- The versioning scheme changes to match Calico's release number to make it
clearer. The assumption being that Calico/VPP version ``vA.B.X`` works with
Calico version ``vA.B.Y`` in the event there are independent bugfix releases.
- Many bugfixes went in for this release :
  - Checking for IP address conflict before creating pods
  - Refactoring the etcd watcher logic to better handle expirations, and
  network failures.
  - For ipsec, cancel pending negotiation if we are switching the encapsulation
  type away from ipsec.
  - Fix disabling Wireguard on a per-node basis
  - Fix a NAT session creation race condition.
  - Fix af-packet interface locking due to a missing kick
  - Fix buffer accounting for pods
  - Reduce ipset resolution complexity
  - Expose interface tag for dpdk interfaces, to mark them as an uplink
  interface for the calico-vpp-agent (e.g.
  ``dpdk { dev 0000:d8:0a.0 { tag main-enp216s0f1 }``)
- Only keep the last two core dump files, as they can be quite huge in size
(~1 GB)
- Try to print the last core dump stack trace when starting up, when gdb is
installed. We will release images with gdb installed while in beta status, as
it is relatively low footprint (~40MB additional space) and eases debugging.
- Improved the log output.
- Change the VRF tag to a hash (netns, ipversion) followed by the ip version,
and the netns basename truncated to 63 chars
- Restart the agent on VPP's fault to simplify the state reconciliation process
and avoid handling reprogramming failures.
- Move the main uplink interface
  - to a mounted & persistent netns if it is virtual (veth, tap), as the netns
  deletion would also trigger the interface deletion.
  - to the vpp process netns if it is physical, to rely on the kernel for auto
  restore on VPP fault
- Added better support for multiple TX queues per worker

### Calico-VPP v0.18.1

> 7 Jan 2022

- Fix issues when deploying on Kind
- Handle updates in the BGPConfiguration
- VPP bugfixes

### Calico-VPP v0.18.0

> 17 Dec 2021

- Add tests: kind environment, simple VCL container, testpmd serviceIP
- Use per tap VRF for host traffic
- Support BGPPeering features
- Add hostPort/hostIP support in pods
- Add support for host policies
- Watch available buffers for interfaces
- Partial support for multi tx infra

### Calico-VPP v0.17.0

> 15 Oct 2021

- Upgrade Calico to v3.20.2
- Add memif interface support for the pods
- Add support for exposing the VPP transport stack (host stack) in the pods
- Add prometheus exporter for pod network stats
- Add support for multiple interfaces in VPP
- Fix wireguard connectivity with node churn
- Enable compatibility with NSM
- Bind BGP listener to node address only (fixes a crash on nodes with IPv6 disabled)
- Fix packet drops with the af_packet driver and GRO

### Calico-VPP v0.16.0

> 23 Aug 2021

- Upgrade Calico to v3.20.0
- Add kind support
- Support service-based policy rules
- Fix MTU configuration in VPP
- Fix chained buffers handling with RDMA interfaces
- Fix IPsec support in interrupt mode in AWS

### Calico-VPP v0.15.0

> 25 Jun 2021

- Upgrade Calico to 3.19.1
- Support named ports in services
- Add RDMA and vmxnet3 drivers
- Use a launch template instead of a configuration container on EKS
- Add DPDK interrupt mode support for ENA on EKS
- Fix state reconciliation with VXLAN encapsulation
- Fixes for chained buffers with IPsec (IPsec now supports MTU > buffer size)

Known issues:

- Chained buffers are not supported with RDMA interfaces. Ensure the MTU is
smaller that the VPP buffer size (2048 bytes by default) when using RDMA
interfaces (Mellanox CX series).
- IPsec is not supported with DPDK in interrupt mode on EKS

### Calico-VPP v0.14.0

> 29 Apr 2021

- Tech-preview release for Calico 3.19.0
- Changed deployment model to a daemonset separate from calico-node
- Changed uplink connectivity to L2 and to reuse the original interface name
for better compatibility with pre-existing network configuration systems.
- Add async crypto support for IPsec
- Upgrade gobgp to v2.25.0
- Improved MTU handling

### Calico-VPP v0.13.0

> 9 Mar 2021

- Support for maglev load-balancing for services
- Checksum offloads fix
- Various bugfixes (ipsec, ping, interface deletion)

### Calico-VPP v0.12.1

> 19 Feb 2021

- Add interrupt mode support for the DPDK driver
- Fixes for IPsec encryption
- Checksum offload fix for virtio interfaces
- Graceful recovery if the number of queues cannot be configured with af_xdp

### Calico-VPP v0.12.0

> 4 Feb 2021

- Full calico policies support
- Support LoadBalancer / ExternalIP services
- Support externalTrafficPolicy=local for services
- Support MTU autodetection
- VPP: reduce CPU consumption
- Add IPv6 tests
- Fixes for AVF, af_packet and af_xdp drivers
- Support custom VXLan port

### Calico-VPP v0.11.1

> 8 Jan 2021

- Update to calico v3.17.1
- Fix bug on link-local address configuration on vpptap0
- Fix vpp-manager crash on config generation failure
- Improve / cleanup YAML deployment manifest

### Calico-VPP v0.11.0

> 16 Dec 2020

- Policies support
- Containerd compatibility

### Calico-VPP v0.10.0

> 7 Dec 2020

- MTU configuration
- Wireguard support (inter-operable with calico linux/eBPF nodes)
- Updated yaml templates

### Calico-VPP v0.9.0

> 19 Nov 2020

- Driver autodetection & unified integration
- Integrated support for VPP native AVF driver
- Calico Policies support alpha
- Usability improvements

### Calico-VPP v0.8.2

> 17 Nov 2020

- State reconciliation : allow calico-vpp agent restart
- Added several performance tuning parameters

### Calico-VPP v0.8.1

> 21 Sep 2020

- AF_XDP support
- ICMP translation support (natOutgoing, serviceIP errors)

### Calico-VPP v0.8.0

> 4 Sep 2020

- VXLAN support
- tun (L3) interfaces for containers instead of tap (L2)
- Support for natOutgoing for services with backends outside of the cluster
(required for EKS)
- Fix default route installation and restoration on the nodes
- Fix UDP packet punting to the nodes

### Calico-VPP v0.7.1

> 20 Aug 2020

- Fix ipsec support in v6 and dualstack

### Calico-VPP v0.7.0

> 19 Aug 2020

- Support for natOugoing v4 & v6
- Support of Dualstack clusters (also with ipip or ipsec between nodes)
- More configuration params: default routes, buffer tuning, etc..

### Calico-VPP v0.6.1

> 28 Jul 2020

- Upgrade to Calico v3.15.1
- Support for virtio interfaces
- Smaller and simpler test setup (it can run on a laptop!)
- Kustomize-based configurations
- Automated end-to-end testing
