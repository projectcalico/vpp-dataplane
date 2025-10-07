# BGP in CalicoVPP

CalicoVPP implements feature parity with Calico so you can
refer to the main [Calico BGP documentation](https://docs.tigera.io/calico/latest/networking/configuring/bgp)
for configuration.

CalicoVPP implements BGP using a [gobgp](https://github.com/osrg/gobgp) server
running within the calico-vpp-node agent.

For troubleshooting, please consult [troubleshooting.md]
