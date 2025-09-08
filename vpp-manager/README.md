# VPP Manager

This simple program manages VPP in the context of the Calico-VPP intgration.
It is responsible for:

- VPP IP configuration. It supports statically replicating the linux
configuration, getting the configuration from the Calico node object, and
using DHCP. It creates a tap interface in Linux that gives the host access
to the container network. If this configuration fails, this program cleanly
aborts.
- Init program responsibilities: it propagates received signals to VPP. Since
VPP should not spawn any other processes, zombie reaping is not necessary.
- Cleanup: When VPP exits, it properly restores the configuration to what it
was before launch, so that Linux gets connectivity back if there is only one
interface. This program then exits with VPP's exit code.
