# VPP Manager

This simple program manages VPP in the context of the Calico-VPP intgration.
It is responsible for:
- VPP IP configuration. It supports statically replicating the linux configuration, getting the configuration from the Calico node object, and using DHCP. It creates a tap interface in Linux that gives the host access to the container network. If this configuration fails, this program cleanly aborts.
- Init program responsibilities: it propagates received signals to VPP. Since VPP should not spawn any other processes, zombie reaping is not necessary.
- Cleanup: When VPP exits, it properly restores the configuration to what it was before launch, so that Linux gets connectivity back if there is only one interface. This program then exits with VPP's exit code.


## Environement varibales

- `CALICOVPP_INTERFACE` : name of the vpp interface to get the connectivity configuration from.

## Configuration files

- `CALICOVPP_CONFIG_EXEC_TEMPLATE` : template for startup script written to `/etc/vpp/startup.exec`. If this is a bash script (starting with the `#!/bin/bash` shebang) it will be executed before vpp starts.
- `CALICOVPP_CONFIG_TEMPLATE` : vpp config file written to `/etc/vpp/startup.conf`

The following substitutions will be done :

- `__VPP_DATAPLANE_IF__` will be the value of `CALICOVPP_INTERFACE`
- `__PCI_DEVICE_ID__` will be the PCI linux gives for the interface `CALICOVPP_INTERFACE` (this doesn't happen for `startup.exec` as it might be its job to create this NIC)
