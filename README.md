# Calico VPP dataplane
<img src="http://docs.projectcalico.org/images/felix.png" width="100" height="100">

This repository contains the source for Calico's VPP dataplane integration. The integration is in incubation status, with significant development in progress.

Please see the [Wiki](https://github.com/calico-vpp/calico-vpp/wiki) for more detailed information about this project, and the [Setup Instructions](https://github.com/calico-vpp/calico-vpp/wiki/Setup-instructions) if you would like to try it.

## Get Started Using Calico

For users who want to learn more about the project or get started with Calico, see the documentation on [docs.projectcalico.org](https://docs.projectcalico.org).

## Get Started Developing Calico

Contributions to this code are welcome! Before starting, make sure you've read [the Calico contributor guide][contrib].

### License

Calico binaries are licensed under the [Apache v2.0 license](LICENSE), with the exception of some [GPL licensed eBPF programs](https://github.com/projectcalico/felix/tree/master/bpf-gpl).

Calico imports packages with a number of apache-compatible licenses. For more information, see [filesystem/licenses](./filesystem/licenses). In addition, the base container image contains
pre-packaged software with a variety of licenses.


[contrib]: https://github.com/projectcalico/calico/blob/master/CONTRIBUTING_CODE.md
