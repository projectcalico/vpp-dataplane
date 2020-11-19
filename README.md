# Calico VPP dataplane
<img src="http://docs.projectcalico.org/images/felix.png" width="100" height="100">

This repository contains the source for Calico's VPP dataplane integration. The integration is in incubation status, with significant development in progress.

## Get Started Using Calico/VPP

* Please [see the Wiki](https://github.com/projectcalico/vpp-dataplane/wiki) for more detailed information about this project
* If you would like to try it, you can read the [Setup Instructions](https://github.com/projectcalico/vpp-dataplane/wiki/Getting-started)
* If you want to learn more about Calico, see the documentation on [docs.projectcalico.org](https://docs.projectcalico.org).
* If you have questions, feel free to drop us a line in the [Calico Slack room #vpp](https://slack.projectcalico.org/)

## Get Started Developing Calico/VPP

Contributions to this code are welcome! Before starting, make sure you've read [the Calico contributor guide][contrib].

### License

Calico binaries are licensed under the [Apache v2.0 license](LICENSE), with the exception of some [GPL licensed eBPF programs](https://github.com/projectcalico/felix/tree/master/bpf-gpl).

Calico imports packages with a number of apache-compatible licenses. For more information, see [filesystem/licenses](./filesystem/licenses). In addition, the base container image contains
pre-packaged software with a variety of licenses.


[contrib]: https://github.com/projectcalico/calico/blob/master/CONTRIBUTING_CODE.md
