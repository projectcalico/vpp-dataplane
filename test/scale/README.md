# SCALE TESTING

## Introduction:

Scale testing involves assessing the performance and behavior of a system under high loads. It helps identify potential bottlenecks and performance issues that may arise in real-world scenarios, and it's important for ensuring that a system can handle increased loads as user demands grow over time. This document will detail the scale testing results of Calico/VPP, including the methodology used and the findings.

## Methodology:

The scale testing was conducted on Kubernetes clusters with CalicoVPP installed.
The testing was performed using a dedicated testing environment that simulated overload on different resources in Kubernetes.

### Scaling number of real nodes:

To conduct this scale test, we set up a KinD Kubernetes cluster. So nodes in our cluster are actually Docker containers running locally on our big servers.
One of the important challenges is that every node in our cluster has a VPP instance running, which may impact our processor performance.
We use a patched version of Kind that allows pinning kubernetes nodes (that are containers) to cpus. We pin every 2 nodes to a couple of cpus, to ensure that not many VPP instances use the same cpu.
Then when running VPP, we pin its main thread to one of the cpus, to let the other one free for kubelet and calico calculations.
For example: nodes 1 and 2 are pinned to the cpus (4, 5), and their respective VPP instances are both pinned to the cpu 4.
Our VPP has a customized configuration that excludes the use of hugepages due to their high resource requirements.

This way, we run *60 nodes* on a local cluster.
This cluster takes some time to stabilize, and there is still room for further optimization

### Scaling number of real pods:

Scaling the number of pods is possible up to the buffer limit of VPP, or to the limit number of IP addresses in our IPPool. CNI and CalicoVPP agent respond quite quickly to the creation of real pods.
We use [*kboom*](https://github.com/mhausenblas/kboom) to conduct this test.

### Scaling involving restarting nodes/pods:

Restarting nodes manually is tested in a *vagrant* cluster. It works fine with connectivity to pods being recovered (using new IP addresses).

Restarting CalicoVPP is tested using [*Chaos monkey*](https://github.com/asobti/kube-monkey) to schedule deletion of sets of pods, applied on our calicovpp dataplane pods, to have them restart.

These tests result in successful restarts

### Scaling number of virtual pods:

[*Mocklet*](https://github.com/VineethReddy02/mocklet) allows to create thousands of virtual pods.
These are not real pods but they trigger CalicoVPP components like CNI server, Policy server, and service Server.
We use these pods to test services by targeting a thousand virtual pods being a backend for a service.
We also test the creation of 100K policies on an interface to have them created in VPP.
These tests are successful and result in stable behaviors in CalicoVPP and VPP itself.


## Running Scale tests:

We use this version of kind
````bash
cd ..
git clone https://github.com/kubernetes-sigs/kind
git remote add calicovpp https://github.com/calico-vpp/kind
git fetch calicovpp
git checkout calicovpp/allow-cpu-pinning-for-kind-nodes
make build
sudo mv bin/kind /usr/local/bin/kind
````

To run a scale test, create a cluster with:

````bash
export N_KIND_WORKERS=60
export N_KIND_CONTROL_PLANES=6
make kind-new-cluster
make load-kind
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/master/manifests/tigera-operator.yaml
```` 
If you want to use local CalicoVPP images run the following:
````bash
export CALICO_AGENT_IMAGE=localhost:5000/calicovpp/agent:latest
export CALICO_VPP_IMAGE=localhost:5000/calicovpp/vpp:latest
export MULTINET_MONITOR_IMAGE=localhost:5000/calicovpp/multinet-monitor:latest
export IMAGE_PULL_POLICY=Always
````
Use this config to disable hugepages and pin vpps to specific cpus.
````bash
# ---------------- vpp config ----------------
export CALICOVPP_DISABLE_HUGEPAGES=true
export CALICOVPP_CONFIG_TEMPLATE="
    unix {
      nodaemon
      full-coredump
      log /var/run/vpp/vpp.log
      cli-listen /var/run/vpp/cli.sock
      pidfile /run/vpp/vpp.pid
    }
    buffers {
        page-size 4K
    }
    cpu { main-core __CPUSET_CPUS_FIRST__ }
    socksvr { socket-name /var/run/vpp/vpp-api.sock }
    plugins {
        plugin default { enable }
        plugin calico_plugin.so { enable }
        plugin dpdk_plugin.so { disable }
    }"
bash ./yaml/overlays/dev/kustomize.sh up
````