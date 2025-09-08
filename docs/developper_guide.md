# CalicoVPP developper guide

## Setting up a kind based development cluster

In order to get a development setup, we usually use [kind](https://kind.sigs.k8s.io/).
We also have a [vagrant based setup](https://github.com/projectcalico/vpp-dataplane/blob/master/test/vagrant)

### First create a kind cluster

````bash
# 3 is an example of number of worker nodes in your cluster
make kind-new-cluster N_KIND_WORKERS=3
````

This creates a dual-stack cluster with four nodes. The cluster is configured
with a local registry to allow sharing images on all nodes without having to
copy them [you can read more about his here](https://kind.sigs.k8s.io/docs/user/local-registry/).
You can adapt the configuration by editing `./test/kind/new_cluster.sh`

If you are running on Windows, you can also [make this work with a few changes](https://github.com/projectcalico/vpp-dataplane/blob/master/test/kind/wsl_deployment_on_kind.md)

You should now have `kubectl get nodes` reporting four nodes

### Install the calico operator to the cluster

````bash
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/master/manifests/tigera-operator.yaml
````

### Build development images

First you will need to build vpp locally with the required patches. This takes
a while but it's usually not run often.

````bash
make -C vpp-manager/ vpp
````

or

````bash
make -C vpp-manager/ vpp BASE=origin/master
````

Then build the agents, containers & push them to the local docker repository

````bash
make dev-kind
````

Then pull calico images once and load them on the nodes (to avoid pulling image
limitation issues in case you have a large cluster)

````bash
make load-kind
````

### Install Calico/VPP targeting the images just built

You can use the `./yaml/overlays/dev/kustomize.sh` script that takes its
configuration from environment and generates the installation yaml for
Calico/VPP.

````bash
# ---------------- images ----------------
export CALICO_AGENT_IMAGE=localhost:5000/calicovpp/agent:latest
export CALICO_VPP_IMAGE=localhost:5000/calicovpp/vpp:latest
export MULTINET_MONITOR_IMAGE=localhost:5000/calicovpp/multinet-monitor:latest
export IMAGE_PULL_POLICY=Always

# ---------------- interfaces ----------------
export CALICOVPP_INTERFACES='{
  "uplinkInterfaces": [
    {
      "interfaceName": "eth0",
      "vppDriver": "af_packet"
    }
  ]
}'

# ---------------- encaps ----------------
export CALICO_ENCAPSULATION_V4=IPIP
export CALICO_ENCAPSULATION_V6=None
export CALICO_NAT_OUTGOING=Enabled
````

To add a redirection to host rule:

````bash
# --------------- redirect ----------------
export CALICOVPP_REDIRECT_PROTO="\"udp\""
export CALICOVPP_REDIRECT_PORT=53
export CALICOVPP_REDIRECT_IP="\"172.18.0.1\""
````

To enable memif:

````bash
# --------------- memif ----------------
export CALICOVPP_ENABLE_MEMIF=true
````

To run multinet:

````bash
# --------------- multinet ----------------
export CALICOVPP_ENABLE_MULTINET=true
export CALICOVPP_ENABLE_MEMIF=true
kubectl apply -f test/yaml/multinet/projectcalico.org_networks.yaml
kubectl apply -f test/yaml/multinet/whereabouts-daemonset-install.yaml
kubectl apply -f https://github.com/k8snetworkplumbingwg/multus-cni/raw/master/deployments/multus-daemonset-thick.yml
kubectl apply -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_ippools.yaml
kubectl apply -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_overlappingrangeipreservations.yaml

````

To run with hugepages on:

````bash
# ---------------- vpp config ----------------
export CALICOVPP_CONFIG_TEMPLATE="
    unix {
      nodaemon
      full-coredump
      log /var/run/vpp/vpp.log
      cli-listen /var/run/vpp/cli.sock
      pidfile /run/vpp/vpp.pid
    }
    buffers {
      buffers-per-numa 262144
    }
    socksvr { socket-name /var/run/vpp/vpp-api.sock }
    plugins {
        plugin default { enable }
        plugin calico_plugin.so { enable }
        plugin dpdk_plugin.so { disable }
    }"
bash ./yaml/overlays/dev/kustomize.sh up
````

To run without hugepages

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
    socksvr { socket-name /var/run/vpp/vpp-api.sock }
    plugins {
        plugin default { enable }
        plugin calico_plugin.so { enable }
        plugin dpdk_plugin.so { disable }
    }"
bash ./yaml/overlays/dev/kustomize.sh up
````

### Removing the CNI

The outputed yaml is stored in `/tmp/calico-vpp.yaml`, you can uninstall by
simply runnning :

````bash
kubectl delete -f /tmp/calico-vpp.yaml
````

## Setting up a VM (vagrant) based development cluster

In order to test Calico-VPP, you can simply use our test infrastructure to
deploy it on a 3-VM cluster. Requirements are :

- an Ubuntu 18.04 or 20.04 machine
- 8 CPU
- 16 GB RAM
- 100GB disk
- kubectl installed: <https://kubernetes.io/docs/tasks/tools/install-kubectl/>
- docker installed: <https://docs.docker.com/engine/install/ubuntu/>

If you are connected to a network that requires the use of a proxy server to
reach the public ubuntu repositories, or that restricts the use of the Google
public DNS servers, configure the following variables in your environment
before running any of the commands below:

````console
export DNS_SERVER=8.8.8.8
export VAGRANT_VM_PROXY=http://proxy.corp:80
````

Start by cloning this repository to get all the necessary scripts:

````console
git clone git@github.com:projectcalico/vpp-dataplane.git
````

Then run the following commands to setup the test cluster:

````console
make install-test-deps
make start-test-cluster
````

At this point, you should be able to interact with the new cluster using
kubectl, but the cluster won't have a CNI configured yet.

````console
kubectl get nodes -o wide
````

Finally, you can install Calico with the VPP dataplane using:

````console
make test-install-calicovpp
````

To install development images (that allow to recompile and restart calico/vpp
without recreating images), run:

````console
# Build VPP in debug mode
make cherry-vpp
make -C vpp-manager/vpp_build install-dep build
make dev
make load-images
make test-install-calicovpp-dev
````
