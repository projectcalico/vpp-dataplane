## Setting up a kind based development cluster

In order to get a development setup, we usually use [kind](https://kind.sigs.k8s.io/).
We also have a [vagrant based setup](https://github.com/projectcalico/vpp-dataplane/blob/master/test/vagrant)

### First create a kind cluster :
````bash
make kind-new-cluster nodes=3 # 3 is an example of number of worker nodes in your cluster
````
This creates a dual-stack cluster with four nodes. The cluster is configured with a local registry to allow sharing images on all nodes without having to copy them [you can read more about his here](https://kind.sigs.k8s.io/docs/user/local-registry/). You can adapt the configuration by editing `./test/kind/new_cluster.sh`

If you are running on Windows, you can also [make this work with a few changes](https://github.com/projectcalico/vpp-dataplane/blob/master/test/kind/wsl_deployment_on_kind.md)

You should now have `kubectl get nodes` reporting four nodes

### Install the calico operator to the cluster
````bash
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/master/manifests/tigera-operator.yaml
````

### Build development images

First you will need to build vpp locally with the required patches. This takes a while but it's usually not run often.
````bash
make -C vpp-manager/ vpp
````

Then build the agents, containers & push them to the local docker repository
````bash
make dev-kind
````

Then pull calico images once and load them on the nodes (to avoid pulling image limitation issues in case you have a large cluster)
````bash
make load-kind
````

### Install Calico/VPP targeting the images just built

You can use the `./yaml/overlays/dev/kustomize.sh` script that takes its configuration from environment and generates the installation yaml for Calico/VPP.

````bash
# ---------------- images ----------------
export CALICO_AGENT_IMAGE=localhost:5000/calicovpp/agent:latest
export CALICO_VPP_IMAGE=localhost:5000/calicovpp/vpp:latest
export MULTINET_MONITOR_IMAGE=localhost:5000/calicovpp/multinet-monitor:latest
export IMAGE_PULL_POLICY=Always

# ---------------- interfaces ----------------
export CALICOVPP_INTERFACE=eth0
export CALICOVPP_NATIVE_DRIVER=af_packet

# ---------------- encaps ----------------
export CALICO_ENCAPSULATION_V4=IPIP
export CALICO_ENCAPSULATION_V6=None
export CALICO_NAT_OUTGOING=Enabled
````
To run with hugepages on:

````bash
# ---------------- vpp config ----------------
export CALICOVPP_CONFIG_TEMPLATE="unix {
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
export CALICOVPP_CONFIG_TEMPLATE="unix {
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
bash ./yaml/overlays/dev/kustomize.sh up nohuge
````

### Removing the CNI

The outputed yaml is stored in `/tmp/calico-vpp.yaml`, you can uninstall by simply runnning :
````bash
kubectl delete -f /tmp/calico-vpp.yaml
````
