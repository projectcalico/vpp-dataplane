
# Setting up a test kind cluster

## Default installation

The example below creates a four nodes kind cluster with the Calico/VPP dataplane.

````bash
echo 'kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "11.0.0.0/16,fd20::0/64"
  serviceSubnet: "11.96.0.0/12,fd10::0/120"
  ipFamily: dual
nodes:
- role: control-plane
- role: worker
- role: worker
- role: worker
' | kind create cluster --config=-

# Add the Calico Operator, and ask it to install Calico itself
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/master/manifests/tigera-operator.yaml
kubectl create -f  https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/yaml/calico/installation-default.yaml

# Install the Calico/VPP flavor for kind with multinet enabled
kubectl create -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/yaml/generated/calico-vpp-kind.yaml
````

## Multinet kind cluster

The example below creates a four nodes kind cluster with the
Calico/VPP dataplane and multinet enabled.

````bash
echo 'kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "11.0.0.0/16,fd20::0/64"
  serviceSubnet: "11.96.0.0/12,fd10::0/120"
  ipFamily: dual
nodes:
- role: control-plane
- role: worker
- role: worker
- role: worker
' | kind create cluster --config=-

# multinet CRDs, multus plugin and ipam
kubectl create -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/test/yaml/multinet/projectcalico.org_networks.yaml
kubectl create -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/test/yaml/multinet/whereabouts-daemonset-install.yaml
kubectl create -f https://github.com/k8snetworkplumbingwg/multus-cni/raw/master/deployments/multus-daemonset-thick.yml
kubectl create -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_ippools.yaml
kubectl create -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_overlappingrangeipreservations.yaml

# Create two sample 'blue' and 'red' PodNetwork & NetworkAttachementDefinitions
kubectl create -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/test/yaml/multinet/network.yaml
kubectl create -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/test/yaml/multinet/netdefinitions.yaml

# Add the Calico Operator, and ask it to install Calico itself
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/master/manifests/tigera-operator.yaml
kubectl create -f  https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/yaml/calico/installation-default.yaml

# Install the Calico/VPP flavor for kind with multinet enabled
kubectl create -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/yamls-overalays/yaml/generated/calico-vpp-kind-multinet.yaml
````

This can be leveraged with the sample pod below

```` bash
# Finally a sample pod leveraging memifs
kubectl create -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/master/test/yaml/multinet/pod-memif.yaml
````
