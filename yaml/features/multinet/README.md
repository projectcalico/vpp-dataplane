## Test multinet feature

### Installing dependencies
#### Installing network CRD

````yaml
kubectl apply -f yaml/features/multinet/projectcalico.org_networks.yaml
kubectl apply -f yaml/features/multinet/whereabouts-daemonset-install.yaml
````

#### Installing multus deamonset

````yaml
kubectl apply -f https://github.com/k8snetworkplumbingwg/multus-cni/raw/master/deployments/multus-daemonset-thick.yml
kubectl apply -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_ippools.yaml
kubectl apply -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_overlappingrangeipreservations.yaml
````

### Enabling multinet

Install calicovpp as mentioned in https://projectcalico.docs.tigera.io/getting-started/kubernetes/vpp/getting-started

But use the manifest from `yaml/generated/calico-vpp-multinet.yaml` for installation.

### Creating network CRD 

You need to create the network crd.

````yaml
kubectl apply -f yaml/features/multinet/projectcalico.org_networks.yaml
kubectl apply -f yaml/features/multinet/whereabouts-daemonset-install.yaml
````

NOTE: if whereabouts is installed after calico/vpp is already installed, restart calicovpp in order to patch whereabouts.

### Testing

````yaml
make -C test/multinet/ test-memif-multinet
````

Make sure pods are created and are running.