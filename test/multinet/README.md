## Test multinet feature

### Creating network CRD 

You need to create the network crd.

````yaml
kubectl apply -f yaml/features/multinet/projectcalico.org_networks.yaml
kubectl apply -f yaml/features/multinet/whereabouts-daemonset-install.yaml
````

### Running multus

You need to run multus as a daemonset

````yaml
git clone https://github.com/k8snetworkplumbingwg/multus-cni.git && cd multus-cni
cat ./deployments/multus-daemonset-thick-plugin.yml | kubectl apply -f -
````

### Running Whereabouts ipam

You need to create crds for whereabouts ipam and run it as a daemonset

````yaml
git clone https://github.com/k8snetworkplumbingwg/whereabouts && cd whereabouts
kubectl apply \
    -f doc/crds/whereabouts.cni.cncf.io_ippools.yaml \
    -f doc/crds/whereabouts.cni.cncf.io_overlappingrangeipreservations.yaml \
    -f doc/crds/ip-reconciler-job.yaml
````

Now install calico/vpp (or restart it if already installed) in order to patch whereabouts.

To use memif interfaces in multinet you need to edit the calico-vpp-node daemonset yaml to enable memif support.

````yaml
kind: DaemonSet
apiVersion: apps/v1
metadata:
  name: calico-vpp-node
  namespace: calico-vpp-dataplane
spec:
  template:
    spec:
      containers:
        - name: agent
          image: calicovpp/agent:latest
          env:
            - name: CALICOVPP_ENABLE_MEMIF
              value: "true"
````

### Testing

````yaml
make -C test/multinet/ test-memif-multinet
````

Make sure pods are created and are running.