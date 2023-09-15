## Introduction

Calico/Vpp is the integration of Vector Packet Processing ([VPP](https://fd.io)) as a Calico dataplane. It focuses on improving network performance for applications, but also on extending network features. We introduce one of these features in this document, allowing pods to attach to multiple networks, or in short: “Multinet”.

## Multinet overview

In Kubernetes, networking does not come with many requirements. It only mandates reachability between pods in a cluster.
However in some use cases, more complex connectivity features are needed. Some applications require isolated networks for handling different types of traffic. Others may need high performance interfaces, but only for specific classes of traffic.
The current Kubernetes approach to those requirements only offers a partial solution. As an example, multus allows the creation of additional interfaces in isolated networks, but outside of kubernetes’ knowledge, leaving the routing, load-balancing and policies implementation to the user.

Calico/Vpp Multinet implementation is an attempt at fulfilling these requirements. Essentially, it allows creating several isolated kubernetes networks to which pods can attach, and it exposes the usual kubernetes abstractions (services & policies) in each of them.


## Implementation details

### Network object

With Calico/Vpp Multinet, we introduce a new Kubernetes resource (as a CRD), called `Network`. A `Network` is defined by a `vni` (Virtual Network Identifier) which allows to identify the network in the dataplane.
It also contains a CIDR `range` that defines the IP addresses to assign to that network's pods. This optionally allows defining overlapping IP ranges for the different networks, provided the other selected components (ipam, etc…) allow this.

```yaml
apiVersion: projectcalico.org/v3
kind: Network
metadata:
  name: blue
spec:
  vni: 56
  range: "172.19.0.0/16"
```

When a network is created, the `NetWatcher` component in the Calico/Vpp agent, will create a dedicated VRF in VPP to isolate the network’s routes.

### Attaching pods

In order to associate Pods to Network, we leverage [Multus](https://github.com/k8snetworkplumbingwg/multus-cni). Multus is a CNI plugin that enables attaching multiple network interfaces to pods. It will do the multiplexing we need, calling the Calico CNI once per attachment.
A `network attachment definition` object has to be created for each network with a matching name, to give multus knowledge of the existing networks.

```yaml
apiVersion: "k8s.cni.cncf.io/v1"
kind: NetworkAttachmentDefinition
metadata:
  name: network-blue-conf
spec:
  config: |-
    {
      "name": "network-blue",
      "plugins": [
        {
          "type": "calico",
          "ipam": {
            "type": "whereabouts",
          }
          …
          "dataplane_options": {
            "network_name": "blue"
          }
        }
      ]
    }
```

The IPAM that we use to assign addresses to pods in secondary networks is [Whereabouts](https://github.com/k8snetworkplumbingwg/whereabouts). We opted for this IPAM as it is a lightweight solution allowing allocating addresses, with a synchronization mechanism across nodes,  out of several potentially overlapping pools.

Pods are attached to networks with annotations using [the multus syntax](https://github.com/k8snetworkplumbingwg/multus-cni/blob/master/docs/quickstart.md#creating-a-pod-that-attaches-an-additional-interface). A pod can be attached to several networks, and it can have more than one interface in a network, in addition to its main interface in the default Kubernetes network.

In this annotation, we specify the name of the network attachment definition, as well as, optionally, the name we would like to give to the interface.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: samplepod
  annotations:
    k8s.v1.cni.cncf.io/networks: network-blue-conf@eth1, network-red-conf@eth2
spec:
  containers:
  ...
```

### Connectivity

Let us consider as an example that we create two “blue” and “red” networks.
A pod that has an interface in the blue network can communicate with other pods attached to that network. However, interfaces of different networks cannot communicate between each other, i.e. a pod cannot ping a red interface from a blue one.

On the dataplane front:
- Blue interfaces all belong to the same blue VRF, and are thus isolated from the red VRF.
- When going from node to node, we need to carry the VRF color along with the packet. In the current implementation we have chosen to create a vxlan tunnel between  each couple of nodes, carrying the network VNI as the VXLAN VNI.

We are currently working on exposing a way to customize the encapsulation used to carry the network VNI between nodes. See `Active developments`

![multinet_connectivity](_static/multinet_connectivity.png?raw=true "Title")

### Memif

When we create a secondary interface for a pod, we can give it a name starting with `memif`, in this case, a memory interface will be created in VPP for that pod in that network. Memif is a very high-performance interface in VPP relying on a shared memory segment to optimize raw packet speed.
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: samplepod
  annotations:
    k8s.v1.cni.cncf.io/networks: network-blue-conf@memif-eth1
```

This is ideal for packet processing workloads as memif interfaces scale to much higher pps than the kernel interfaces.

## Integration with Kubernetes constructs

### Multinet services

Services in Kubernetes are an abstract way of load-balancing traffic across a set of  pods. In Calico/Vpp multinet, we expose network-aware services, i.e. services that load-balance across a set of pods interfaces in that network.
For example, if a service has a network annotation "blue", its endpoints are selected among the pods that match its selector AND have interfaces in that specific network "blue". Thus, this service is accessible only from blue interfaces, due to isolation.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
  annotations:
    extensions.projectcalico.org/selector: "app=MyApp"
    extensions.projectcalico.org/network: "blue"
spec:
  ports:
  - protocol: TCP
    port: 80
    targetPort: 9376
```

![Multinet service](_static/multinet_service.png?raw=true "Title")


### Multinet policies

Calico network policies are used in addition to Kubernetes network policies, they can be applied to several kinds of endpoints, including pods and containers.
Calico/VPP multinet offers the opportunity to attach policies to specific networks, and thus, have them applied only on that network's interfaces.
We leverage annotations as well, by associating policy rules to networks. When a policy matches a pod via its label selector, each one if its rules is applied to interfaces of that pod that are in the same network.

```yaml
apiVersion: crd.projectcalico.org/v1
kind: NetworkPolicy
metadata:
  name: my-policy
spec:
  selector: demo == 'demo'
  ingress:
  - action: Allow
    protocol: TCP
    destination:
      ports:
      - 3434
  - action: Allow
    protocol: TCP
    metadata:
      annotations:
        extensions.projectcalico.org/network: "red"
  destination:
    ports:
    - 7809
```

Here is a link to a demo starring all these features.

[![Demo](_static/demobutton.png?raw=true "Title")](https://asciinema.org/a/htzzaP4WUhPrOYirUJEkNokU7)


## Active developments

This feature is still a work in progress. Here are a list of the topics we are actively focusing on :
- The encapsulation used for carrying the network identifier (VNI) between nodes defaults to VxLan, and expects the nodes to be connected with a single interface. We would like to give more flexibility to the cluster administrator here by making this part of the network specification.
- We would like to allow the BGP peering of multiple networks, with exported routes carrying the network identifier (VNI) they belong to.
- The resulting ip and route configuration in the pod needs some refinement as well :
  - Is there a default route, and if yes to which network ? Right now we kept the original behavior with a default route pointing to the default network.
  - How are serviceIPs routed within the pods ? The same question applies for DNS & service resolution in case the configurations differ between networks.
  - What is the pod’s resulting configuration when attaching to networks with overlapping addresses.

## Testing multinet feature

### Installing dependencies
#### Installing network CRD

````yaml
kubectl apply -f test/yaml/multinet/projectcalico.org_networks.yaml
kubectl apply -f test/yaml/multinet/whereabouts-daemonset-install.yaml
````

#### Installing multus deamonset

````yaml
kubectl apply -f https://github.com/k8snetworkplumbingwg/multus-cni/raw/99c4481e08a4a8f0a3d0013446f03e4206033cae/deployments/multus-daemonset-thick.yml
kubectl apply -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_ippools.yaml
kubectl apply -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_overlappingrangeipreservations.yaml
````

### Enabling multinet

Install calicovpp as mentioned in https://projectcalico.docs.tigera.io/getting-started/kubernetes/vpp/getting-started

But use the manifest from `yaml/generated/calico-vpp-multinet.yaml` for installation.

NOTE: if whereabouts is installed after calico/vpp is already installed, restart calicovpp in order to patch whereabouts.

### Testing

````yaml
kubectl apply -f test/yaml/multinet/network.yaml
kubectl apply -f test/yaml/multinet/netdefinitions.yaml
kubectl apply -f test/yaml/multinet/pod-memif.yaml
````

Make sure pods are created and are running.
