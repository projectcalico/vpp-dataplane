## Introduction

Calico/Vpp is an integration of Vector Packet Processing user space network dataplane in Calico, which is a CNI provider for Kubernetes cluster deployments. It allows to enrich the cluster with several features as opposed to other dataplanes for Calico. We introduce one of these features in this document: Multinet.

## Multinet overview

In Kuberenetes, networking is easy to achieve, and as long as we have connectivity between pods in our cluster, most customers' requirements are met.
However, in some use cases, more complex connectivity features are needed, depending on the specificities of applications we run in our cluster. We may require for example to have isolated networks for handling specific traffic, or we may need high performance interfaces for dedicated applications.
Current Kubernetes implementation does not offer such properties at the level of pod specification.
All pods in the cluster communicate in their initial unique "default" network provided during cluster creation.
Calico/Vpp Multinet feature comes to fulfill these requirements.
Multinet in Calico/VPP consists of having a number of networks in which pods can have their own interfaces and communicate between each other inside the network. Different networks are isolated from each other. Types of interfaces offered by VPP can be used in those networks to meet traffic needs.

## Implementation details

### Network object

With Calico/Vpp Multinet, we introduce a new Kubernetes resource, called `Network`. A `Network` is defined by a `vni` (Virtual Network Identifier) which is the value that will allow to identify the network in the dataplane. 
It is also defined by a CIDR `range` that will help determine the IP addresses to assign to that network's pods, which will raise the question about overlapping ranges networks...

```yaml
apiVersion: projectcalico.org/v3
kind: Network
metadata:
  name: blue
spec:
  vni: 56
  range: "172.19.0.0/16"
```

When a network is created, a server in Calico/Vpp agent, called `NetWatcher`, creates a dedicated VRF in VPP. In fact, this will permit to isolate routes. 

### Attaching pods

We have `Multus` running in our cluster: Multus CNI is a Container Network Interface (CNI) plugin for Kubernetes that enables attaching multiple network interfaces to pods.
A network attachment definition object is created per network, to allow multus to attach pods to the desired network.
The IPAM (IP Address Management) plugin that we use to assign addresses to pods in secondary networks is `Whereabouts`. We opted for this IPAM as it allows to work accross all the nodes in the cluster and to assign unique addresses for our interfaces.

When pods are created, they are attached to existing networks via annotations. A pod can actually be attached to several networks, and it can have more than one interface in a network, other than its main interface in the default Kubernetes network.

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

Let us consider as an example that we create blue and red networks.
A pod that has an interface in blue network can communicate with other pods inside that network and it has a route towards blue. However, interfaces of different networks cannot communicate between each other, i.e. a red interface cannot ping a blue one.

On the dataplane front, blue interfaces all have a route to the same blue VRF, and are isolated from the red VRF. As for node-to-node communication, a vxlan tunnel is created between blue VRFs of every couple of different nodes, using blue network VNI, to allow communication.

![Alt text](img/multinet/multinet_connectivity.png?raw=true "Title")

### Memif

When we create a secondary interface for a pod, we can give it a name starting with `memif`, in this case, a memory interface is created in VPP for that pod in that network. Memif is a very high-performance interface in VPP that shares a memory segment to empower packet transmission and reception. On the Linux side, a dummy interface is created to attach our memif.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: samplepod
  annotations:
    k8s.v1.cni.cncf.io/networks: network-blue-conf@memif-eth1
```

## Additional features

### Services

Services in Kubernetes are an abstract way of exposing an application running on some pods. In Calico/Vpp multinet, we can have a network specific service, i.e. a service that exposes a set of pods having interfaces in that network.
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

![Alt text](img/multinet/multinet_service.png?raw=true "Title")

### Policies

Calico network policies are used in addition to Kubernetes network policies, they can be applied to several kinds of endpoints, including pods and containers. 
Calico/VPP multinet offers the opportunity to attach some policies to specific networks, and thus, have them applied only on that network's interfaces.
We leverage annotations as usual, by associating policy rules to networks. When a policy matches a pod via its label selector, each one if its rules is applied to interfaces of that pod that are in the same network.

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

Here is a link to a [DEMO](https://asciinema.org/a/htzzaP4WUhPrOYirUJEkNokU7) starring all theses features.