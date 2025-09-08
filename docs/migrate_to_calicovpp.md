# Migrating Calico clusters to CalicoVPP

Calico-VPP nodes are entirely compatible with regular Calico nodes, meaning
that there can be both VPP enabled and regular nodes in the same cluster.
This allows to migrate existing clusters to the VPP dataplane with minimal
disruption.

## Prerequisites

Before attempting a migration to the VPP dataplane, ensure that your cluster
is running the same version of Calico than the version we use in the latest
release of Calico-VPP. The calico version is mentioned in the Calico-VPP
release tag.

## Migrating nodes to the VPP dataplane

Before you get started with the migration, you should define a Calico-VPP
configuration for your cluster. The simplest way to do so in most cases is to
use a [Baremetal configuration](https://docs.tigera.io/calico/latest/getting-started/kubernetes/vpp/getting-started).

The process to deploy VPP on some nodes in a Kubernetes / Calico cluster is
the following:

- Add an annotation to all the nodes in the cluster, such as
`calico-vpp: disabled`
- Edit the `calico-node` DaemonSet to run only on the nodes that have this
annotation:

```yaml
spec:
  nodeSelector:
    beta.kubernetes.io/os: linux
    calico-vpp: disabled
```

- Create the VPP version of the node DaemonSet, and configure its node selector
to select only the nodes with a different annotation, such as
`calico-vpp: enabled`
- Then start migrating the nodes. For each node that you want to deploy VPP on:
  - Remove all the running pods on the node with
  `kubectl drain --ignore-daemonsets <node>`
  - Change the node annotation from `calico-vpp: disabled` to
  `calico-vpp: enabled`
  - Wait for the `calico-vpp-node` pod to start
  - Resume the scheduling of pods to this node with `kubectl uncordon <node>`
  - The new pods that are scheduled on this node will benefit from VPP
  networking. After migrating the first node, validate that the pods scheduled
  on this node are functional before migrating additional nodes.
