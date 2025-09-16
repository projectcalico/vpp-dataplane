# Install Calico VPP using static Kubernetes manifest

The recommended way to install Calico VPP is using operator. However, it is
also possible to bypass the operator and install Calico VPP using the
Kubernetes manifest directly. To be able to do so, one would need the static
Calico VPP manifest.

Here's how to generate the static Kubernetes manifest:

* Clone the Calico VPP repo and go to the `vpp-dataplane/yaml/static` dir:

````bash
cd vpp-dataplane/yaml/static
````

* Download the appropriate Calico Kubernetes manifest file. For example, to
  install Calico VPP v3.28.0, download the corresponding Calico v3.28.0
  manifest:

````bash
wget https://raw.githubusercontent.com/projectcalico/calico/release-v3.28/manifests/calico.yaml
````

* Copy the appropriate **generated** Calico VPP daemonset yaml and rename it
to `calico-vpp-daemonset.yaml`.
For example, to install Calico VPP v3.28.0 in EKS:

````bash
git checkout release/v3.28.0
cp ../generated/calico-vpp-eks.yaml ./calico-vpp-daemonset.yaml
````

One can also download the same directly:

````bash
wget -O calico-vpp-daemonset.yaml https://raw.githubusercontent.com/projectcalico/vpp-dataplane/release/v3.28.0/yaml/generated/calico-vpp-eks.yaml
````

* Finally, run kustomize:

````bash
kubectl kustomize . > calico-vpp-eks.yaml
````

`calico-vpp-eks.yaml` is the static Kubernetes manifest that can be used to
install Calico VPP in EKS directly.

Having generated the static manifest, one can then customize it per one's
requirements and environment before installing.
Please refer to [Getting Started](https://docs.projectcalico.org/getting-started/kubernetes/vpp/getting-started)
for more information.

**NOTE:** If installing in EKS, add the following to the `calico-node` env
definitions:

````yaml
- name:  FELIX_AWSSRCDSTCHECK
  value: "Disable"
````
