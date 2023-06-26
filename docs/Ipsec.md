This describes how to enable IPSEC on a Calico/VPP cluster

## Enable ipsec on a running cluster

[You can find the documentation here](https://docs.tigera.io/calico/latest/getting-started/kubernetes/vpp/ipsec)

## Using this kustomize component

You can use the following script to build the appropriate manifest for a cluster with ipsec enabled.

```bash
cd $REPOSITORY_ROOT/yaml

cat > kustomization.yaml <<EOF
bases:
  - ./base
components:
  - ./components/ipsec
EOF
kubectl kustomize . > calico-vpp-ipsec.yaml
kubectl apply -f calico-vpp-ipsec.yaml
```

You will also need to create the secret for the PSK out of band

```bash
kubectl -n calico-vpp-dataplane create secret generic calicovpp-ipsec-secret \
   --from-literal=psk="$(dd if=/dev/urandom bs=1 count=36 2>/dev/null | base64)"
```
