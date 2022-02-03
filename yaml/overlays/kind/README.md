# Kind cluster setup

```
kind create cluster --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "192.168.0.0/16,fd20::0/64"
  ipFamily: dual
nodes:
- role: control-plane
- role: worker
- role: worker
EOF

kubectl apply -f yaml/generated/calico-vpp-kind.yaml
```
