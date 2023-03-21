#!/bin/bash
set -o errexit

# create registry container unless it already exists
reg_name='kind-registry'
reg_port='5000'
if [ "$(docker inspect -f '{{.State.Running}}' "${reg_name}" 2>/dev/null || true)" != 'true' ]; then
  docker run \
    -d --restart=always -p "127.0.0.1:${reg_port}:5000" --name "${reg_name}" \
    registry:2
fi

# create a cluster with the local registry enabled in containerd
config=$(cat <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${reg_port}"]
    endpoint = ["http://${reg_name}:5000"]
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
    endpoint = ["http://${reg_name}:5000"]
   
networking:
  disableDefaultCNI: true
  podSubnet: "11.0.0.0/16,fd20::0/64"
  serviceSubnet: "11.96.0.0/12,fd10::0/120"
  ipFamily: dual
nodes:
EOF
)

if [ "$N_KIND_CONTROL_PLANES" == "" ]; then
	echo "Please Set N_KIND_CONTROL_PLANES"
	exit 1
fi

if [ "$N_KIND_WORKERS" == "" ]; then
	echo "Please Set N_KIND_WORKERS"
	exit 1
fi

FIRST_CPU=3
for ((i=1; i<=$N_KIND_CONTROL_PLANES; i++)); do \
config=$(cat <<EOF
$config
- role: control-plane
  extraMounts:
    - hostPath: $HOME
      containerPath: $HOME
  cpuSet: "$(($N_KIND_WORKERS+$FIRST_CPU+1+i)),$(($N_KIND_WORKERS+$FIRST_CPU+2-2*(i%2)+i))"
EOF
);\
done

for ((i=1; i<=$N_KIND_WORKERS; i++)); do \
config=$(cat <<EOF
$config
- role: worker
  extraMounts:
    - hostPath: $HOME
      containerPath: $HOME
  cpuSet: "$((i+$FIRST_CPU)),$((i+$FIRST_CPU+(1-2*(i%2))))"
EOF
);\
done

echo -e "$config" | kind create cluster --config=-

# connect the registry to the cluster network if not already connected
if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${reg_name}")" = 'null' ]; then
  docker network connect "kind" "${reg_name}"
fi

# Document the local registry
# https://github.com/kubernetes/enhancements/tree/master/keps/sig-cluster-lifecycle/generic/1755-communicating-a-local-registry
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${reg_port}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF
