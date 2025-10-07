#!/bin/bash
set -o errexit

N_KIND_CONTROL_PLANES=${N_KIND_CONTROL_PLANES:-1}
N_KIND_WORKERS=${N_KIND_WORKERS:-2}
IPFAMILY=${IPFAMILY:-dual}

KIND_REGISTRY_NAME=${KIND_REGISTRY_NAME:-kind-registry}
KIND_REGISTRY_PORT=${KIND_REGISTRY_PORT:-5000}

CPU_PINNING=${CPU_PINNING:-false}
FIRST_CPU=${FIRST_CPU:-3}

VERBOSE=${VERBOSE:-false}
NO_TAINT=${NO_TAINT:-false}

if [ "${VERBOSE}" == "true" ]; then
set -x
cat /proc/sys/fs/inotify/max_user_instances
cat /proc/sys/fs/inotify/max_user_watches
cat /proc/sys/vm/nr_hugepages
go version
fi

if [[ $(${KIND} get clusters | grep -E '^'"${CLUSTER_NAME}"'$') == "${CLUSTER_NAME}" ]]; then
	echo "Cluster kind already exists"
	exit 0
fi

# create registry container unless it already exists
if [ "$(docker inspect -f '{{.State.Running}}' "${KIND_REGISTRY_NAME}" 2>/dev/null || true)" != 'true' ]; then
  docker run \
    -d --restart=always -p "127.0.0.1:${KIND_REGISTRY_PORT}:5000" --name "${KIND_REGISTRY_NAME}" \
    registry:2
fi

# create a cluster with the local registry enabled in containerd
config=$(cat <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${CLUSTER_NAME}
containerdConfigPatches:
- |-
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."localhost:${KIND_REGISTRY_PORT}"]
    endpoint = ["http://${KIND_REGISTRY_NAME}:5000"]
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
    endpoint = ["http://${KIND_REGISTRY_NAME}:5000"]
EOF
)

if [ "${IPFAMILY}" == "v4" ]; then
config=$(cat <<EOF
$config
networking:
  disableDefaultCNI: true
  podSubnet: "11.0.0.0/16"
  serviceSubnet: "11.96.0.0/12"
  ipFamily: ipv4
nodes:
EOF
)
elif [ "${IPFAMILY}" == "v6" ]; then
config=$(cat <<EOF
$config
networking:
  disableDefaultCNI: true
  podSubnet: "fd20::0/64"
  serviceSubnet: "fd10::0/120"
  ipFamily: ipv6
nodes:
EOF
)
else
config=$(cat <<EOF
$config
networking:
  disableDefaultCNI: true
  podSubnet: "11.0.0.0/16,fd20::0/64"
  serviceSubnet: "11.96.0.0/12,fd10::0/120"
  ipFamily: dual
nodes:
EOF
)
fi

for ((i=1; i<=N_KIND_CONTROL_PLANES; i++)); do \
config=$(cat <<EOF
$config
- role: control-plane
  extraMounts:
    - hostPath: $HOME
      containerPath: $HOME
EOF
);
if [ "${CPU_PINNING}" == "true" ]; then
config=$(cat <<EOF
$config
  cpuSet: "$((N_KIND_WORKERS+FIRST_CPU+1+i)),$((N_KIND_WORKERS+FIRST_CPU+2-2*(i%2)+i))"
EOF
);\
fi
done
# use cpuSet in the case of a patched kind version like in scale tests (test/scale/README.md)

for ((i=1; i<=N_KIND_WORKERS; i++)); do \
config=$(cat <<EOF
$config
- role: worker
  extraMounts:
    - hostPath: $HOME
      containerPath: $HOME
EOF
);
if [ "${CPU_PINNING}" == "true" ]; then
config=$(cat <<EOF
$config
  cpuSet: "$((N_KIND_WORKERS+FIRST_CPU+1+i)),$((N_KIND_WORKERS+FIRST_CPU+2-2*(i%2)+i))"
EOF
);\
fi
done
# use cpuSet in the case of a patched kind version like in scale tests (test/scale/README.md)

echo -e "$config" | ${KIND} create cluster --config=-

# connect the registry to the cluster network if not already connected
if [ "$(docker inspect -f='{{json .NetworkSettings.Networks.kind}}' "${KIND_REGISTRY_NAME}")" = 'null' ]; then
  docker network connect "kind" "${KIND_REGISTRY_NAME}"
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
    host: "localhost:${KIND_REGISTRY_PORT}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF


if [ "${NO_TAINT}" == "true" ]; then
kubectl taint nodes --all node-role.kubernetes.io/control-plane- || true
fi
