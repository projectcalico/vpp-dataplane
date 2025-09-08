# Testing Calico/VPP on baremetal

This setup creates a single node setup leveraging DPDK.

- ⚠️ This is a test script, not to be used for production
- ⚠️ It will reconfigure the uplink interface, here `enp216s0f1` do not use
your management interface or you will most probably loose access to your server.

## Install kubernetes

````bash
sudo apt update
sudo apt install kubelet kubeadm kubectl containerd
````

## Preparing the cluster

````bash
sudo sysctl -w vm.nr_hugepages=4096
sudo swapoff -a
# Load PCI drivers, often but not always required
sudo modprobe uio_pci_generic
sudo modprobe vfio-pci
# Reset previous installations
sudo kubeadm reset -f
sudo rm -rf /etc/cni/net.d/
````

````bash
echo "
K8_VERSION=v1.31.0
POD_CIDR=11.0.0.0/16
SERVICE_CIDR=11.96.0.0/16
MAIN_IP=20.0.0.1/24
MAIN_INTERFACE_NAME=enp216s0f1
DNS_TYPE=CoreDNS
VERBOSE=false
" > v4.1node.conf
$HOME/vpp-dataplane/test/scripts/vppdev.sh orch up
````

## Install the tigera operator

````bash
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/master/manifests/tigera-operator.yaml
````

## Install Calico/VPP

````bash
# ---------------- images ----------------
export CALICO_AGENT_IMAGE=calicovpp/agent:v3.26.0
export CALICO_VPP_IMAGE=calicovpp/vpp:v3.26.0
export MULTINET_MONITOR_IMAGE=calicovpp/multinet-monitor:v3.26.0
export IMAGE_PULL_POLICY=IfNotPresent

# ---------------- interfaces ----------------
export CALICOVPP_INTERFACES='{
  "uplinkInterfaces": [
    {
      "interfaceName": "enp216s0f1",
      "vppDriver": "dpdk"
    }
  ]
}'

export CALICOVPP_ENABLE_MEMIF=true
export CALICOVPP_ENABLE_VCL=true
export CALICO_ENCAPSULATION=IPIP # VXLAN IPIP None
export CALICO_NAT_OUTGOING=Enabled

export CALICOVPP_CONFIG_TEMPLATE="unix {
  nodaemon
  full-coredump
  log /var/run/vpp/vpp.log
  cli-listen /var/run/vpp/cli.sock
  pidfile /run/vpp/vpp.pid
}
cpu {
  main-core 1
  workers 0
}
api-trace { on }
session { event-queue-length 100000 }
socksvr { socket-name /var/run/vpp/vpp-api.sock }
buffers { buffers-per-numa 131072 }
cnat {
  translation-db-memory 50M
  translation-db-buckets 1024
  session-db-memory 20G
  session-db-buckets 4096
  snat-db-memory 1M
  snat-db-buckets 1024
  session-cleanup-timeout 0.1
}
plugins {
    plugin default { enable }
    plugin calico_plugin.so { enable }
    plugin dpdk_plugin.so { disable }
}
"
$HOME/vpp-dataplane/yaml/overlays/dev/kustomize.sh up
