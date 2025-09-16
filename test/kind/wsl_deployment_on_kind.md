# Deploy calico/vpp on kind cluster in WSL2 (Windows Subsystem for Linux)

## Enabling virtualization on windows

Check in task manager/performance that virtualization is enabled.
If not, enter bios setup and enable virtualization.

Enter Start menu, type "turn windows features on or off", enable hyper-v.

## Installing and configuring WSL on windows

Install wsl if not yet installed.

Open Powershell as Admin:

````console
Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform, Microsoft-Windows-Subsystem-Linux
````

reboot your computer

Open Powershell as Admin:

````console
wsl --set-default-version 2
wsl --install -d Ubuntu-20.04
````

## Installing docker

Install docker desktop for windows (<https://docs.docker.com/desktop/windows/install/>)
Install choco (<https://chocolatey.org/install#individual>)

````console
choco install kind
````

Make sure docker desktop is running (e.g `docker ps` connects to the daemon socket)

## Installing calico vpp

create this file cluster-config.yml

````yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30000
    hostPort: 30000
    protocol: TCP
````

````console
kind create cluster --config=cluster-config.yml
````

Apply calico-vpp components manifests:

````console
kubectl apply -f https://projectcalico.docs.tigera.io/manifests/tigera-operator.yaml
kubectl apply -f https://raw.githubusercontent.com/projectcalico/vpp-dataplane/v3.23.0/yaml/calico/installation-default.yaml
````

get the calico/vpp deployment yaml

````console
curl -o calico-vpp.yaml https://raw.githubusercontent.com/projectcalico/vpp-dataplane/v3.23.0/yaml/generated/calico-vpp-nohuge.yaml
````

Make necessary changes to `calico-vpp.yaml` configMap depending on cluster,
in kind this should normally be:

````yaml
CALICOVPP_INTERFACE: eth0
SERVICE_PREFIX: 10.96.0.0/16
buffers {
      buffers-per-numa 16384
      page-size 4k
    }
memory {
      main-heap-page-size 4k
    }
````

````console
kubectl apply -f calico-vpp.yaml
````

Check your cluster: `kubectl get pods -A`
