This document summarizes a testbed for bgp filters, using a node external to calicoVPP KinD cluster, in the same docker bridge network. The external node peers with the cluster nodes and filters are included.

create the external node in the kind cluster network, and install gobgp:
```yaml
docker run -d --name my-ubuntu-container --network kind -it ubuntu sleep infinity
docker exec my-ubuntu-container apt update
docker exec my-ubuntu-container apt install golang -y
wget https://github.com/osrg/gobgp/releases/download/v3.14.0/gobgp_3.14.0_linux_amd64.tar.gz
docker cp gobgp_3.14.0_linux_amd64.tar.gz my-ubuntu-container:/
docker exec my-ubuntu-container tar -xf gobgp_3.14.0_linux_amd64.tar.gz
```
use the same as number as the cluster nodes peering, and the external node address as a router-id, and add every node as a neighbor:

```yaml
echo "
[global.config]
  as = 64512
  router-id = '172.18.0.7'
  local-address-list = ['172.18.0.7']
  port = 179

[[neighbors]]
  [neighbors.config]
    neighbor-address = '172.18.0.4'
    peer-as = 64512

[[neighbors]]
  [neighbors.config]
    neighbor-address = '172.18.0.3'
    peer-as = 64512

[[neighbors]]
  [neighbors.config]
    neighbor-address = '172.18.0.2'
    peer-as = 64512

[[neighbors]]
  [neighbors.config]
    neighbor-address = '172.18.0.5'
    peer-as = 64512

" > ./gobgp.conf

docker cp gobgp.conf my-ubuntu-container:/

docker exec -d  my-ubuntu-container  ./gobgpd -f ./gobgp.conf &  >/dev/null 2>&1

docker exec my-ubuntu-container ./gobgp -u 172.18.0.7 global rib add 1.2.3.4/32 nexthop 172.18.0.7
```
add a route to test advertisement and filtering
```yaml
./gobgp -u 172.18.0.7 global rib add 1.2.3.4/32 nexthop 172.18.0.7
```
