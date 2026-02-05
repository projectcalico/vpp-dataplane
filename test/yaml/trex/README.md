Usage
=====

Deploy the yaml

````console
kubectl create namespace trex
kubectl apply -f test.yaml
````

Start trex

The mac address given by vpp to the memif should be configured on trex

````bash
NODE=$(kubectl -n trex get pod trex -o jsonpath='{.spec.nodeName}'); \
VPP_POD=$(kubectl -n calico-vpp-dataplane get pod -o \
jsonpath="{.items[?(@.spec.nodeName==\"$NODE\")].metadata.name}"); \
MAC_ADDR=$(k -n calico-vpp-dataplane exec $VPP_POD -c vpp -- vppctl\
 sh hard|grep memi -A 3|grep Ether|awk '{print $3}'); \
echo $MAC_ADDR
kubectl exec -it -n trex trex -- bash -c "sed -i 's/dest_mac: .*/\
dest_mac: $MAC_ADDR/g' /usr/local/bin/trex-start"
````

````console
kubectl exec -it -n trex trex -- bash
$ trex-start
# Ctrl-C to quit
````

Start the console

````console
kubectl exec -it -n trex trex -- bash
$ DST_ADDRESS=1.2.3.4 DST_PORT=4444 trex-console
````

In the console, start the packet generation

````console
$ trex-console
# (q) to quit
$ start -f /trex-scripts/trex.py -p 0 -m 10mbps
## To show stats (use q to quit)
$ tui
## To update to full speed
$ update -m 100%
## To stop traffic generation
$ stop -a
````
