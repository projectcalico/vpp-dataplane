# Envoy VCL/linux testing

This is a simple toy setup for running envoy within VPP attached with the VCL

This testing was done in a single node cluster, with `20.0.0.1/24` being
the node
address, connected to another node with `20.0.0.2/24`

Envoy is configured in both cases to listen on `podID:10001` and proxy
to `20.0.0.2:80`
Service addresses are also configured

In order for this to work, we need to remove sNAT (either globally, or just
for our peer address)

````console
set cnat snat-policy prefix 20.0.0.2/32
````

Then create two envoy pods (with and without VCL)

````bash
test.sh up envoy
````

To start envoy

````bash
# with VCL
kubectl exec -it -n envoy envoy-vcl -- taskset -c 0-3 \
 envoy -c /etc/envoy/envoyvcl.yaml --concurrency 4
# with linux
kubectl exec -it -n envoy envoy-linux -- taskset -c 0-3 \
 envoy -c /etc/envoy/envoy.yaml --concurrency 4
````
