# Services features

Services in calicovpp support different load balancing types, and can use
specific fields in hash calculation for load balancing.

This is implemented using service annotations, here is an example:

````yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
  annotations:
    "cni.projectcalico.org/vppLBType": "maglev"
    "cni.projectcalico.org/vppHashConfig": "symmetric, iproto, dstport, srcport"
````

* Possible values for `vppLBType` are `ecmp`, `maglev`, `maglevdsr`
`maglev` implements consistent hashing for better redundancy and scalability.
`maglebdsr` offers Direct Server Return to accelerate server response times.
* `vppHashConfig` is a list of elements from
`srcport, dstport, srcaddr, dstaddr, iproto, reverse, symmetric`, that the
forwarding of packets is based on.

## SRv6-native (NAT-less) ClusterIP services

When SRv6 is enabled, a ClusterIP service can be served over SRv6 steering with
Direct Server Return instead of the cnat DNAT/un-DNAT path. The VIP is not
translated: the client packet is steered to a backend node over an SRv6 policy,
the backend pod binds the VIP and replies with it as source, so no reverse
translation is needed and the client source address is preserved across nodes.

This is opt-in and coexists with cnat. It requires:

* the `srv6NativeServicesEnabled` feature gate
  (see [config](../config/README.md)), and
* the annotation below on the service.

````yaml
apiVersion: v1
kind: Service
metadata:
  name: my-service
  annotations:
    "cni.projectcalico.org/vppSRv6Native": "true"
````

Eligibility (first cut): pod-backed ClusterIP with `port == targetPort`. Services
that are not eligible (host-backed, port remap, ExternalIP/LoadBalancer) keep the
cnat path. This is distinct from the `maglevdsr` `vppLBType` above, which is a
cnat load-balancing mode rather than SRv6-native steering.

For troubleshooting, please consult [troubleshooting.md]
