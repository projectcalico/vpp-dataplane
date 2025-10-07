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

For troubleshooting, please consult [troubleshooting.md]
