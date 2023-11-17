Usage
=====

Deploy the yaml

```shell
kubectl create namespace testpmd
kubectl apply -f test.yaml
```

Start testpmd (4-6 being the CPU range on which to run testpmd)
```shell
kubectl -n testpmd exec -it testpmd memif-testpmd 4-6
```

The annotation in the yaml specification of the pod specifies that
packets to the PodIP destined to ports between 4444 and 20000 for
both TCP and UDP will be sent to the memif, and end up in testpmd.
```yaml
  annotations:
    "cni.projectcalico.org/vppExtraMemifPorts": "tcp:4444-20000,udp:4444-20000"
```

Testpmd is started in 5tuple swap mode, meaning it will mirror all the packets
it receives. In order to test it, either send a single TCP packet, e.g.
`curl http://<testPmdPodIP>:4444` from another container or a cluster node.

Alternatively you can also use a traffic generator like trex (see the corresponding 
yaml under [../trex](../trex))




