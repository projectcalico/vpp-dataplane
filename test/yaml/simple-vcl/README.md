Usage
=====

This describes how to run a simple VCL test application in Calico/VPP.

Enabling VCL
------------

First ensure your calico/vpp cluster is running with VCL enabled
```console
$ kubectl -n calico-vpp-dataplane exec -it calico-vpp-node-<NODEID> -c agent -- env | grep CALICOVPP_ENABLE_VCL
CALICOVPP_ENABLE_VCL=true
```

To produce this output, your calico-vpp.yaml should look like this :
```yaml
metadata:
  name: calico-vpp-node
  namespace: calico-vpp-dataplane
spec:
  template:
    spec:
      containers:
        - name: agent
          env:
            - name: CALICOVPP_ENABLE_VCL
              value: "true"
```

Creating pods
-------------

You can then create the pods

```console
$ kubectl create namespace simple-vcl
$ kubectl apply -f ./test.yaml
```

Once the pods are running you will see something like

```console
kubectl -n simple-vcl get pods -o wide
NAME         READY   STATUS    RESTARTS   AGE   IP             NODE    NOMINATED NODE   READINESS GATES
vcl-client   1/1     Running   0          20s   10.0.104.3     node2   <none>           <none>
vcl-server   1/1     Running   0          20s   10.0.166.130   node1   <none>           <none>
```

To run the test launch a server

```console
$ kubectl -n simple-vcl exec -it vcl-server -- /scratch/server 10.0.166.130 1234
Server IP = 10.0.166.130 Port = 1234
Creating VCL app....
Creating VCL session...
Bind...
Listen...
```

And a client
```console
$ kubectl -n simple-vcl exec -it vcl-client -- /scratch/client  10.0.166.130 1234
server ip = 10.0.166.130 port = 1234

Creating VCL app...
Creating VCL session...
Connecting to server...
Sending data to server: Hello there!

Server replied with: Hello there!
```

That's it !

