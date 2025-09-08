# Policies in CalicoVPP

Calico enriches Kubernetes set of policies allowing to have ordering in
policies, deny rules, policies applied to host interfaces, more flexible
match rules. In CalicoVPP, we feed Felix messages to our policy server
(agent component), which then configures VPP to create those policies.

## Troubleshooting policies

VPP cli allows to look at policies in details, here are the commands for that

````bash
    _______    _        _   _____  ___ 
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/    

vpp# sh capo ?
  show capo interfaces                     show capo interfaces
  show capo ipsets                         show capo ipsets
  show capo policies                       show capo policies [verbose]
  show capo rules                          show capo rules
````

Basically, `sh capo interfaces` shows everything related to policies and
where they are applied.

### Example

Let's create two pods:

````bash
apiVersion: v1
kind: Pod
metadata:
  labels:
    role: sender
  name: ts1
spec:
  containers:
    - name: pod
      image: nicolaka/netshoot
      command: ["tail", "-f", "/dev/null"]
---
apiVersion: v1
kind: Pod
metadata:
  labels:
    role: receiver
  name: ts2
spec:
  containers:
    - name: pod
      image: nicolaka/netshoot
      command: ["tail", "-f", "/dev/null"]
````

Here are our pods

````bash
NAME   READY   STATUS    RESTARTS   AGE     IP           NODE
ts1    1/1     Running   0          3m41s   11.0.0.196   kind-worker3
ts2    1/1     Running   0          3m41s   11.0.0.67    kind-worker2
````

If we check ts2 interface we only have the usual allow policies:

````bash
sh capo interfaces
...
[tun3 sw_if_index=11  addr=11.0.0.67 addr6=fd20::1cc0:b1ac:ad47:e7c2]
  profiles:
    [policy#10]
      tx:[rule#15;allow][]
      rx:[rule#16;allow][]
    [policy#11]
````

Let's create this policy:

````bash
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: test-network-policy
spec:
  podSelector:
    matchLabels:
      role: receiver
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              role: sender
      ports:
        - protocol: TCP
          port: 5978
````

And recheck interfaces policies

````bash
sh capo interfaces
...
[tun3 sw_if_index=11  addr=11.0.0.67 addr6=fd20::1cc0:b1ac:ad47:e7c2]
  tx:
    [policy#2]
      tx:[rule#0;allow][src==172.18.0.2/32,src==fc00:f853:ccd:e793::2/128,]
    [policy#12]
      tx:[rule#18;allow][proto==TCP,dst==5978,src==[ipset#1;prefix;11.0.0.196/32,fd20::58fd:b191:5c13:9cc3/128,],]
  profiles:
    [policy#10]
      tx:[rule#15;allow][]
      rx:[rule#16;allow][]
    [policy#11]
````

We see that a rule (rule#18 in policy#12) allowing tcp connections from the
sender pod on 5978 port is added.
Note: policy#2 is added automatically, it is a failsafe policy allowing
traffic from host to its own pods.
We conduct a test using netcat, it shows that this port accepts connections,
unlike other ports.

## More resources

Other resources can be leveraged to add policies and troubleshooting is the same.
For reference: [hostendpoint](https://docs.tigera.io/calico/latest/reference/resources/hostendpoint),
[globalNetworkPolicy](https://docs.tigera.io/calico/latest/reference/resources/globalnetworkpolicy).
