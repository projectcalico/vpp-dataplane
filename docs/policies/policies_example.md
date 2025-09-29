# Policy usage example

Calico enriches Kubernetes set of policies allowing to have ordering in
policies, deny rules, policies applied to host interfaces, more flexible
match rules. In CalicoVPP, we feed Felix messages to our policy server
(agent component), which then configures VPP to create those policies.

## Network Policy (npol) Plugin

We use the vpp npol plugin (network policies) to implement the calico policies.

### Overview

The **Network Policy (npol)** plugin provides a programmable policy engine
for applying packet filtering and forwarding rules in VPP.
It allows you to:

- Create and manage **IP sets** (collections of IPs, subnets, or IP:port
entries).
- Define **rules** to allow, deny, or log traffic based on IPs, prefixes, sets,
ports, and direction.
- Build **policies** from rules and apply them on interfaces in RX (inbound)
and TX (outbound) directions.

### Quick Start

This example shows how to configure and apply a network policy on a loopback interface.

#### Create a loopback interface and configure an IP address

````bash
$ calicovppctl vppctl -node worker-1 create loopback interface
loop0
$ calicovppctl vppctl -node worker-1 set interface state loop0 up
$ calicovppctl vppctl -node worker-1 set interface ip address loop0 10.0.0.1/32
$ calicovppctl vppctl -node worker-1 sh int addr
local0 (dn):
loop0 (up):
 L3 10.0.0.1/32
````

#### Explore npol commands

````bash
$ calicovppctl vppctl -node worker-1 npol ?
npol interface clear      npol interface clear [interface | sw_if_index N]
npol interface configure  npol interface configure [interface |
                          sw_if_index N] rx <num_rx> tx <num_tx>
                           <policy_id> ...
npol ipset add member     npol ipset add member [id] [prefix]
npol ipset add            npol ipset add [prefix|proto ip port|ip]
npol ipset del member     npol ipset del member [id] [prefix]
npol ipset del            npol ipset del [id]
npol policy add           npol policy add [rx rule_id rule_id ...]
                          [tx rule_id rule_id ...] [update [id]]
npol policy del           npol policy del [id]
npol rule add             npol rule add [ip4|ip6] [allow|deny|log|pass]
                          [filter[==|!=]value][[src|dst][==|!=]
                          [prefix|set ID|[port-port]]]
npol rule del             npol rule del [id]
````

#### Create an IP set

````bash
$ calicovppctl vppctl -node worker-1 npol ipset add 20.0.0.0/24
npol ipset 0 added
$ calicovppctl vppctl -node worker-1 sh npol ipsets
[ipset#0;prefix;20.0.0.0/24,]
````

#### Add rules

- Rule 0: Deny packets with a source IP in the created set.
- Rule 1: Allow all other packets.

````bash
$ calicovppctl vppctl -node worker-1 npol rule add ip4 deny src==set0
   npol rule 0 added
$ calicovppctl vppctl -node worker-1 npol rule add ip4 allow
   npol rule 1 added
$ calicovppctl vppctl -node worker-1 sh npol rules
   [rule#0;deny][src==[ipset#0;prefix;20.0.0.0/24,],]
   [rule#1;allow][]
````

#### Create a policy

This policy applies Rule 0 and Rule 1 on RX,
and Rule 1 on TX.

````bash
$ calicovppctl vppctl -node worker-1 npol policy add rx 0 1 tx 1
npol policy 0 added
$ calicovppctl vppctl -node worker-1 sh npol policies verbose
[policy#0]
 tx:[rule#1;allow][]
 rx:[rule#0;deny][src==[ipset#0;prefix;20.0.0.0/24,],]
 rx:[rule#1;allow][]
````

#### Apply the policy to an interface

````bash
$ calicovppctl vppctl -node worker-1 npol interface configure loop0 0
npol interface 1 configured
$ calicovppctl vppctl -node worker-1 sh npol interfaces
Interfaces with policies configured:
[loop0 sw_if_index=1  addr=10.0.0.1]
  rx-policy-default:1 rx-profile-default:1
  tx-policy-default:1 tx-profile-default:1
 profiles:
   [policy#0]
     tx:[rule#1;allow][]
     rx:[rule#0;deny][src==[ipset#0;prefix;20.0.0.0/24,],]
     rx:[rule#1;allow][]
````

### Summary

- **IP sets** define groups of IPs, prefixes, or IP:port pairs.
- **Rules** define match conditions and actions (allow, deny, log, pass).
- **Policies** group rules per direction (RX/TX).
- **Interfaces** are configured with policies, enforcing filtering in the
datapath.

This modular design allows fine-grained policy enforcement
directly in VPP with efficient data structures.

## Troubleshooting policies

VPP cli allows to look at policies in details, here are the commands for that

````bash
$ calicovppctl vppctl -node worker-1
    _______    _        _   _____  ___ 
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/    

vpp# sh npol ?
  show npol interfaces                     show npol interfaces
  show npol ipsets                         show npol ipsets
  show npol policies                       show npol policies [verbose]
  show npol rules                          show npol rules
````

Basically, `sh npol interfaces` shows everything related to policies and
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
sh npol interfaces
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
sh npol interfaces
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
