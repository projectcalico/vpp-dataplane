# Troubleshooting CalicoVPP services

CalicoVPP services are implemented in a plugin called cnat
You can list configured rules using the following CLIs

## Show cnat translation

This shows the active translations
Below this show an active VIP ``11.104.1.252 TCP port 443``
that has two backends:

- ``11.0.0.132 port 5443``
- ``11.0.0.134 port 5443``

````bash
$ calicovppctl vppctl -node worker-1 show cnat translation
[0] 11.104.1.252;443 TCP lb:default fhc:0x9f(default)
::;0->11.0.0.132;5443
  fib-entry:55
  [@0]: dpo-load-balance: [proto:ip4 index:56 buckets:1 uRPF:115 to:[30218:7444869]]
        [0] [@6]: ipv4 [features] via 0.0.0.0 ipip0: mtu:9000 next:9 flags:[features]
            stacked-on entry:50:
              [@2]: ipv4 via 172.18.0.3 host-eth0: mtu:1500 next:5 flags:[features]
::;0->11.0.0.134;5443
  fib-entry:56
  [@0]: dpo-load-balance: [proto:ip4 index:57 buckets:1 uRPF:114 to:[26005:3295227]]
        [0] [@6]: ipv4 [features] via 0.0.0.0 ipip0: mtu:9000 next:9 flags:[features]
            stacked-on entry:50:
              [@2]: ipv4 via 172.18.0.3 host-eth0: mtu:1500 next:5 flags:[features]
 via:
  [@2]: dpo-load-balance: [proto:ip4 index:58 buckets:2 uRPF:-1 to:[0:0]]
    [0] [@18]: dpo-load-balance: [proto:ip4 index:56 buckets:1 uRPF:115 to:[30218:7444869]]
          [0] [@6]: ipv4 [features] via 0.0.0.0 ipip0: mtu:9000 next:9 flags:[features]
              stacked-on entry:50:
                [@2]: ipv4 via 172.18.0.3 host-eth0: mtu:1500 next:5 flags:[features]
    [1] [@18]: dpo-load-balance: [proto:ip4 index:57 buckets:1 uRPF:114 to:[26005:3295227]]
          [0] [@6]: ipv4 [features] via 0.0.0.0 ipip0: mtu:9000 next:9 flags:[features]
              stacked-on entry:50:
                [@2]: ipv4 via 172.18.0.3 host-eth0: mtu:1500 next:5 flags:[features]
````

## Show cnat session

This lists the active cnat sessions, that is the established five tuple to
five tuple rewrites

<!-- markdownlint-disable -->
````bash
$ calicovppctl vppctl -node worker-1 show cnat session verbose
CNat Sessions: now:24233
Hash table 'CNat Session DB'
[2]: heap offset 36123480, len 1, refcnt 2, linear 0
    0: session:[172.18.0.1;53 -> 172.18.0.3;49353, UDP] => 172.18.0.1;53 -> 11.0.0.130;36878 input lb:-1 age:24237
[4]: heap offset 36123880, len 1, refcnt 2, linear 0
    0: session:[11.0.0.131;35302 -> 172.18.0.1;53, UDP] => 172.18.0.3;50374 -> 172.18.0.1;53 output lb:-1 age:24260
[7]: heap offset 36124480, len 1, refcnt 2, linear 0
    0: session:[11.0.0.130;44076 -> 172.18.0.1;53, UDP] => 172.18.0.3;49347 -> 172.18.0.1;53 output lb:-1 age:24241
[8]: heap offset 36124680, len 1, refcnt 2, linear 0
    0: session:[172.18.0.1;53 -> 172.18.0.3;49859, UDP] => 172.18.0.1;53 -> 11.0.0.131;34849 input lb:-1 age:24258
[10]: heap offset 36125080, len 1, refcnt 2, linear 0
    0: session:[11.0.0.130;37518 -> 172.18.0.1;53, UDP] => 172.18.0.3;51400 -> 172.18.0.1;53 output lb:-1 age:24255
                ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^            ^^^^^
               Incoming 5tuple used to match packets           5tuple after dNAT & sNAT     direction        age(sec)
````
<!-- markdownlint-restore -->

``direction`` being

- ``input`` for the PRE-ROUTING sessions
- ``output`` is the POST-ROUTING sessions

The current implementation stores independant sessions for PRE and POST-ROUTING
as well as independant sessions for forward and return flows.

## Show cnat snat-policy

The following CLI shows how the source NATing is configured

````console
calicovppctl vppctl -node worker-1 'show cnat snat-policy'
````

These IPs will be used for source-NATing

````console
Source NAT
  ip4: 172.18.0.3;0
  ip6: fc00:f853:ccd:e793::3;0
````

These destination prefixes will not be source NATed

````console
Excluded prefixes:
  Hash table 'snat prefixes'
[13]: heap offset 33519872, len 1, refcnt 1, linear 0
    0: 172.18.0.3/32
[85]: heap offset 33520256, len 1, refcnt 1, linear 0
    0: fd10::/120
    0: 11.96.0.0/12
    10 active elements 10 active buckets
    1 free lists
       [len 1] 0 free elts
    0 linear search buckets
    heap: 1 chunk(s) allocated
          bytes: used 128k, scrap 118.75k
````

This is legacy and now unused

````console
Included v4 interfaces:
  loop0
  tun1

Included v6 interfaces:
  loop0
  tun1
````

This list the pod interaces (see source code for logic)

````console
k8s pod interfaces:
  tap0
  loop0
````

We do not sNAT to the host

````console
k8s host interfaces:
  tap0
````

For the full logic, check [the source code](https://github.com/FDio/vpp/blob/master/src/plugins/cnat/cnat_snat_policy.c)
and the ``cnat_snat_policy_k8s`` function
