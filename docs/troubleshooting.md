# General CalicoVPP Troubleshooting

*This document assumes that you have installed [calicovppctl](../install/calicovppctl.md)*

## Performance and load

As VPP runs in poll mode, load cannot be told by CPU usage.

````console
$ calicovppctl vppctl -node worker-1 clear run
# wait a few seconds
$ calicovppctl vppctl -node worker-1 show run
Time 3.8, 10 sec internal node vector rate 2.09 loops/sec 5317177.75
  vector rates in 4.9950e1, out 4.7868e1, drop 2.3414e0, punt 0.0000e0
Name        State   Calls Vectors  Suspends  Clocks  Vectors/Call
ip4-input   active  63    175      0         3.27e2  2.78
ip4-lookup  active  71    175      0         2.98e2  2.46
...
````

A loaded VPP will typically have

- a high `Vectors/Call` maxing out at 256
- a low `loops/sec` strugling around 10000
- The ``Clocks`` column tells you the consumption in cycles
per node on average. Beyond ``1e3`` is expensive.

## Show error counters

The following CLI show error and info counters in VPP
You can ignore the Severity column which is not indicative
of actual severity

````console
$ calicovppctl vppctl -node worker-1 show errors
 Count         Node                        Reason               Severity
     1 acl-plugin-out-ip4-fa           ACL deny packets            error
 11028 acl-plugin-out-ip4-fa          new sessions added           error
  9690  acl-plugin-in-ip6-fa           checked packets             error
     5  acl-plugin-in-ip6-fa        restart session timer          error
     5       arp-proxy                 ARP replies sent            info
 12723       arp-reply                 ARP replies sent            info
  2042       arp-reply       ARP request IP4 source address lear   info
137390      ipip4-input              packets decapsulated          error
  6351       tcp6-input                 Packets punted             info
213058       tcp4-input                 Packets punted             info
   239       ip6-glean                    throttled                info
  5429       ip6-glean           neighbor solicitations sent       info
     2       ip4-glean                ARP requests sent            info
229587       ip4-inacl                 input ACL misses            error
    48       ip6-input            Multicast RPF check failed       error
    17  ip6-local-hop-by-hop Unknown protocol ip6 local h-b-h pa   error
 47074     ip6-icmp-input    neighbor solicitations for unknown    error
  1332     ip6-icmp-input        neighbor advertisements sent      info
     1     ip6-icmp-input      neighbor advertisements received    info
   150     ip6-icmp-input     neighbor discovery not configured    error
  5554     ethernet-input              l3 mac mismatch             error
````

This reset the error counters

````console
calicovppctl vppctl -node worker-1 clear errors
````

## Show session and tcp stats

The following CLI show the global statistics reported by TCP

````console
$ calicovppctl vppctl -node worker-1 show tcp stats
Thread 0:
Thread 1:
 30 timer expirations
 3 timeout close-wait
 1 reset on close due to unread data
````

The following CLI show the global statistics reported by the session layer

````console
$ calicovppctl vppctl -node worker-1 show session  stats
Thread 0:
Thread 1:
 36 ip port pair already listened on
````

## Show startup logs

The following CLI will output interesting information if VPP
fails to start up properly

````console
calicovppctl vppctl -node worker-1 show log
````
