# Troubleshooting CalicoVPP policies

*This document assumes that you have installed [calicovppctl](../install/calicovppctl.md)*

You can show the active policies per interface using the following CLIs.

## Show npol interfaces

This CLI show the resulting policies configured for every interface in VPP.
The first IPv4 address of every pod is provided to help identify which pod
and interface belongs to.

Policies contain 3 sections :

- ``tx`` which contain rules that are applied on packets that LEAVE VPP
on a given interface. Rules are applied top to bottom.
- ``rx`` which contain rules that are applied on packets that ENTER VPP
on a given interface. Rules are applied top to bottom.
- ``profiles`` are specific rules that are enforced when a matched rule action
is ``PASS`` or when no policies are configured.

````bash
$ calicovppctl vppctl -node worker-1 show npol interfaces
Interfaces with policies configured:
[tap0 sw_if_index=2  addr=172.18.0.4 addr6=fc00:f853:ccd:e793::4]
  tx:
    [policy#0]
      tx:[rule#24;allow][src==[ipset#0;ip;11.0.0.1,fd20::97de:47c:45f6:c00,],]
    [policy#1]
      tx:[rule#1;allow][]
[tun1 sw_if_index=4  addr=11.0.0.1 addr6=fd20::97de:47c:45f6:c00]
  profiles:
    [policy#5]
      tx:[rule#5;allow][]
      rx:[rule#4;allow][]
    [policy#6]
````

## Show npol policies

This CLI list all the policies that are referenced on interfaces

````console
$ calicovppctl vppctl -node worker-1 show npol policies verbose
[policy#0]
  tx:[rule#24;allow][src==[ipset#0;ip;11.0.0.1,fd20::97de:47c:45f6:c00,],]
[policy#4]
  tx:[rule#6;allow][proto==TCP,dst==22,]
  tx:[rule#7;allow][proto==UDP,dst==68,]
  tx:[rule#8;allow][proto==TCP,dst==179,]
  tx:[rule#9;allow][proto==TCP,dst==2379,]
  tx:[rule#10;allow][proto==TCP,dst==2380,]
  tx:[rule#11;allow][proto==TCP,dst==5473,]
  tx:[rule#12;allow][proto==TCP,dst==6443,]
````

## Show npol rules

This list rules that are referenced by policies

````console
$ calicovppctl vppctl -node worker-1 show npol rules
[rule#0;allow][src==172.18.0.4/32,src==fc00:f853:ccd:e793::4/128,]
[rule#1;allow][]
[rule#16;allow][proto==UDP,dst==67,]
[rule#17;allow][proto==TCP,dst==179,]
[rule#18;allow][proto==TCP,dst==2379,]
[rule#19;allow][proto==TCP,dst==2380,]
[rule#23;allow][proto==TCP,dst==6667,]
[rule#24;allow][src==[ipset#0;ip;11.0.0.1,fd20::97de:47c:45f6:c00,],]
[rule#25;allow][dst==[ipset#0;ip;11.0.0.1,fd20::97de:47c:45f6:c00,],]
````

## Show npol ipset

This list ipsets that are referenced by rules. IPsets are just list of IPs

````console
$ calicovppctl vppctl -node worker-1 show npol ipset
[ipset#0;ip;11.0.0.1,fd20::97de:47c:45f6:c00,]
````
