# Packet capture and traces in CalicoVPP

If packet drop is supsected, a capture might help identify the root cause.
Multiple capture types are available.

- ``pcap`` capture all packets RECEIVED on a given interface TYPE.
Output in pcap wireshark format.
- ``dispatch trace`` traces all packets RECEIVED on a given interface TYPE
as they journey through VPP nodes. Output in pcap wireshark format.
- ``trace`` traces all packets RECEIVED on a given interface TYPE as they
journey through VPP nodes. In text format.

## pcap

This will capture all the packets RECEIVED on ALL interfaces.
You can filter using ``-interface <tun3>``
Use ``calicovppctl -node worker-1 vppctl show int addr`` to list
interfaces with addresses

````console
calicovppctl pcap -node worker-1
gzip -d ./pcap_worker-1.pcap.gz
````

## Dispatch trace

This will capture all the packets RECEIVED on tuntap interfaces.
You can filter using ``-interface <vcl|memif|phy>``
Use ``calicovppctl -node worker-1 vppctl show int addr`` to list
interfaces with addresses

````console
calicovppctl dispatch -node worker-1 -interface virtio
gzip -d ./dispatch_worker-1.pcap.gz
````

## VPP trace

This will capture all the packets RECEIVED on the uplink interface.
You can filter using ``-interface <vcl|memif|phy>``
Use ``calicovppctl -node worker-1 vppctl show int addr`` to list
interfaces with addresses

````console
$ calicovppctl trace -node worker-1 -interface phy
$ gzip -d trace.txt.gz
$ head trace.txt
------------------- Start of thread 0 vpp_main -------------------
Packet 1

05:23:12:530191: af-packet-input
  af_packet: hw_if_index 1 rx-queue 0 next-index 4
    tpacket2_hdr:
      status 0x20000009 len 66 snaplen 66 mac 76 net 90
      sec 0x68e52673 nsec 0x2e217644 vlan 0 vlan_tpid 0
    vnet-hdr:
      flags 0x01 gso_type 0x00 hdr_len 0
````
