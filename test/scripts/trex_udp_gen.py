#!/usr/bin/python

import argparse;
from trex_stl_lib.api import *

class STLS1(object):
    def __init__(self, args):
        self.dst_addr = args.dst_addr
        self.pkt_size = args.pkt_size
        self.limit_flows = args.limit_flows

    def create_stream (self):
        base_pkt = Ether()/IP(dst=self.dst_addr)/UDP(dport=4444)

        pad_len = self.pkt_size - len(base_pkt)
        base_pkt = base_pkt / Raw('a' * pad_len)

        vm = STLVM()
        vm.tuple_var(name="tuple", ip_min="10.0.0.2", ip_max="10.0.0.255",
                    port_min=1025, port_max=65535, limit_flows=self.limit_flows)
        vm.write(fv_name="tuple.ip", pkt_offset="IP.src")
        vm.write(fv_name="tuple.port", pkt_offset="UDP.sport")
        # vm.fix_chksum()
        vm.fix_chksum_hw(l3_offset='IP', l4_offset='UDP', l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP)


        return STLStream(packet=STLPktBuilder(pkt=base_pkt, vm=vm), mode=STLTXCont())

    def get_streams (self, direction = 0, **kwargs):
        return [self.create_stream()]


# dynamic load - used for trex console or simulator
# e.g. :
# reset ; service ; arp ; service --off ; start -f stl/this_file.py -m 10mbps -p 1
def register():
    return STLS1()


def connect_and_run_test (args):
    stream = STLS1(args).get_streams()[0]
    c = STLClient() # Connect to localhost

    try:
        # connect to server
        print("connect...")
        c.connect()
        c.acquire(force=True)

        # add both streams to ports
        c.add_streams(stream, ports=[0])

        # clear the stats before injecting
        c.clear_stats()

        c.start(ports=[0], mult=args.multiplier, duration=args.duration)

        # block until done
        c.wait_on_traffic(ports=[0])

        # read the stats after the test
        stats = c.get_stats()

        print(json.dumps(stats[0], indent=4, separators=(',', ': '), sort_keys=True))

    except STLError as e:
        print("FAILED")
        print(e)

    finally:
        c.disconnect()

def process_options ():
    parser = argparse.ArgumentParser(usage="""
    connect to TRex and send burst of packets

    examples

     stl_run_udp_simple.py -s 9001

     stl_run_udp_simple.py -s 9000 -d 2

     stl_run_udp_simple.py -s 3000 -d 3 -m 10mbps

     stl_run_udp_simple.py -s 3000 -d 3 -m 10mbps --debug

     then run the simulator on the output
       ./stl-sim -f example.yaml -o a.pcap  ==> a.pcap include the packet

    """,
    description="example for TRex api",
    epilog=" written by hhaim");

    parser.add_argument("-s", "--frame-size",
                        dest="pkt_size",
                        help='L2 frame size in bytes without FCS',
                        default=64,
                        type = int,
                        )

    parser.add_argument("--ip",
                        dest="dst_addr",
                        help='remote trex ip default local',
                        default="127.0.0.1",
                        type = str
                        )


    parser.add_argument('-d','--duration',
                        dest='duration',
                        help='duration in second ',
                        default=10,
                        type = int,
                        )

    parser.add_argument('-m','--multiplier',
                        dest='multiplier',
                        help='speed in gbps/pps for example 1gbps, 1mbps, 1mpps ',
                        default="1mbps"
                        )

    parser.add_argument('-f','--limit-flows',
                        dest='limit_flows',
                        help='Maximum number of flows',
                        default=10000,
                        type=int,
                        )

    return parser.parse_args()



def main():
    args = process_options ()
    connect_and_run_test(args)

if __name__ == "__main__":
    main()
