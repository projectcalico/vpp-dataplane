from trex_stl_lib.api import *

class STLS1(object):

    def create_stream (self):

        base_pkt = Ether()/IP(dst="${DST_ADDRESS}")/UDP(dport=${DST_PORT})
        size = 64

        pad = max(0, size - len(base_pkt) - 4) * 'x'

        vm = STLVM()

        vm.tuple_var(name="tuple", ip_min="${SRC_ADDRESS}", ip_max="${SRC_ADDRESS2}",
        			 port_min=${SRC_PORT}, port_max=${SRC_PORT2}, limit_flows=10000000)

        vm.write(fv_name="tuple.ip", pkt_offset="IP.src")
        vm.fix_chksum()

        vm.write(fv_name="tuple.port", pkt_offset="UDP.sport")

        pkt = STLPktBuilder(pkt=base_pkt/pad, vm=vm)

        return STLStream(packet=pkt, mode=STLTXCont())

    def get_streams (self, direction = 0, **kwargs):
        return [self.create_stream()]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()



# start -f trex.py -m 10mbps -p 0