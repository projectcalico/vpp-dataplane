package generated

import (
	_ "git.fd.io/govpp.git/binapi"
)

//go:generate go run git.fd.io/govpp.git/cmd/binapi-generator --no-version-info --no-source-path-info --plugins vpplink -o ./bindings -vpp $VPP_DIR --filter ikev2,gso,arp,interface,ip,ipip,ipsec,ip_neighbor,tapv2,nat44_ed,cnat,af_packet,feature,ip6_nd,punt,vxlan,af_xdp,vlib,virtio,avf,wireguard,capo,memif,acl,abf,crypto_sw_scheduler,sr,rdma,vmxnet3,pbl,memclnt,session,vpe
