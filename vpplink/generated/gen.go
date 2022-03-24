package generated

import (
	_ "go.fd.io/govpp/binapi"
)

//go:generate go build -buildmode=plugin -o ./.bin/vpplink_plugin.so github.com/calico-vpp/vpplink/pkg
//go:generate go run go.fd.io/govpp/cmd/binapi-generator --no-version-info --no-source-path-info --plugins ./.bin/vpplink_plugin.so -o ./bindings -vpp $VPP_DIR --filter ikev2,gso,arp,interface,ip,ipip,ipsec,ip_neighbor,tapv2,nat44_ed,cnat,af_packet,feature,ip6_nd,punt,vxlan,af_xdp,vlib,virtio,avf,wireguard,capo,memif,acl,abf,crypto_sw_scheduler,sr,rdma,vmxnet3,pbl,memclnt,session,vpe,urpf
