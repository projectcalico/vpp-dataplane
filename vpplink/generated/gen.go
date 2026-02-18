//go:build generate

package generated

import (
	_ "github.com/calico-vpp/vpplink/pkg"
	_ "go.fd.io/govpp/cmd/binapi-generator"
)

//go:generate go build -buildmode=plugin -o ./.bin/vpplink_plugin.so github.com/calico-vpp/vpplink/pkg
//go:generate go run go.fd.io/govpp/cmd/binapi-generator --no-version-info --no-source-path-info --gen rpc,./.bin/vpplink_plugin.so -o ./bindings --input $VPP_DIR ikev2 gso arp interface ip ipip ipsec ip_neighbor tapv2 nat44_ed cnat af_packet feature ip6_nd punt vxlan af_xdp vlib virtio avf wireguard capo memif acl abf crypto_sw_scheduler sr rdma vmxnet3 pbl memclnt session vpe urpf classify ip_session_redirect rd_cp
