//go:build generate

package generated

import (
	_ "go.fd.io/govpp/cmd/binapi-generator"
)

//go:generate go run go.fd.io/govpp/cmd/binapi-generator --no-version-info --no-source-path-info --gen rpc -o ./bindings --input $VPP_DIR ikev2 gso arp interface ip ipip ipsec ip_neighbor tapv2 nat44_ed cnat af_packet feature ip6_nd punt vxlan af_xdp vlib virtio wireguard npol memif acl abf crypto_sw_scheduler sr rdma vmxnet3 pbl memclnt session vpe urpf classify ip_session_redirect
