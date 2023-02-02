package types

import (
	"net"

	"github.com/projectcalico/vpp-dataplane/vpplink/generated/bindings/ethernet_types"
)

func MacAddress(hwAddr net.HardwareAddr) ethernet_types.MacAddress {
	return ethernet_types.NewMacAddress(hwAddr)
}
