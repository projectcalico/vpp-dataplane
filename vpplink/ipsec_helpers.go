// Copyright (C) 2019 Cisco Systems Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package vpplink

import (
	typesv0 "github.com/calico-vpp/vpplink/api/v0"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ipsec_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/tunnel_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func toVppSaFlags(flags typesv0.SaFlags) ipsec_types.IpsecSadFlags {
	return ipsec_types.IpsecSadFlags(flags)
}

func getVPPKey(in []byte) ipsec_types.Key {
	return ipsec_types.Key{
		Length: uint8(len(in)),
		Data:   in,
	}
}

func toVppTunnel(tunnel typesv0.Tunnel) tunnel_types.Tunnel {
	return tunnel_types.Tunnel{
		Src:     types.ToVppAddress(tunnel.Src),
		Dst:     types.ToVppAddress(tunnel.Dst),
		TableID: tunnel.TableID,
	}
}

func GetSaFlagNone() typesv0.SaFlags {
	return typesv0.SaFlags(ipsec_types.IPSEC_API_SAD_FLAG_NONE)
}

func GetSaFlagUseEsn() typesv0.SaFlags {
	return typesv0.SaFlags(ipsec_types.IPSEC_API_SAD_FLAG_USE_ESN)
}

func GetSaFlagAntiReplay() typesv0.SaFlags {
	return typesv0.SaFlags(ipsec_types.IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY)
}

func GetSaFlagIsTunnel() typesv0.SaFlags {
	return typesv0.SaFlags(ipsec_types.IPSEC_API_SAD_FLAG_IS_TUNNEL)
}

func GetSaFlagIsTunnelV6() typesv0.SaFlags {
	return typesv0.SaFlags(ipsec_types.IPSEC_API_SAD_FLAG_IS_TUNNEL_V6)
}

func GetSaFlagUDPEncap() typesv0.SaFlags {
	return typesv0.SaFlags(ipsec_types.IPSEC_API_SAD_FLAG_UDP_ENCAP)
}

func GetSaFlagIsInbound() typesv0.SaFlags {
	return typesv0.SaFlags(ipsec_types.IPSEC_API_SAD_FLAG_IS_INBOUND)
}

func GetSaFlagAsync() typesv0.SaFlags {
	return typesv0.SaFlags(ipsec_types.IPSEC_API_SAD_FLAG_ASYNC)
}
