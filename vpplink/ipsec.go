// Copyright (C) 2019 Cisco Systems Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vpplink

import (
	"fmt"
	"io"

	vpptypes "github.com/calico-vpp/vpplink/api/v0"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ipsec"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ipsec_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (v *Vpp) GetIPsecTunnelProtection(tunnelInterface uint32) ([]types.IPsecTunnelProtection, error) {
	client := ipsec.NewServiceClient(v.GetConnection())

	stream, err := client.IpsecTunnelProtectDump(v.GetContext(), &ipsec.IpsecTunnelProtectDump{
		SwIfIndex: interface_types.InterfaceIndex(tunnelInterface),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to dump tunnel interface (%v) protections: %w", tunnelInterface, err)
	}
	protections := make([]types.IPsecTunnelProtection, 0)
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to dump tunnel interface (%v) protections: %w", tunnelInterface, err)
		}
		p := response.Tun
		protections = append(protections, types.IPsecTunnelProtection{
			SwIfIndex:   uint32(p.SwIfIndex),
			NextHop:     types.FromVppAddress(p.Nh),
			OutSAIndex:  p.SaOut,
			InSAIndices: p.SaIn,
		})
	}
	return protections, nil
}

func (v *Vpp) SetIPsecAsyncMode(enable bool) error {
	client := ipsec.NewServiceClient(v.GetConnection())

	_, err := client.IpsecSetAsyncMode(v.GetContext(), &ipsec.IpsecSetAsyncMode{
		AsyncEnable: enable,
	})
	if err != nil {
		return fmt.Errorf("failed to %v IPsec async mode: %w", strEnableDisable[enable], err)
	}
	return nil
}

/*
func (v *Vpp) GetIPsecTunnelProtection(tunnelInterface uint32) (protections []types.IPsecTunnelProtection, err error) {
	client := ipsec.NewServiceClient(v.conn)

	stream, err := client.IpsecTunnelProtectDump(v.ctx, &ipsec.IpsecTunnelProtectDump{
		SwIfIndex: interface_types.InterfaceIndex(tunnelInterface),
	})
	if err != nil {
		return nil, fmt.Errorf("error listing tunnel interface %v protections: %w", tunnelInterface, err)
	}
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error listing tunnel interface %v protections: %w", tunnelInterface, err)
		}
		protections = append(protections, types.IPsecTunnelProtection{
			SwIfIndex:   uint32(response.Tun.SwIfIndex),
			NextHop:     response.Tun.Nh.ToIP(),
			OutSAIndex:  response.Tun.SaOut,
			InSAIndices: response.Tun.SaIn,
		})
	}
	return protections, nil
}*/

func (v *Vpp) addDelIpsecSA(sa *vpptypes.IPSecSA, isAdd bool) error {
	client := ipsec.NewServiceClient(v.conn)

	request := &ipsec.IpsecSadEntryAddDelV3{
		IsAdd: isAdd,
		Entry: ipsec_types.IpsecSadEntryV3{
			SadID:              sa.SAId,
			Spi:                sa.Spi,
			Protocol:           ipsec_types.IPSEC_API_PROTO_ESP,
			CryptoAlgorithm:    ipsec_types.IPSEC_API_CRYPTO_ALG_AES_CTR_128,
			CryptoKey:          getVPPKey(sa.CryptoKey),
			Salt:               sa.Salt,
			IntegrityKey:       getVPPKey(sa.IntegrityKey),
			IntegrityAlgorithm: ipsec_types.IPSEC_API_INTEG_ALG_SHA1_96,
			Flags:              toVppSaFlags(sa.Flags),
			UDPSrcPort:         uint16(sa.SrcPort),
			UDPDstPort:         uint16(sa.DstPort),
		},
	}
	if sa.Tunnel != nil {
		request.Entry.Tunnel = toVppTunnel(*sa.Tunnel)
	}
	_, err := client.IpsecSadEntryAddDelV3(v.ctx, request)
	if err != nil {
		return err
	}
	return nil
}

func (v *Vpp) AddIpsecSA(sa *vpptypes.IPSecSA) error {
	if err := v.addDelIpsecSA(sa, true); err != nil {
		return fmt.Errorf("failed to add IPSec SA: %w", err)
	}
	return nil
}

func (v *Vpp) DelIpsecSA(sa *vpptypes.IPSecSA) error {
	if err := v.addDelIpsecSA(sa, false); err != nil {
		return fmt.Errorf("failed to delete IPSec SA: %w", err)
	}
	return nil
}

func (v *Vpp) AddIpsecSAProtect(swIfIndex, saIn, saOut uint32) error {
	client := ipsec.NewServiceClient(v.conn)

	_, err := client.IpsecTunnelProtectUpdate(v.ctx, &ipsec.IpsecTunnelProtectUpdate{
		Tunnel: ipsec.IpsecTunnelProtect{
			SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
			SaOut:     saOut,
			SaIn:      []uint32{saIn},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to add IPSec Tunnel Protect: %w", err)
	}
	return nil
}

func (v *Vpp) DelIpsecSAProtect(swIfIndex uint32) error {
	client := ipsec.NewServiceClient(v.conn)

	_, err := client.IpsecTunnelProtectDel(v.ctx, &ipsec.IpsecTunnelProtectDel{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	})
	if err != nil {
		return fmt.Errorf("failed to delete IPSec Tunnel Protect: %w", err)
	}
	return nil
}

func (v *Vpp) AddIpsecInterface() (uint32, error) {
	client := ipsec.NewServiceClient(v.conn)

	response, err := client.IpsecItfCreate(v.ctx, &ipsec.IpsecItfCreate{
		Itf: ipsec.IpsecItf{
			UserInstance: ^uint32(0),
		},
	})
	if err != nil {
		return InvalidSwIfIndex, fmt.Errorf("failed to add IPSec interface: %w", err)
	}
	return uint32(response.SwIfIndex), nil
}

func (v *Vpp) DelIpsecInterface(swIfIndex uint32) error {
	client := ipsec.NewServiceClient(v.conn)

	_, err := client.IpsecItfDelete(v.ctx, &ipsec.IpsecItfDelete{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	})
	if err != nil {
		return fmt.Errorf("failed to delete IPSec interface: %w", err)
	}
	return nil
}
