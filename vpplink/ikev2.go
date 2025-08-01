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
	"net"

	"github.com/pkg/errors"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ikev2"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ikev2_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type IKEv2IDType uint8

const (
	IKEv2IDTypeIPv4Addr   IKEv2IDType = 1
	IKEv2IDTypeFQDN       IKEv2IDType = 2
	IKEv2IDTypeRFC822Addr IKEv2IDType = 3
	IKEv2IDTypeIPv6Addr   IKEv2IDType = 5
	IKEv2IDTypeDerAsn1Dn  IKEv2IDType = 9
	IKEv2IDTypeDerAsn1Gn  IKEv2IDType = 10
	IKEv2IDTypeKeyID      IKEv2IDType = 11
)

type IKEv2AuthMethod uint8

const (
	IKEv2AuthMethodRSASig       IKEv2AuthMethod = 1
	IKEv2AuthMethodSharedKeyMic IKEv2AuthMethod = 2
)

type IKEv2EncryptionAlgorithm uint32

const (
	IKEv2EncryptionAlgorithmDESIV64  IKEv2EncryptionAlgorithm = 1
	IKEv2EncryptionAlgorithmDES      IKEv2EncryptionAlgorithm = 2
	IKEv2EncryptionAlgorithm3DES     IKEv2EncryptionAlgorithm = 3
	IKEv2EncryptionAlgorithmRC5      IKEv2EncryptionAlgorithm = 4
	IKEv2EncryptionAlgorithmIDEA     IKEv2EncryptionAlgorithm = 5
	IKEv2EncryptionAlgorithmCAST     IKEv2EncryptionAlgorithm = 6
	IKEv2EncryptionAlgorithmBLOWFISH IKEv2EncryptionAlgorithm = 7
	IKEv2EncryptionAlgorithm3IDEA    IKEv2EncryptionAlgorithm = 8
	IKEv2EncryptionAlgorithmDESIV32  IKEv2EncryptionAlgorithm = 9
	IKEv2EncryptionAlgorithmNULL     IKEv2EncryptionAlgorithm = 11
	IKEv2EncryptionAlgorithmAESCBC   IKEv2EncryptionAlgorithm = 12
	IKEv2EncryptionAlgorithmAESCTR   IKEv2EncryptionAlgorithm = 13
	IKEv2EncryptionAlgorithmAESGCM16 IKEv2EncryptionAlgorithm = 20
)

type IKEv2IntegrityAlgorithm uint32

const (
	IKEv2IntegrityAlgorithmNone               IKEv2IntegrityAlgorithm = 0
	IKEv2IntegrityAlgorithmAuthHMACMD596      IKEv2IntegrityAlgorithm = 1
	IKEv2IntegrityAlgorithmAuthHMACSHA196     IKEv2IntegrityAlgorithm = 2
	IKEv2IntegrityAlgorithmAuthDESMAC         IKEv2IntegrityAlgorithm = 3
	IKEv2IntegrityAlgorithmAuthKPDKMD5        IKEv2IntegrityAlgorithm = 4
	IKEv2IntegrityAlgorithmAuthAESXCBC96      IKEv2IntegrityAlgorithm = 5
	IKEv2IntegrityAlgorithmAuthHMACMD5128     IKEv2IntegrityAlgorithm = 6
	IKEv2IntegrityAlgorithmAuthHMACSHA1160    IKEv2IntegrityAlgorithm = 7
	IKEv2IntegrityAlgorithmAuthAESCMAC96      IKEv2IntegrityAlgorithm = 8
	IKEv2IntegrityAlgorithmAuthAES128GMAC     IKEv2IntegrityAlgorithm = 9
	IKEv2IntegrityAlgorithmAuthAES192GMAC     IKEv2IntegrityAlgorithm = 10
	IKEv2IntegrityAlgorithmAuthAES256GMAC     IKEv2IntegrityAlgorithm = 11
	IKEv2IntegrityAlgorithmAuthHMACSHA2256128 IKEv2IntegrityAlgorithm = 12
	IKEv2IntegrityAlgorithmAuthHMACSHA2384192 IKEv2IntegrityAlgorithm = 13
	IKEv2IntegrityAlgorithmAuthHMACSHA2512256 IKEv2IntegrityAlgorithm = 14
)

type IKEv2DHGroup uint32

const (
	IKEv2DHGroupNone         IKEv2DHGroup = 0
	IKEv2DHGroupMODP768      IKEv2DHGroup = 1
	IKEv2DHGroupMODP1024     IKEv2DHGroup = 2
	IKEv2DHGroupMODP1536     IKEv2DHGroup = 5
	IKEv2DHGroupMODP2048     IKEv2DHGroup = 14
	IKEv2DHGroupMODP3072     IKEv2DHGroup = 15
	IKEv2DHGroupMODP4096     IKEv2DHGroup = 16
	IKEv2DHGroupMODP6144     IKEv2DHGroup = 17
	IKEv2DHGroupMODP8192     IKEv2DHGroup = 18
	IKEv2DHGroupECP256       IKEv2DHGroup = 19
	IKEv2DHGroupECP384       IKEv2DHGroup = 20
	IKEv2DHGroupECP521       IKEv2DHGroup = 21
	IKEv2DHGroupMODP1024160  IKEv2DHGroup = 22
	IKEv2DHGroupMODP2048224  IKEv2DHGroup = 23
	IKEv2DHGroupMODP2048256  IKEv2DHGroup = 24
	IKEv2DHGroupECP192       IKEv2DHGroup = 25
	IKEv2DHGroupECP224       IKEv2DHGroup = 26
	IKEv2DHGroupBRAINPOOL224 IKEv2DHGroup = 27
	IKEv2DHGroupBRAINPOOL256 IKEv2DHGroup = 28
	IKEv2DHGroupBRAINPOOL384 IKEv2DHGroup = 29
	IKEv2DHGroupBRAINPOOL512 IKEv2DHGroup = 30
)

func (v *VppLink) AddIKEv2Profile(name string) error {
	return v.addDelIKEv2Profile(name, true)
}

func (v *VppLink) DelIKEv2Profile(name string) error {
	return v.addDelIKEv2Profile(name, false)
}

func (v *VppLink) addDelIKEv2Profile(name string, isAdd bool) error {
	client := ikev2.NewServiceClient(v.GetConnection())

	if len(name) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}

	_, err := client.Ikev2ProfileAddDel(v.GetContext(), &ikev2.Ikev2ProfileAddDel{
		Name:  name,
		IsAdd: isAdd,
	})
	if err != nil {
		return fmt.Errorf("failed to create IKEv2 profile %s: %w", name, err)
	}
	v.GetLog().Debugf("created ikev2 profile %s", name)
	return nil
}

func (v *VppLink) ListIKEv2Profiles() ([]ikev2_types.Ikev2Profile, error) {
	client := ikev2.NewServiceClient(v.GetConnection())

	stream, err := client.Ikev2ProfileDump(v.GetContext(), &ikev2.Ikev2ProfileDump{})
	if err != nil {
		return nil, fmt.Errorf("failed to dump IKEv2 profiles: %w", err)
	}
	var profiles []ikev2_types.Ikev2Profile
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to dump IKEv2 profiles: %w", err)
		}
		profiles = append(profiles, response.Profile)
	}
	return profiles, nil
}

func (v *VppLink) setIKEv2Auth(profile string, authMethod IKEv2AuthMethod, authData []byte) error {
	client := ikev2.NewServiceClient(v.GetConnection())

	if len(profile) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}

	_, err := client.Ikev2ProfileSetAuth(v.GetContext(), &ikev2.Ikev2ProfileSetAuth{
		Name:       profile,
		AuthMethod: uint8(authMethod),
		IsHex:      false,
		Data:       authData,
	})
	if err != nil {
		return fmt.Errorf("failed to set IKEv2 auth for profile %s: %w", profile, err)
	}
	v.GetLog().Debugf("set auth method for profile %s to %d", profile, authMethod)
	return nil
}

func (v *VppLink) SetIKEv2PSKAuth(profile, psk string) (err error) {
	return v.setIKEv2Auth(profile, IKEv2AuthMethodSharedKeyMic, []byte(psk))
}

func (v *VppLink) setIKEv2ID(profile string, isLocal bool, idType IKEv2IDType, id []byte) error {
	client := ikev2.NewServiceClient(v.GetConnection())

	if len(profile) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}

	_, err := client.Ikev2ProfileSetID(v.GetContext(), &ikev2.Ikev2ProfileSetID{
		Name:    profile,
		IsLocal: isLocal,
		IDType:  uint8(idType),
		Data:    id,
	})
	if err != nil {
		return fmt.Errorf("failed to set IKEv2 ID %t for profile %s: %w", isLocal, profile, err)
	}
	v.GetLog().Debugf("set IKEv2 ID %t for profile %s", isLocal, profile)
	return nil
}

func (v *VppLink) SetIKEv2LocalIDAddress(profile string, localAddr net.IP) (err error) {
	if localAddr.To4() == nil {
		return errors.New("IPv6 unsupported in IKEv2 at this time")
	}
	return v.setIKEv2ID(profile, true, IKEv2IDTypeIPv4Addr, localAddr.To4())
}

func (v *VppLink) SetIKEv2RemoteIDAddress(profile string, rmtAddr net.IP) (err error) {
	if rmtAddr.To4() == nil {
		return errors.New("IPv6 unsupported in IKEv2 at this time")
	}
	return v.setIKEv2ID(profile, false, IKEv2IDTypeIPv4Addr, rmtAddr.To4())
}

func (v *VppLink) SetIKEv2TrafficSelector(
	profile string,
	isLocal bool,
	proto uint8,
	startPort uint16,
	endPort uint16,
	startAddr net.IP,
	endAddr net.IP,
) error {
	client := ikev2.NewServiceClient(v.GetConnection())

	if len(profile) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}
	if startAddr.To4() == nil || endAddr.To4() == nil {
		return errors.New("IPv6 unsupported in IKEv2 at this time")
	}

	_, err := client.Ikev2ProfileSetTs(v.GetContext(), &ikev2.Ikev2ProfileSetTs{
		Name: profile,
		Ts: ikev2_types.Ikev2Ts{
			IsLocal:    isLocal,
			ProtocolID: proto,
			StartPort:  startPort,
			EndPort:    endPort,
			StartAddr:  types.ToVppAddress(startAddr),
			EndAddr:    types.ToVppAddress(endAddr),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to set IKEv2 traffic selector for profile %s: %w", profile, err)
	}
	v.GetLog().Debugf("set traffic selector for profile %s", profile)
	return nil
}

func (v *VppLink) SetIKEv2PermissiveTrafficSelectors(profile string) (err error) {
	err = v.SetIKEv2TrafficSelector(profile, true, 0, 0, 0xffff, net.ParseIP("0.0.0.0"), net.ParseIP("255.255.255.255"))
	if err != nil {
		return err
	}
	return v.SetIKEv2TrafficSelector(profile, false, 0, 0, 0xffff, net.ParseIP("0.0.0.0"), net.ParseIP("255.255.255.255"))
}

func (v *VppLink) SetIKEv2ESPTransforms(
	profile string,
	cryptoAlg IKEv2EncryptionAlgorithm,
	cryptoKeySize uint32,
	integAlg IKEv2IntegrityAlgorithm,
) error {
	client := ikev2.NewServiceClient(v.GetConnection())

	if len(profile) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}

	_, err := client.Ikev2SetEspTransforms(v.GetContext(), &ikev2.Ikev2SetEspTransforms{
		Name: profile,
		Tr: ikev2_types.Ikev2EspTransforms{
			CryptoAlg:     uint8(cryptoAlg),
			CryptoKeySize: cryptoKeySize,
			IntegAlg:      uint8(integAlg),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to set ESP transforms for profile %s: %w", profile, err)
	}
	v.GetLog().Debugf("set ESP transforms for profile %s", profile)
	return nil
}

func (v *VppLink) SetIKEv2IKETransforms(
	profile string,
	cryptoAlg IKEv2EncryptionAlgorithm,
	cryptoKeySize uint32,
	integAlg IKEv2IntegrityAlgorithm,
	dhGroup IKEv2DHGroup,
) error {
	client := ikev2.NewServiceClient(v.GetConnection())

	if len(profile) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}

	_, err := client.Ikev2SetIkeTransforms(v.GetContext(), &ikev2.Ikev2SetIkeTransforms{
		Name: profile,
		Tr: ikev2_types.Ikev2IkeTransforms{
			CryptoAlg:     uint8(cryptoAlg),
			CryptoKeySize: cryptoKeySize,
			IntegAlg:      uint8(integAlg),
			DhGroup:       uint8(dhGroup),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to set IKE transforms for profile %s: %w", profile, err)
	}
	v.GetLog().Debugf("set IKE transforms for profile %s", profile)
	return nil
}

func (v *VppLink) SetIKEv2DefaultTransforms(profile string) (err error) {
	err = v.SetIKEv2IKETransforms(
		profile,
		IKEv2EncryptionAlgorithmAESCBC,
		256,
		IKEv2IntegrityAlgorithmAuthHMACSHA196,
		IKEv2DHGroupMODP2048,
	)
	if err != nil {
		return err
	}
	return v.SetIKEv2ESPTransforms(
		profile,
		IKEv2EncryptionAlgorithmAESGCM16,
		256,
		IKEv2IntegrityAlgorithmNone,
	)
}

func (v *VppLink) SetIKEv2Responder(profile string, swIfIndex uint32, address net.IP) error {
	client := ikev2.NewServiceClient(v.GetConnection())

	if len(profile) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}
	if address.To4() == nil {
		return errors.New("IPv6 unsupported in IKEv2 at this time")
	}

	vppAddr := types.ToVppAddress(address)
	_, err := client.Ikev2SetResponder(v.GetContext(), &ikev2.Ikev2SetResponder{
		Name: profile,
		Responder: ikev2_types.Ikev2Responder{
			SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
			Addr:      vppAddr,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to set IKE responder for profile %s: %w", profile, err)
	}
	v.GetLog().Debugf("set IKE responder for profile %s, interface %d addr %v", profile, swIfIndex, vppAddr)
	return nil
}

func (v *VppLink) SetIKEv2TunnelInterface(profile string, swIfIndex uint32) error {
	client := ikev2.NewServiceClient(v.GetConnection())

	if len(profile) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}

	_, err := client.Ikev2SetTunnelInterface(v.GetContext(), &ikev2.Ikev2SetTunnelInterface{
		Name:      profile,
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	})
	if err != nil {
		return fmt.Errorf("failed to set IKE tunnel interface for profile %s: %w", profile, err)
	}
	v.GetLog().Debugf("set IKE tunnel interface for profile %s", profile)
	return nil
}

func (v *VppLink) IKEv2Initiate(profile string) error {
	client := ikev2.NewServiceClient(v.GetConnection())

	if len(profile) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}

	_, err := client.Ikev2InitiateSaInit(v.GetContext(), &ikev2.Ikev2InitiateSaInit{
		Name: profile,
	})
	if err != nil {
		return fmt.Errorf("failed to initiate IKE for profile %s: %w", profile, err)
	}
	v.GetLog().Debugf("initiated IKE for profile %s", profile)
	return nil
}
