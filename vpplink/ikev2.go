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
	"net"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ikev2"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ikev2_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
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
	IKEv2EncryptionAlgorithmDES_IV64   IKEv2EncryptionAlgorithm = 1
	IKEv2EncryptionAlgorithmDES        IKEv2EncryptionAlgorithm = 2
	IKEv2EncryptionAlgorithm3DES       IKEv2EncryptionAlgorithm = 3
	IKEv2EncryptionAlgorithmRC5        IKEv2EncryptionAlgorithm = 4
	IKEv2EncryptionAlgorithmIDEA       IKEv2EncryptionAlgorithm = 5
	IKEv2EncryptionAlgorithmCAST       IKEv2EncryptionAlgorithm = 6
	IKEv2EncryptionAlgorithmBLOWFISH   IKEv2EncryptionAlgorithm = 7
	IKEv2EncryptionAlgorithm3IDEA      IKEv2EncryptionAlgorithm = 8
	IKEv2EncryptionAlgorithmDES_IV32   IKEv2EncryptionAlgorithm = 9
	IKEv2EncryptionAlgorithmNULL       IKEv2EncryptionAlgorithm = 11
	IKEv2EncryptionAlgorithmAES_CBC    IKEv2EncryptionAlgorithm = 12
	IKEv2EncryptionAlgorithmAES_CTR    IKEv2EncryptionAlgorithm = 13
	IKEv2EncryptionAlgorithmAES_GCM_16 IKEv2EncryptionAlgorithm = 20
)

type IKEv2IntegrityAlgorithm uint32

const (
	IKEv2IntegrityAlgorithmNone                   IKEv2IntegrityAlgorithm = 0
	IKEv2IntegrityAlgorithmAUTH_HMAC_MD5_96       IKEv2IntegrityAlgorithm = 1
	IKEv2IntegrityAlgorithmAUTH_HMAC_SHA1_96      IKEv2IntegrityAlgorithm = 2
	IKEv2IntegrityAlgorithmAUTH_DES_MAC           IKEv2IntegrityAlgorithm = 3
	IKEv2IntegrityAlgorithmAUTH_KPDK_MD5          IKEv2IntegrityAlgorithm = 4
	IKEv2IntegrityAlgorithmAUTH_AES_XCBC_96       IKEv2IntegrityAlgorithm = 5
	IKEv2IntegrityAlgorithmAUTH_HMAC_MD5_128      IKEv2IntegrityAlgorithm = 6
	IKEv2IntegrityAlgorithmAUTH_HMAC_SHA1_160     IKEv2IntegrityAlgorithm = 7
	IKEv2IntegrityAlgorithmAUTH_AES_CMAC_96       IKEv2IntegrityAlgorithm = 8
	IKEv2IntegrityAlgorithmAUTH_AES_128_GMAC      IKEv2IntegrityAlgorithm = 9
	IKEv2IntegrityAlgorithmAUTH_AES_192_GMAC      IKEv2IntegrityAlgorithm = 10
	IKEv2IntegrityAlgorithmAUTH_AES_256_GMAC      IKEv2IntegrityAlgorithm = 11
	IKEv2IntegrityAlgorithmAUTH_HMAC_SHA2_256_128 IKEv2IntegrityAlgorithm = 12
	IKEv2IntegrityAlgorithmAUTH_HMAC_SHA2_384_192 IKEv2IntegrityAlgorithm = 13
	IKEv2IntegrityAlgorithmAUTH_HMAC_SHA2_512_256 IKEv2IntegrityAlgorithm = 14
)

type IKEv2DHGroup uint32

const (
	IKEv2DHGroupNone          IKEv2DHGroup = 0
	IKEv2DHGroupMODP_768      IKEv2DHGroup = 1
	IKEv2DHGroupMODP_1024     IKEv2DHGroup = 2
	IKEv2DHGroupMODP_1536     IKEv2DHGroup = 5
	IKEv2DHGroupMODP_2048     IKEv2DHGroup = 14
	IKEv2DHGroupMODP_3072     IKEv2DHGroup = 15
	IKEv2DHGroupMODP_4096     IKEv2DHGroup = 16
	IKEv2DHGroupMODP_6144     IKEv2DHGroup = 17
	IKEv2DHGroupMODP_8192     IKEv2DHGroup = 18
	IKEv2DHGroupECP_256       IKEv2DHGroup = 19
	IKEv2DHGroupECP_384       IKEv2DHGroup = 20
	IKEv2DHGroupECP_521       IKEv2DHGroup = 21
	IKEv2DHGroupMODP_1024_160 IKEv2DHGroup = 22
	IKEv2DHGroupMODP_2048_224 IKEv2DHGroup = 23
	IKEv2DHGroupMODP_2048_256 IKEv2DHGroup = 24
	IKEv2DHGroupECP_192       IKEv2DHGroup = 25
	IKEv2DHGroupECP_224       IKEv2DHGroup = 26
	IKEv2DHGroupBRAINPOOL_224 IKEv2DHGroup = 27
	IKEv2DHGroupBRAINPOOL_256 IKEv2DHGroup = 28
	IKEv2DHGroupBRAINPOOL_384 IKEv2DHGroup = 29
	IKEv2DHGroupBRAINPOOL_512 IKEv2DHGroup = 30
)

func (v *VppLink) AddIKEv2Profile(name string) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if len(name) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}
	request := &ikev2.Ikev2ProfileAddDel{
		Name:  name,
		IsAdd: true,
	}
	response := &ikev2.Ikev2ProfileAddDelReply{}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "failed to create IKEv2 profile %s", name)
	} else if response.Retval != 0 {
		return fmt.Errorf("failed to create IKEv2 profile %s (retval %d)", name, response.Retval)
	}
	v.log.Debugf("created ikev2 profile %s", name)
	return nil
}

func (v *VppLink) setIKEv2Auth(profile string, authMethod IKEv2AuthMethod, authData []byte) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if len(profile) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}
	request := &ikev2.Ikev2ProfileSetAuth{
		Name:       profile,
		AuthMethod: uint8(authMethod),
		IsHex:      false,
		Data:       authData,
	}
	response := &ikev2.Ikev2ProfileSetAuthReply{}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "failed to set IKEv2 auth for profile %s", profile)
	} else if response.Retval != 0 {
		return fmt.Errorf("failed to set IKEv2 auth for profile %s (retval %d)", profile, response.Retval)
	}
	v.log.Debugf("set auth method for profile %s to %d", profile, authMethod)
	return nil
}

func (v *VppLink) SetIKEv2PSKAuth(profile, psk string) (err error) {
	return v.setIKEv2Auth(profile, IKEv2AuthMethodSharedKeyMic, []byte(psk))
}

func (v *VppLink) setIKEv2ID(profile string, isLocal bool, idType IKEv2IDType, id []byte) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if len(profile) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}
	request := &ikev2.Ikev2ProfileSetID{
		Name:    profile,
		IsLocal: isLocal,
		IDType:  uint8(idType),
		Data:    id,
	}
	response := &ikev2.Ikev2ProfileSetIDReply{}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "failed to set IKEv2 ID %t for profile %s", isLocal, profile)
	} else if response.Retval != 0 {
		return fmt.Errorf("failed to set IKEv2 ID %t for profile %s (retval %d)", isLocal, profile, response.Retval)
	}
	v.log.Debugf("set IKEv2 ID %t for profile %s", isLocal, profile)
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
) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if len(profile) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}
	if startAddr.To4() == nil || endAddr.To4() == nil {
		return errors.New("IPv6 unsupported in IKEv2 at this time")
	}
	request := &ikev2.Ikev2ProfileSetTs{
		Name: profile,
		Ts: ikev2_types.Ikev2Ts{
			IsLocal:    isLocal,
			ProtocolID: proto,
			StartPort:  startPort,
			EndPort:    endPort,
			StartAddr:  types.ToVppAddress(startAddr),
			EndAddr:    types.ToVppAddress(endAddr),
		},
	}
	response := &ikev2.Ikev2ProfileSetTsReply{}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "failed to set IKEv2 traffic selector for profile %s", profile)
	} else if response.Retval != 0 {
		return fmt.Errorf("failed to set IKEv2 traffic selector for profile %s (retval %d)", profile, response.Retval)
	}
	v.log.Debugf("set traffic selector for profile %s", profile)
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
) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if len(profile) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}
	request := &ikev2.Ikev2SetEspTransforms{
		Name: profile,
		Tr: ikev2_types.Ikev2EspTransforms{
			CryptoAlg:     uint8(cryptoAlg),
			CryptoKeySize: cryptoKeySize,
			IntegAlg:      uint8(integAlg),
		},
	}
	response := &ikev2.Ikev2SetEspTransformsReply{}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "failed to set ESP transforms for profile %s", profile)
	} else if response.Retval != 0 {
		return fmt.Errorf("failed to set ESP transforms for profile %s (retval %d)", profile, response.Retval)
	}
	v.log.Debugf("set ESP transforms for profile %s", profile)
	return nil
}

func (v *VppLink) SetIKEv2IKETransforms(
	profile string,
	cryptoAlg IKEv2EncryptionAlgorithm,
	cryptoKeySize uint32,
	integAlg IKEv2IntegrityAlgorithm,
	dhGroup IKEv2DHGroup,
) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if len(profile) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}
	request := &ikev2.Ikev2SetIkeTransforms{
		Name: profile,
		Tr: ikev2_types.Ikev2IkeTransforms{
			CryptoAlg:     uint8(cryptoAlg),
			CryptoKeySize: cryptoKeySize,
			IntegAlg:      uint8(integAlg),
			DhGroup:       uint8(dhGroup),
		},
	}
	response := &ikev2.Ikev2SetIkeTransformsReply{}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "failed to set IKE transforms for profile %s", profile)
	} else if response.Retval != 0 {
		return fmt.Errorf("failed to set IKE transforms for profile %s (retval %d)", profile, response.Retval)
	}
	v.log.Debugf("set IKE transforms for profile %s", profile)
	return nil
}

func (v *VppLink) SetIKEv2DefaultTransforms(profile string) (err error) {
	err = v.SetIKEv2IKETransforms(
		profile,
		IKEv2EncryptionAlgorithmAES_CBC,
		256,
		IKEv2IntegrityAlgorithmAUTH_HMAC_SHA1_96,
		IKEv2DHGroupMODP_2048,
	)
	if err != nil {
		return err
	}
	return v.SetIKEv2ESPTransforms(
		profile,
		IKEv2EncryptionAlgorithmAES_GCM_16,
		256,
		IKEv2IntegrityAlgorithmNone,
	)
}

func (v *VppLink) SetIKEv2Responder(profile string, swIfIndex uint32, address net.IP) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if len(profile) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}
	if address.To4() == nil {
		return errors.New("IPv6 unsupported in IKEv2 at this time")
	}
	vppAddr := types.ToVppAddress(address)
	request := &ikev2.Ikev2SetResponder{
		Name: profile,
		Responder: ikev2_types.Ikev2Responder{
			SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
			Addr:      vppAddr,
		},
	}
	response := &ikev2.Ikev2SetResponderReply{}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "failed to set IKE responder for profile %s", profile)
	} else if response.Retval != 0 {
		return fmt.Errorf("failed to set IKE responder for profile %s (retval %d)", profile, response.Retval)
	}
	v.log.Debugf("set IKE responder for profile %s, interface %d addr %v", profile, swIfIndex, vppAddr)
	return nil
}

func (v *VppLink) SetIKEv2TunnelInterface(profile string, swIfIndex uint32) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if len(profile) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}
	request := &ikev2.Ikev2SetTunnelInterface{
		Name:      profile,
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	}
	response := &ikev2.Ikev2SetTunnelInterfaceReply{}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "failed to set IKE tunnel interface for profile %s", profile)
	} else if response.Retval != 0 {
		return fmt.Errorf("failed to set IKE tunnel interface for profile %s (retval %d)", profile, response.Retval)
	}
	v.log.Debugf("set IKE tunnel interface for profile %s", profile)
	return nil
}

func (v *VppLink) IKEv2Initiate(profile string) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	if len(profile) >= 64 {
		return errors.New("IKEv2 profile name too long (max 64)")
	}
	request := &ikev2.Ikev2InitiateSaInit{
		Name: profile,
	}
	response := &ikev2.Ikev2InitiateSaInitReply{}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "failed to initiate IKE for profile %s", profile)
	} else if response.Retval != 0 {
		return fmt.Errorf("failed to initiate IKE for profile %s (retval %d)", profile, response.Retval)
	}
	v.log.Debugf("initiated IKE for profile %s", profile)
	return nil
}
