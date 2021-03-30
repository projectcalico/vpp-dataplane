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

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip6_nd"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
	log "github.com/sirupsen/logrus"
)

func (v *VppLink) DisableIP6RouterAdvertisements(swIfIndex uint32) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &ip6_nd.SwInterfaceIP6ndRaConfigReply{}
	request := &ip6_nd.SwInterfaceIP6ndRaConfig{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Suppress:  1,
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Disabling RA for swif %d failed", swIfIndex)
	} else if response.Retval != 0 {
		return fmt.Errorf("Disabling RA for swif %d failed with retval %d", swIfIndex, response.Retval)
	}
	return nil
}

func (v *VppLink) EnableIP6NdProxy(swIfIndex uint32) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	log.Errorf("EnableIP6NdProxy fixme")

	response := &ip6_nd.IP6ndProxyAddDelReply{}
	request := &ip6_nd.IP6ndProxyAddDel{
		IsAdd:     true,
		IP:        ip_types.IP6Address{}, // FIXME
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	}
	err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Enabling IP6 ND Proxy swif %d failed", swIfIndex)
	} else if response.Retval != 0 {
		return fmt.Errorf("Enabling IP6 ND Proxy swif %d failed with retval %d", swIfIndex, response.Retval)
	}
	return nil
}
