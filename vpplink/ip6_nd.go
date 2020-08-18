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
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/20.09-rc0~214-g61309b2f8/ip6_nd"
)

func (v *VppLink) DisableIP6RouterAdvertisements(swIfIndex uint32) (err error) {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &ip6_nd.SwInterfaceIP6ndRaConfigReply{}
	request := &ip6_nd.SwInterfaceIP6ndRaConfig{
		SwIfIndex: ip6_nd.InterfaceIndex(swIfIndex),
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
