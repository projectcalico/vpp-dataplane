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
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/arp"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/interface_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
)

func (v *VppLink) EnableArpProxy(swIfIndex, tableID uint32) (err error) {
	v.Lock()
	defer v.Unlock()

	// First enable global arp proxy
	//set arp proxy table-id 0 start 0.0.0.0 end 255.255.255.255
	response1 := &arp.ProxyArpAddDelReply{}
	request1 := &arp.ProxyArpAddDel{
		IsAdd: true,
		Proxy: arp.ProxyArp{
			TableID: tableID,
			Low:     ip_types.IP4Address{0, 0, 0, 0},
			Hi:      ip_types.IP4Address{255, 255, 255, 255},
		},
	}
	err = v.GetChannel().SendRequest(request1).ReceiveReply(response1)
	if err != nil {
		return errors.Wrapf(err, "Enabling proxyarp swif %d failed", swIfIndex)
	} else if response1.Retval != 0 {
		return fmt.Errorf("Enabling proxyarp swif %d failed with retval %d", swIfIndex, response1.Retval)
	}

	response := &arp.ProxyArpIntfcEnableDisableReply{}
	request := &arp.ProxyArpIntfcEnableDisable{
		Enable:    true,
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	}
	err = v.GetChannel().SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrapf(err, "Enabling proxyarp swif %d failed", swIfIndex)
	} else if response.Retval != 0 {
		return fmt.Errorf("Enabling proxyarp swif %d failed with retval %d", swIfIndex, response.Retval)
	}
	return nil
}
