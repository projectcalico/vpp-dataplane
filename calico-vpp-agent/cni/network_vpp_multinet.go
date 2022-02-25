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

package cni

import (
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

type dummy struct {
	name string
}

func (d *dummy) Type() string {
	return "dummy"
}
func (d *dummy) Attrs() *netlink.LinkAttrs {
	return &netlink.LinkAttrs{Name: d.name}
}

func isMemif(ifName string) bool {
	return strings.HasPrefix(ifName, "memif")
}

func createDummy(netns string, interfaceName string) error {
	memifDummy := dummy{name: interfaceName}
	createDummyInNetns := func(netns ns.NetNS) error {
		err := netlink.LinkAdd(&memifDummy)
		if err != nil {
			return errors.Wrap(err, "unable to create dummy link in linux")
		}
		link, err := netlink.LinkByName(interfaceName)
		if err != nil {
			return errors.Wrap(err, "unable to retrieve name")
		}

		err = netlink.LinkSetUp(link)
		if err != nil {
			return errors.Wrap(err, "unable to set interface up")
		}
		return nil
	}
	err := ns.WithNetNSPath(netns, createDummyInNetns)
	if err != nil {
		return errors.Wrap(err, "unable to create dummy in netns")
	}
	return nil
}
