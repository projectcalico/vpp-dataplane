// Copyright (C) 2020 Cisco Systems Inc.
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

package policy

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/policy/proto"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
)

type IPSet struct {
	VppID     uint32
	Type      types.IpsetType
	IPPorts   []types.IPPort
	Addresses []net.IP
	Networks  []*net.IPNet
}

var protos = map[string]uint8{
	"tcp":  6,
	"udp":  17,
	"sctp": 132,
}

func parseIPPort(ipps string) (ipp types.IPPort, err error) {
	sarray := strings.Split(ipps, ",") // Get host, and proto:port
	if len(sarray) != 2 {
		return ipp, fmt.Errorf("Cannot parse IPPort: %s", ipps)
	}
	addr := sarray[0]
	sarray = strings.Split(sarray[1], ":") // Get proto and port
	if len(sarray) != 2 {
		return ipp, fmt.Errorf("Cannot parse IPPort 2: %s", ipps)
	}
	port, err := strconv.ParseUint(sarray[1], 10, 16)
	if err != nil {
		return ipp, fmt.Errorf("Cannot parse IPPort port: %s", ipps)
	}
	ipp = types.IPPort{
		Addr:    net.ParseIP(addr),
		L4Proto: protos[sarray[0]],
		Port:    uint16(port),
	}
	if ipp.Addr == nil || ipp.L4Proto == 0 {
		return ipp, fmt.Errorf("Cannot parse IPPort address or proto: %s", ipps)
	}
	return ipp, nil
}

func parseIPArray(strs []string) (addrs []net.IP, err error) {
	addrs = make([]net.IP, 0, len(strs))
	for _, addr := range strs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, fmt.Errorf("Cannot parse IP: %s", addr)
		}
		addrs = append(addrs, ip)
	}
	return addrs, nil
}

func parseIPPortArray(strs []string) (ipps []types.IPPort, err error) {
	ipps = make([]types.IPPort, 0, len(strs))
	for _, s := range strs {
		ipp, err := parseIPPort(s)
		if err != nil {
			return nil, err
		}
		ipps = append(ipps, ipp)
	}
	return ipps, nil
}

func parseNetArray(strs []string) (nets []*net.IPNet, err error) {
	nets = make([]*net.IPNet, 0, len(strs))
	for _, n := range strs {
		_, cidr, err := net.ParseCIDR(n)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot parse CIDR: %s", n)
		}
		nets = append(nets, cidr)
	}
	return nets, nil
}

func fromIPSetUpdate(ips *proto.IPSetUpdate) (i *IPSet, err error) {
	switch ips.GetType() {
	case proto.IPSetUpdate_IP:
		i.Type = types.IpsetTypeIP
		i.Addresses, err = parseIPArray(ips.GetMembers())
	case proto.IPSetUpdate_IP_AND_PORT:
		i.Type = types.IpsetTypeIPPort
		i.IPPorts, err = parseIPPortArray(ips.GetMembers())
	case proto.IPSetUpdate_NET:
		i.Type = types.IpsetTypeNet
		i.Networks, err = parseNetArray(ips.GetMembers())
	}
	return i, err
}

func (i *IPSet) Create(vpp *vpplink.VppLink) (err error) {
	id, err := vpp.IpsetCreate(i.Type)
	if err != nil {
		return err
	}
	i.VppID = id
	switch i.Type {
	case types.IpsetTypeIP:
		err = vpp.AddIpsetIPMembers(i.VppID, i.Addresses)
	case types.IpsetTypeIPPort:
		err = vpp.AddIpsetIPPortMembers(i.VppID, i.IPPorts)
	case types.IpsetTypeNet:
		err = vpp.AddIpsetNetMembers(i.VppID, i.Networks)
	}
	return err
}

func (i *IPSet) Delete(vpp *vpplink.VppLink) (err error) {
	err = vpp.IpsetDelete(i.VppID)
	if err != nil {
		return err
	}
	i.VppID = types.InvalidID
	return nil
}

func (i *IPSet) AddMembers(members []string, apply bool, vpp *vpplink.VppLink) (err error) {
	switch i.Type {
	case types.IpsetTypeIP:
		addrs, err := parseIPArray(members)
		if err != nil {
			return err
		}
		if apply {
			err = vpp.AddIpsetIPMembers(i.VppID, addrs)
			if err != nil {
				return err
			}
		}
		i.Addresses = append(i.Addresses, addrs...)
	case types.IpsetTypeIPPort:
		ipps, err := parseIPPortArray(members)
		if err != nil {
			return err
		}
		if apply {
			err = vpp.AddIpsetIPPortMembers(i.VppID, ipps)
			if err != nil {
				return err
			}
		}
		i.IPPorts = append(i.IPPorts, ipps...)
	case types.IpsetTypeNet:
		nets, err := parseNetArray(members)
		if err != nil {
			return err
		}
		if apply {
			err = vpp.AddIpsetNetMembers(i.VppID, nets)
			if err != nil {
				return err
			}
		}
		i.Networks = append(i.Networks, nets...)
	}
	return err
}

func (i *IPSet) RemoveMembers(members []string, apply bool, vpp *vpplink.VppLink) (err error) {
	switch i.Type {
	case types.IpsetTypeIP:
		addrs, err := parseIPArray(members)
		if err != nil {
			return err
		}
		if apply {
			err = vpp.DelIpsetIPMembers(i.VppID, addrs)
			if err != nil {
				return err
			}
		}
		for j := 0; j < len(i.Addresses); j++ {
			for _, r := range addrs {
				if i.Addresses[j].Equal(r) {
					i.Addresses[j] = i.Addresses[len(i.Addresses)-1]
					i.Addresses = i.Addresses[:len(i.Addresses)-1]
				}
			}
		}
	case types.IpsetTypeIPPort:
		ipps, err := parseIPPortArray(members)
		if err != nil {
			return err
		}
		if apply {
			err = vpp.DelIpsetIPPortMembers(i.VppID, ipps)
			if err != nil {
				return err
			}
		}
		for j := 0; j < len(i.IPPorts); j++ {
			for _, r := range ipps {
				if i.IPPorts[j].Equal(&r) {
					i.IPPorts[j] = i.IPPorts[len(i.IPPorts)-1]
					i.IPPorts = i.IPPorts[:len(i.IPPorts)-1]
				}
			}
		}
	case types.IpsetTypeNet:
		nets, err := parseNetArray(members)
		if err != nil {
			return err
		}
		if apply {
			err = vpp.DelIpsetNetMembers(i.VppID, nets)
			if err != nil {
				return err
			}
		}
		for j := 0; j < len(i.Networks); j++ {
			for _, r := range nets {
				if i.Networks[j] == r {
					i.Networks[j] = i.Networks[len(i.Networks)-1]
					i.Networks = i.Networks[:len(i.Networks)-1]
				}
			}
		}
	}
	return err
}
