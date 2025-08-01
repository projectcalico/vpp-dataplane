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

package felix

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectcalico/calico/felix/proto"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type IPSet struct {
	VppID     uint32
	Type      types.IpsetType
	IPPorts   map[string]types.IPPort
	Addresses map[string]net.IP
	Networks  map[string]*net.IPNet
}

func (i *IPSet) String() string {
	s := fmt.Sprintf("[vpp-id=%d ", i.VppID)

	switch i.Type {
	case types.IpsetTypeIP:
		s += fmt.Sprintf("addr=%s", i.Addresses)
	case types.IpsetTypeIPPort:
		s += fmt.Sprintf("ipport=%v", i.IPPorts)
	case types.IpsetTypeNet:
		s += fmt.Sprintf("net=%s", i.Networks)
	}

	s += "]"

	return s
}

var protos = map[string]uint8{
	"tcp":  6,
	"udp":  17,
	"sctp": 132,
}

func NewIPSet() *IPSet {
	return &IPSet{
		IPPorts:   make(map[string]types.IPPort),
		Addresses: make(map[string]net.IP),
		Networks:  make(map[string]*net.IPNet),
	}
}

func parseIPPort(ipps string) (ipp types.IPPort, err error) {
	sarray := strings.Split(ipps, ",") // Get host, and proto:port
	if len(sarray) != 2 {
		return ipp, fmt.Errorf("cannot parse IPPort: %s", ipps)
	}
	addr := sarray[0]
	sarray = strings.Split(sarray[1], ":") // Get proto and port
	if len(sarray) != 2 {
		return ipp, fmt.Errorf("cannot parse IPPort 2: %s", ipps)
	}
	port, err := strconv.ParseUint(sarray[1], 10, 16)
	if err != nil {
		return ipp, fmt.Errorf("cannot parse IPPort port: %s", ipps)
	}
	ipp = types.IPPort{
		Addr:    net.ParseIP(addr),
		L4Proto: protos[sarray[0]],
		Port:    uint16(port),
	}
	if ipp.Addr == nil || ipp.L4Proto == 0 {
		return ipp, fmt.Errorf("cannot parse IPPort address or proto: %s", ipps)
	}
	return ipp, nil
}

func parseIPArray(strs []string) (addrs map[string]net.IP, err error) {
	addrs = make(map[string]net.IP)
	for _, addr := range strs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, fmt.Errorf("cannot parse IP: %s", addr)
		}
		addrs[addr] = ip
	}
	return addrs, nil
}

func toAddressArray(addrs map[string]net.IP) []net.IP {
	array := make([]net.IP, 0, len(addrs))
	for _, v := range addrs {
		array = append(array, v)
	}
	return array
}

func parseIPPortArray(strs []string) (ipps map[string]types.IPPort, err error) {
	ipps = make(map[string]types.IPPort)
	for _, s := range strs {
		ipp, err := parseIPPort(s)
		if err != nil {
			return nil, err
		}
		ipps[s] = ipp
	}
	return ipps, nil
}

func toIPPortArray(addrs map[string]types.IPPort) []types.IPPort {
	array := make([]types.IPPort, 0, len(addrs))
	for _, v := range addrs {
		array = append(array, v)
	}
	return array
}

func parseNetArray(strs []string) (nets map[string]*net.IPNet, err error) {
	nets = make(map[string]*net.IPNet)
	for _, n := range strs {
		_, cidr, err := net.ParseCIDR(n)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot parse CIDR: %s", n)
		}
		nets[n] = cidr
	}
	return nets, nil
}

func toNetArray(addrs map[string]*net.IPNet) []*net.IPNet {
	array := make([]*net.IPNet, 0, len(addrs))
	for _, v := range addrs {
		array = append(array, v)
	}
	return array
}

func fromIPSetUpdate(ips *proto.IPSetUpdate) (i *IPSet, err error) {
	i = NewIPSet()
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
	logrus.Infof("Created ipset %d", i.VppID)
	switch i.Type {
	case types.IpsetTypeIP:
		err = vpp.AddIpsetIPMembers(i.VppID, toAddressArray(i.Addresses))
	case types.IpsetTypeIPPort:
		err = vpp.AddIpsetIPPortMembers(i.VppID, toIPPortArray(i.IPPorts))
	case types.IpsetTypeNet:
		err = vpp.AddIpsetNetMembers(i.VppID, toNetArray(i.Networks))
	}
	return err
}

func (i *IPSet) Delete(vpp *vpplink.VppLink) (err error) {
	logrus.Infof("policy(del) ipset %d", i.VppID)
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
			err = vpp.AddIpsetIPMembers(i.VppID, toAddressArray(addrs))
			if err != nil {
				return err
			}
		}
		for k, v := range addrs {
			i.Addresses[k] = v
		}
	case types.IpsetTypeIPPort:
		ipps, err := parseIPPortArray(members)
		if err != nil {
			return err
		}
		if apply {
			err = vpp.AddIpsetIPPortMembers(i.VppID, toIPPortArray(ipps))
			if err != nil {
				return err
			}
		}
		for k, v := range ipps {
			i.IPPorts[k] = v
		}
	case types.IpsetTypeNet:
		nets, err := parseNetArray(members)
		if err != nil {
			return err
		}
		if apply {
			err = vpp.AddIpsetNetMembers(i.VppID, toNetArray(nets))
			if err != nil {
				return err
			}
		}
		for k, v := range nets {
			i.Networks[k] = v
		}
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
			err = vpp.DelIpsetIPMembers(i.VppID, toAddressArray(addrs))
			if err != nil {
				return err
			}
		}
		for k := range addrs {
			delete(i.Addresses, k)
		}
	case types.IpsetTypeIPPort:
		ipps, err := parseIPPortArray(members)
		if err != nil {
			return err
		}
		if apply {
			err = vpp.DelIpsetIPPortMembers(i.VppID, toIPPortArray(ipps))
			if err != nil {
				return err
			}
		}
		for k := range ipps {
			delete(i.IPPorts, k)
		}
	case types.IpsetTypeNet:
		nets, err := parseNetArray(members)
		if err != nil {
			return err
		}
		if apply {
			err = vpp.DelIpsetNetMembers(i.VppID, toNetArray(nets))
			if err != nil {
				return err
			}
		}
		for k := range nets {
			delete(i.Networks, k)
		}
	}
	return err
}
