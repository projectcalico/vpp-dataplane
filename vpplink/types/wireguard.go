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

package types

import (
	"bytes"
	"fmt"
	"net"
	"strings"
)

type WireguardTunnel struct {
	Addr       net.IP
	Port       uint16
	SwIfIndex  uint32
	PublicKey  []byte
	PrivateKey []byte
}

func (t *WireguardTunnel) String() string {
	return fmt.Sprintf("[%d] %s:%d", t.SwIfIndex, t.Addr, t.Port)
}

type WireguardPeer struct {
	PublicKey           []byte
	Port                uint16
	PersistentKeepalive int
	TableID             uint32
	Addr                net.IP
	SwIfIndex           uint32
	Index               uint32
	AllowedIps          []net.IPNet
}

func (t *WireguardPeer) allowedIpsMap() map[string]bool {
	m := make(map[string]bool)
	for _, aip := range t.AllowedIps {
		m[aip.String()] = true
	}
	return m
}

func (t *WireguardPeer) Equal(o *WireguardPeer) bool {
	if o == nil {
		return false
	}
	if !bytes.Equal(o.PublicKey, t.PublicKey) {
		return false
	}
	if o.Port != t.Port {
		return false
	}
	if o.TableID != t.TableID {
		return false
	}
	if o.SwIfIndex != t.SwIfIndex {
		return false
	}
	if !o.Addr.Equal(t.Addr) {
		return false
	}
	if o.PersistentKeepalive != t.PersistentKeepalive {
		return false
	}
	if len(t.AllowedIps) != len(o.AllowedIps) {
		return false
	}
	/* AllowedIps should be unique */
	m := t.allowedIpsMap()
	for _, aip := range o.AllowedIps {
		if _, found := m[aip.String()]; !found {
			return false
		}
	}
	return false

}

func (t *WireguardPeer) AddAllowedIp(addr net.IPNet) {
	m := t.allowedIpsMap()
	if _, found := m[addr.String()]; !found {
		t.AllowedIps = append(t.AllowedIps, addr)
	}
}

func (t *WireguardPeer) DelAllowedIp(addr net.IPNet) {
	allowedIps := make([]net.IPNet, 0)
	for _, aip := range t.AllowedIps {
		if aip.String() != addr.String() {
			allowedIps = append(allowedIps, aip)
		}
	}
	t.AllowedIps = allowedIps
}

func (t *WireguardPeer) String() string {
	s := fmt.Sprintf("peer %d [%d] %s:%d ", t.Index, t.SwIfIndex, t.Addr, t.Port)

	aips := make([]string, 0)
	for _, aip := range t.AllowedIps {
		aips = append(aips, aip.String())
	}
	s = fmt.Sprintf("%s [%s]", s, strings.Join(aips, ","))

	if t.TableID != 0 {
		return fmt.Sprintf("%s tbl:%d", s, t.TableID)
	}
	if t.PersistentKeepalive != 1 {
		return fmt.Sprintf("%s ka:%d", s, t.PersistentKeepalive)
	}
	return s
}
