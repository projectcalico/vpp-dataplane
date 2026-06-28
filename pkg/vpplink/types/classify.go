// Copyright (C) 2023 Cisco Systems Inc.
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
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

const InvalidTableID = ^uint32(0)

type IPv4Header struct {
	VersionIHL uint8
	Tos        uint8
	TotLen     uint16
	ID         uint16
	FragOff    uint16
	TTL        uint8
	Protocol   uint8
	Csum       uint16
	Saddr      [4]byte
	Daddr      [4]byte
}

type UDPHeader struct {
	Sport uint16
	Dport uint16
	Len   uint16
	Csum  uint16
}

type GeneveHeader struct {
	VersionOptLen uint8
	Flags         uint8
	ProtocolType  uint16
	Vni           uint32
	Options       []byte
}

func (h GeneveHeader) FixedBytes() []byte {
	buf := make([]byte, 0, 8)
	buf = append(buf, h.VersionOptLen, h.Flags)
	buf = binary.BigEndian.AppendUint16(buf, h.ProtocolType)
	buf = binary.BigEndian.AppendUint32(buf, h.Vni)
	return buf
}

type UDPv4Header struct {
	IP  IPv4Header
	UDP UDPHeader
}

func NewUDPv4Header(buffer []byte) (*UDPv4Header, error) {
	udpHdr := UDPv4Header{}
	reader := bytes.NewReader(buffer)
	err := binary.Read(reader, binary.BigEndian, &udpHdr)
	return &udpHdr, err
}

func (h UDPv4Header) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, h)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type GeneveV4Header struct {
	UDPv4Header
	GeneveHeader
}

func (gnv GeneveV4Header) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, gnv.UDPv4Header)
	if err != nil {
		return nil, err
	}
	buf.Write(gnv.FixedBytes())
	buf.Write(gnv.Options)
	return buf.Bytes(), nil
}

type TCPPorts struct {
	Sport uint16
	Dport uint16
}

type TCPv4Header struct {
	IP  IPv4Header
	TCP TCPPorts
}

func (h TCPv4Header) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, h)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var (
	FiveTupleMask     []byte
	DstFourTupleMask  []byte
	DstThreeTupleMask []byte
	SrcThreeTupleMask []byte
	DstAddrMask       []byte
	SrcAddrMask       []byte
)

type DstThreeTuple struct {
	Protocol IPProto
	DstAddr  netip.Addr
	DstPort  uint16
}

type FiveTuple struct {
	Protocol IPProto
	SrcAddr  netip.Addr
	SrcPort  uint16
	DstAddr  netip.Addr
	DstPort  uint16
}

func IPToAddr(a net.IP) netip.Addr {
	if a == nil {
		return netip.AddrFrom4([4]byte{0, 0, 0, 0})
	}
	if a.To4() == nil {
		addr, _ := netip.AddrFromSlice(a)
		return addr
	}
	addr, _ := netip.AddrFromSlice(a)
	return netip.AddrFrom4(addr.As4())
}

func New5Tuple(protocol IPProto, srcAddr net.IP, srcPort uint16, dstAddr net.IP, dstPort uint16) FiveTuple {
	return FiveTuple{
		Protocol: protocol,
		SrcPort:  srcPort, DstPort: dstPort,
		SrcAddr: IPToAddr(srcAddr), DstAddr: IPToAddr(dstAddr),
	}
}

func NewDst4Tuple(protocol IPProto, srcAddr net.IP, dstAddr net.IP, dstPort uint16) FiveTuple {
	return New5Tuple(protocol, srcAddr, 0, dstAddr, dstPort)
}

func NewDst3Tuple(protocol IPProto, dstAddr net.IP, dstPort uint16) FiveTuple {
	return New5Tuple(protocol, net.IPv4zero, 0, dstAddr, dstPort)
}

func NewSrc3Tuple(protocol IPProto, srcAddr net.IP, srcPort uint16) FiveTuple {
	return New5Tuple(protocol, srcAddr, srcPort, net.IPv4zero, 0)
}

func (tuple *FiveTuple) String() string {
	return fmt.Sprintf("%s,%s:%d->%s:%d", tuple.Protocol.String(),
		tuple.SrcAddr, tuple.SrcPort, tuple.DstAddr, tuple.DstPort)
}

func (tuple *FiveTuple) GetMatch() ([]byte, error) {
	var match UDPv4Header
	match.IP.Protocol = uint8(tuple.Protocol)
	match.IP.Saddr = tuple.SrcAddr.As4()
	match.IP.Daddr = tuple.DstAddr.As4()
	match.UDP.Sport = tuple.SrcPort
	match.UDP.Dport = tuple.DstPort
	matchBytes, err := match.Bytes()
	if err != nil {
		return nil, err
	}
	return matchBytes, nil
}

func (tuple *FiveTuple) GetMask() ([]byte, error) {
	var mask UDPv4Header

	if tuple.Protocol != IPProto(0) {
		mask.IP.Protocol = 0xff
	}
	if !tuple.SrcAddr.IsUnspecified() && tuple.SrcAddr.IsValid() {
		mask.IP.Saddr = [4]byte{0xff, 0xff, 0xff, 0xff}
	}
	if tuple.SrcPort != 0 {
		mask.UDP.Sport = 0xffff
	}
	if !tuple.DstAddr.IsUnspecified() && tuple.DstAddr.IsValid() {
		mask.IP.Daddr = [4]byte{0xff, 0xff, 0xff, 0xff}
	}
	if tuple.DstPort != 0 {
		mask.UDP.Dport = 0xffff
	}
	maskBytes, err := mask.Bytes()
	if err != nil {
		return nil, err
	}
	return maskBytes, nil
}

func (tuple *FiveTuple) GetBPF() string {
	expressions := make([]string, 0, 4)
	if !tuple.SrcAddr.IsUnspecified() && tuple.SrcAddr.IsValid() {
		expressions = append(expressions, fmt.Sprintf("src host %s", tuple.SrcAddr))
	}
	if !tuple.DstAddr.IsUnspecified() && tuple.DstAddr.IsValid() {
		expressions = append(expressions, fmt.Sprintf("dst host %s", tuple.DstAddr))
	}
	if tuple.SrcPort != 0 {
		expressions = append(expressions, fmt.Sprintf("src port %d", tuple.SrcPort))
	}
	if tuple.DstPort != 0 {
		expressions = append(expressions, fmt.Sprintf("dst port %d", tuple.DstPort))
	}
	return strings.Join(expressions, " and ")
}

func NewGeneveHeader(outerFiveTuple FiveTuple, vni uint32) GeneveV4Header {
	return GeneveV4Header{
		UDPv4Header{
			IP:  IPv4Header{Protocol: uint8(UDP), Saddr: outerFiveTuple.SrcAddr.As4(), Daddr: outerFiveTuple.DstAddr.As4()},
			UDP: UDPHeader{Sport: outerFiveTuple.SrcPort, Dport: outerFiveTuple.DstPort},
		},
		GeneveHeader{
			Vni: vni << 8,
		},
	}
}

func (gnv *GeneveV4Header) GetMatch() ([]byte, error) {
	matchBytes, err := gnv.Bytes()
	if err != nil {
		return nil, err
	}
	return matchBytes, nil
}

func (gnv *GeneveV4Header) GetMask() ([]byte, error) {
	var mask GeneveV4Header
	srcIP := netip.AddrFrom4(gnv.IP.Saddr)
	dstIP := netip.AddrFrom4(gnv.IP.Daddr)

	if gnv.IP.Protocol != 0 {
		mask.IP.Protocol = 0xff
	}
	if !srcIP.IsUnspecified() && srcIP.IsValid() {
		mask.IP.Saddr = [4]byte{0xff, 0xff, 0xff, 0xff}
	}
	if gnv.UDP.Sport != 0 {
		mask.UDP.Sport = 0xffff
	}
	if !dstIP.IsUnspecified() && dstIP.IsValid() {
		mask.IP.Daddr = [4]byte{0xff, 0xff, 0xff, 0xff}
	}
	if gnv.UDP.Dport != 0 {
		mask.UDP.Dport = 0xffff
	}
	// if vni != INVALID_ID<<8
	if gnv.Vni != 0xffffff00 {
		mask.Vni = 0xffffff00
	}
	maskBytes, err := mask.Bytes()
	if err != nil {
		return nil, err
	}
	return maskBytes, nil
}

func init() {
	var err error
	FiveTupleMask, err = (UDPv4Header{
		IP: IPv4Header{
			Protocol: 0xff,
			Saddr:    [4]byte{0xff, 0xff, 0xff, 0xff},
			Daddr:    [4]byte{0xff, 0xff, 0xff, 0xff},
		},
		UDP: UDPHeader{
			Sport: 0xffff,
			Dport: 0xffff,
		},
	}).Bytes()
	if err != nil {
		panic(err)
	}

	DstFourTupleMask, err = (UDPv4Header{
		IP: IPv4Header{
			Protocol: 0xff,
			Saddr:    [4]byte{0xff, 0xff, 0xff, 0xff},
			Daddr:    [4]byte{0xff, 0xff, 0xff, 0xff},
		},
		UDP: UDPHeader{
			Dport: 0xffff,
		},
	}).Bytes()
	if err != nil {
		panic(err)
	}

	DstThreeTupleMask, err = (UDPv4Header{
		IP:  IPv4Header{Protocol: 0xff, Daddr: [4]byte{0xff, 0xff, 0xff, 0xff}},
		UDP: UDPHeader{Dport: 0xffff},
	}).Bytes()
	if err != nil {
		panic(err)
	}

	SrcThreeTupleMask, err = (UDPv4Header{
		IP:  IPv4Header{Protocol: 0xff, Saddr: [4]byte{0xff, 0xff, 0xff, 0xff}},
		UDP: UDPHeader{Sport: 0xffff},
	}).Bytes()
	if err != nil {
		panic(err)
	}

	DstAddrMask, err = (UDPv4Header{
		IP: IPv4Header{Daddr: [4]byte{0xff, 0xff, 0xff, 0xff}},
	}).Bytes()
	if err != nil {
		panic(err)
	}

	SrcAddrMask, err = (UDPv4Header{
		IP: IPv4Header{Saddr: [4]byte{0xff, 0xff, 0xff, 0xff}},
	}).Bytes()
	if err != nil {
		panic(err)
	}
}

type ClassifyAction int

const (
	AddAbsolute ClassifyAction = iota
	AddRelative
	Del
	DelChain
)

const (
	VectorSize = 16
)

type ClassifyTable struct {
	TableIndex        uint32
	NBuckets          uint32
	MaxNumEntries     uint32
	MatchNVectors     uint32
	SkipNVectors      uint32
	NextTableIndex    uint32
	MissNextIndex     uint32
	Mask              []byte
	MemorySize        uint32
	CurrentDataOffset int16
}
