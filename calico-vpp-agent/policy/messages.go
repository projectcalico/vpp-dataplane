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
	"bytes"
	"encoding/binary"
	"io"
	"net"

	pb "github.com/gogo/protobuf/proto"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/policy/proto"
)

func (s *Server) RecvMessage(conn net.Conn) (msg interface{}, err error) {
	buf := make([]byte, 8)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return
	}
	length := binary.LittleEndian.Uint64(buf)

	data := make([]byte, length)
	_, err = io.ReadFull(conn, data)
	if err != nil {
		return
	}

	envelope := proto.ToDataplane{}
	err = pb.Unmarshal(data, &envelope)
	if err != nil {
		return
	}
	s.log.WithField("envelope", envelope).Debug("Received message from dataplane.")

	switch payload := envelope.Payload.(type) {
	case *proto.ToDataplane_ConfigUpdate:
		msg = payload.ConfigUpdate
	case *proto.ToDataplane_InSync:
		msg = payload.InSync
	case *proto.ToDataplane_IpsetUpdate:
		msg = payload.IpsetUpdate
	case *proto.ToDataplane_IpsetDeltaUpdate:
		msg = payload.IpsetDeltaUpdate
	case *proto.ToDataplane_IpsetRemove:
		msg = payload.IpsetRemove
	case *proto.ToDataplane_ActivePolicyUpdate:
		msg = payload.ActivePolicyUpdate
	case *proto.ToDataplane_ActivePolicyRemove:
		msg = payload.ActivePolicyRemove
	case *proto.ToDataplane_ActiveProfileUpdate:
		msg = payload.ActiveProfileUpdate
	case *proto.ToDataplane_ActiveProfileRemove:
		msg = payload.ActiveProfileRemove
	case *proto.ToDataplane_HostEndpointUpdate:
		msg = payload.HostEndpointUpdate
	case *proto.ToDataplane_HostEndpointRemove:
		msg = payload.HostEndpointRemove
	case *proto.ToDataplane_WorkloadEndpointUpdate:
		msg = payload.WorkloadEndpointUpdate
	case *proto.ToDataplane_WorkloadEndpointRemove:
		msg = payload.WorkloadEndpointRemove
	case *proto.ToDataplane_HostMetadataUpdate:
		msg = payload.HostMetadataUpdate
	case *proto.ToDataplane_HostMetadataRemove:
		msg = payload.HostMetadataRemove
	case *proto.ToDataplane_IpamPoolUpdate:
		msg = payload.IpamPoolUpdate
	case *proto.ToDataplane_IpamPoolRemove:
		msg = payload.IpamPoolRemove
	case *proto.ToDataplane_ServiceAccountUpdate:
		msg = payload.ServiceAccountUpdate
	case *proto.ToDataplane_ServiceAccountRemove:
		msg = payload.ServiceAccountRemove
	case *proto.ToDataplane_NamespaceUpdate:
		msg = payload.NamespaceUpdate
	case *proto.ToDataplane_NamespaceRemove:
		msg = payload.NamespaceRemove

	default:
		s.log.WithField("payload", payload).Warn("Ignoring unknown message from felix")
	}

	return
}

func (s *Server) SendMessage(conn net.Conn, msg interface{}) (err error) {
	s.log.Debugf("Writing msg (%v) to felix: %#v", s.nextSeqNumber, msg)
	// Wrap the payload message in an envelope so that protobuf takes care of deserialising
	// it as the correct type.
	envelope := &proto.FromDataplane{
		SequenceNumber: s.nextSeqNumber,
	}
	s.nextSeqNumber++
	switch msg := msg.(type) {
	case *proto.ProcessStatusUpdate:
		envelope.Payload = &proto.FromDataplane_ProcessStatusUpdate{ProcessStatusUpdate: msg}
	case *proto.WorkloadEndpointStatusUpdate:
		envelope.Payload = &proto.FromDataplane_WorkloadEndpointStatusUpdate{WorkloadEndpointStatusUpdate: msg}
	case *proto.WorkloadEndpointStatusRemove:
		envelope.Payload = &proto.FromDataplane_WorkloadEndpointStatusRemove{WorkloadEndpointStatusRemove: msg}
	case *proto.HostEndpointStatusUpdate:
		envelope.Payload = &proto.FromDataplane_HostEndpointStatusUpdate{HostEndpointStatusUpdate: msg}
	case *proto.HostEndpointStatusRemove:
		envelope.Payload = &proto.FromDataplane_HostEndpointStatusRemove{HostEndpointStatusRemove: msg}
	case *proto.WireguardStatusUpdate:
		envelope.Payload = &proto.FromDataplane_WireguardStatusUpdate{WireguardStatusUpdate: msg}
	default:
		s.log.WithField("msg", msg).Panic("Unknown message type")
	}
	data, err := pb.Marshal(envelope)

	if err != nil {
		s.log.WithError(err).WithField("msg", msg).Panic(
			"Failed to marshal data")
	}

	lengthBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lengthBytes, uint64(len(data)))
	var messageBuf bytes.Buffer
	messageBuf.Write(lengthBytes)
	messageBuf.Write(data)
	for {
		_, err := messageBuf.WriteTo(conn)
		if err == io.ErrShortWrite {
			s.log.Warn("Short write to felix; buffer full?")
			continue
		}
		if err != nil {
			return err
		}
		s.log.Debug("Wrote message to felix")
		break
	}
	return nil
}
