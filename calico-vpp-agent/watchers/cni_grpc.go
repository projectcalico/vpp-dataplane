// Copyright (C) 2025 Cisco Systems Inc.
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

package watchers

import (
	"context"
	gerrors "errors"
	"net"
	"os"
	"syscall"

	"github.com/pkg/errors"
	cniproto "github.com/projectcalico/calico/cni-plugin/pkg/dataplane/grpc/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/felix/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/config"
)

type CNIServer struct {
	cniproto.UnimplementedCniDataplaneServer
	log        *logrus.Entry
	grpcServer *grpc.Server
	eventChan  chan any
}

// Serve runs the grpc server for the Calico CNI backend API
func NewCNIServer(eventChan chan any, log *logrus.Entry) *CNIServer {
	return &CNIServer{
		log:        log,
		grpcServer: grpc.NewServer(),
		eventChan:  eventChan,
	}
}

func (s *CNIServer) ServeCNI(t *tomb.Tomb) error {
	err := syscall.Unlink(config.CNIServerSocket)
	if err != nil && !gerrors.Is(err, os.ErrNotExist) {
		s.log.Warnf("unable to unlink cni server socket: %+v", err)
	}

	defer func() {
		err = syscall.Unlink(config.CNIServerSocket)
		if err != nil {
			s.log.Errorf("error cleaning up CNIServerSocket %s", err)
		}
	}()

	socketListener, err := net.Listen("unix", config.CNIServerSocket)
	if err != nil {
		return errors.Wrapf(err, "failed to listen on %s", config.CNIServerSocket)
	}

	cniproto.RegisterCniDataplaneServer(s.grpcServer, s)

	s.log.Infof("Serving CNI grpc")
	err = s.grpcServer.Serve(socketListener)
	s.log.Infof("CNI Server returned")
	return err
}

func (s *CNIServer) Del(ctx context.Context, request *cniproto.DelRequest) (*cniproto.DelReply, error) {
	podSpecKey := model.LocalPodSpecKey(request.GetNetns(), request.GetInterfaceName())
	// Only try to delete the device if a namespace was passed in.
	if request.GetNetns() == "" {
		s.log.Debugf("no netns passed, skipping")
		return &cniproto.DelReply{
			Successful: true,
		}, nil
	}
	evt := model.NewCniPodDelEvent(podSpecKey)
	s.eventChan <- evt

	return <-evt.Done, nil
}

func (s *CNIServer) Add(ctx context.Context, request *cniproto.AddRequest) (*cniproto.AddReply, error) {
	/* We don't support request.GetDesiredHostInterfaceName() */
	podSpec, err := model.NewLocalPodSpecFromAdd(request)
	if err != nil {
		s.log.Errorf("Error parsing interface add request %v %v", request, err)
		return &cniproto.AddReply{
			Successful:   false,
			ErrorMessage: err.Error(),
		}, nil
	}

	evt := model.NewCniPodAddEvent(podSpec)
	s.eventChan <- evt

	return <-evt.Done, nil
}

func (s *CNIServer) GracefulStop() {
	s.grpcServer.GracefulStop()
}
