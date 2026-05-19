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
	"os"
	"sync"

	"context"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	govpp "go.fd.io/govpp"
	vppapi "go.fd.io/govpp/api"
	memclnt "go.fd.io/govpp/binapi/memclnt"
	vppcore "go.fd.io/govpp/core"
)

const (
	DefaultReplyTimeout = 1 * time.Second
)

// Vpp is the base struct that exposes all the methods defined
// by the various wrappers.
// Depending on the available APIs, this struct will implement
// the various interfaces defined in go.fd.io/govpp/api/v1
type Vpp struct {
	conn   *vppcore.Connection
	ch     vppapi.Channel
	socket string
	log    *logrus.Entry
	ctx    context.Context
	pid    *int
}

func (v *Vpp) GetLog() *logrus.Entry {
	return v.log
}

func (v *Vpp) GetContext() context.Context {
	return v.ctx
}

func (v *Vpp) GetConnection() vppapi.Connection {
	return v.conn
}

func getPid(ctx context.Context, conn *vppcore.Connection) *int {
	client := memclnt.NewServiceClient(conn)

	resp, err := client.ControlPing(ctx, &memclnt.ControlPing{})
	if err != nil {
		return nil
	}
	pid := int(resp.VpePID)
	return &pid
}

func NewVpp(socket string, logger *logrus.Entry) (*Vpp, error) {
	conn, err := govpp.Connect(socket)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot connect to VPP on socket %s", socket)
	}

	ch, err := conn.NewAPIChannel()
	if err != nil {
		return nil, errors.Wrap(err, "channel creation failed")
	}

	return &Vpp{
		conn:   conn,
		ch:     ch,
		socket: socket,
		log:    logger,
		ctx:    context.Background(),
		pid:    getPid(context.Background(), conn),
	}, nil
}

func (v *Vpp) Reconnect() (err error) {
	v.conn, err = govpp.Connect(v.socket)
	if err != nil {
		return errors.Wrapf(err, "cannot re-connect to VPP on socket %s", v.socket)
	}
	v.ch, err = v.conn.NewAPIChannel()
	if err != nil {
		return errors.Wrap(err, "channel re-creation failed")
	}
	return nil
}

func (v *Vpp) Close() error {
	if v == nil {
		return nil
	}
	if v.ch != nil {
		v.ch.Close()
	}
	if v.conn != nil {
		v.conn.Disconnect()
	}
	return nil
}

func (v *Vpp) SendSignal(signal syscall.Signal) error {
	if v.pid == nil {
		return errors.New("pid is not set")
	}
	pid := *v.pid
	process, err := os.FindProcess(pid) // Always succeeds on Unix systems
	if err != nil {
		return errors.Wrapf(err, "failed to find process with pid %d", pid)
	}
	if err := process.Signal(signal); err != nil {
		return errors.Wrapf(err, "failed to send signal %s to process with pid %d", signal, pid)
	}
	return nil
}

type VppLink struct {
	*Vpp
	pid                    uint32
	watcherLock            sync.Mutex
	interfaceEventWatchers []*interfaceEventWatcher
	stopEvents             func() error
}

func NewVppLink(socket string, logger *logrus.Entry) (*VppLink, error) {
	vpp, err := NewVpp(socket, logger)
	return &VppLink{Vpp: vpp, pid: uint32(os.Getpid())}, err
}
