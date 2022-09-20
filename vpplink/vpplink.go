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
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.fd.io/govpp"
	vppapi "go.fd.io/govpp/api"
	vppcore "go.fd.io/govpp/core"
)

const (
	DefaultReplyTimeout = 1 * time.Second
)

type VppLink struct {
	lock                   sync.Mutex
	conn                   *vppcore.Connection
	ch                     vppapi.Channel
	socket                 string
	log                    logrus.FieldLogger
	pid                    uint32
	watcherLock            sync.Mutex
	interfaceEventWatchers []*interfaceEventWatcher
	stopEvents             func() error
}

func (v *VppLink) GetChannel() (vppapi.Channel, error) {
	return v.conn.NewAPIChannel()
}

func NewVppLink(socket string, logger logrus.FieldLogger) (*VppLink, error) {
	conn, err := govpp.Connect(socket)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot connect to VPP on socket %s", socket)
	}

	ch, err := conn.NewAPIChannel()
	if err != nil {
		return nil, errors.Wrap(err, "channel creation failed")
	}

	vppLink := &VppLink{
		conn:   conn,
		ch:     ch,
		socket: socket,
		log:    logger,
		pid:    uint32(os.Getpid()),
	}

	stopEvents, err := vppLink.watchInterfaceEvents()
	if err != nil {
		vppLink.log.Warnf("error watching interface events: %v", err)
	} else {
		vppLink.stopEvents = stopEvents
	}

	return vppLink, nil
}

func (v *VppLink) Reconnect() (err error) {
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

func (v *VppLink) Close() {
	if v == nil {
		return
	}
	if v.stopEvents != nil {
		_ = v.stopEvents()
	}
	if v.ch != nil {
		v.ch.Close()
	}
	if v.conn != nil {
		v.conn.Disconnect()
	}
}
