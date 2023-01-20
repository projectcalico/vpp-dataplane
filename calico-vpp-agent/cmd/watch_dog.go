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

package main

import (
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

var (
	felixConfigReceived bool
	bgpSpecReceived     bool
	agentStarted        bool
)

type WatchDog struct {
	log *logrus.Entry
}

func NewWatchDog(log *logrus.Entry) *WatchDog {
	return &WatchDog{
		log: log,
	}
}

func (wd *WatchDog) watch(t *tomb.Tomb) error {
	for !agentStarted {
		time.Sleep(time.Second * 5)
		if !felixConfigReceived {
			wd.log.Info("Felix Config not received, still waiting...")
		}
		if !bgpSpecReceived {
			wd.log.Info("BGP Spec not received, still waiting...")
		}
		if felixConfigReceived && bgpSpecReceived {
			wd.log.Info("AGENT STARTING...")
			agentStarted = true
		}
	}
	return nil
}
