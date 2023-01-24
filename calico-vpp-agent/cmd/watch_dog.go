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

type WatchDog struct {
	log *logrus.Entry
	t   *tomb.Tomb
}

func NewWatchDog(log *logrus.Entry, t *tomb.Tomb) *WatchDog {
	return &WatchDog{
		log: log,
		t:   t,
	}
}

func (wd *WatchDog) Wait(myChan chan interface{}, msg string) interface{} {
	ticker := time.NewTicker(time.Second * 5)
	nbTicks := 0
	defer ticker.Stop()
	for {
		select {
		case value := <-myChan:
			return value
		case <-wd.t.Dying():
			return nil
		case <-ticker.C:
			nbTicks++
			if nbTicks >= 6 { // Start warning after 6 ticks, i.e. 30sec
				wd.log.Warn(msg)
			} else {
				wd.log.Info(msg)
			}
		}
	}
}
