// Copyright (c) 2022 Cisco and/or its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mocks

import (
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"gopkg.in/tomb.v2"
)

// PubSubHandlerMock is mocking the handlers registering to common.ThePubSub
type PubSubHandlerMock struct {
	eventChan          chan common.CalicoVppEvent
	ReceivedEvents     []common.CalicoVppEvent
	expectedEventTypes []common.CalicoVppEventType
	t                  tomb.Tomb
}

// NewPubSubHandlerMock creates new instance of PubSubHandlerMock
func NewPubSubHandlerMock(expectedEventTypes ...common.CalicoVppEventType) *PubSubHandlerMock {
	handler := &PubSubHandlerMock{
		eventChan:          make(chan common.CalicoVppEvent, common.ChanSize),
		ReceivedEvents:     make([]common.CalicoVppEvent, 0, 10),
		expectedEventTypes: expectedEventTypes,
	}
	return handler
}

// Start register this handler to common.ThePubSub and starts its handling loop in another go routing
func (m *PubSubHandlerMock) Start() {
	reg := common.RegisterHandler(m.eventChan, "Testing handler")
	reg.ExpectEvents(m.expectedEventTypes...)
	m.t.Go(m.receiveLoop)
}

// Stop does graceful shutdown of this handler
func (m *PubSubHandlerMock) Stop() error {
	m.t.Kill(nil)
	return m.t.Wait()
}

func (m *PubSubHandlerMock) receiveLoop() error {
	for {
		select {
		case <-m.t.Dying():
			close(m.eventChan)
			return nil
		case event := <-m.eventChan:
			m.ReceivedEvents = append(m.ReceivedEvents, event)
		}
	}
}
