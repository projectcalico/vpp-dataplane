// Copyright (C) 2021 Cisco Systems Inc.
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

package model

import (
	cniproto "github.com/projectcalico/calico/cni-plugin/pkg/dataplane/grpc/proto"
)

type CniPodDelEvent struct {
	PodSpecKey string
	Done       chan *cniproto.DelReply
}

func NewCniPodDelEvent(podSpecKey string) *CniPodDelEvent {
	return &CniPodDelEvent{
		PodSpecKey: podSpecKey,
		Done:       make(chan *cniproto.DelReply, 1),
	}
}

type CniPodAddEvent struct {
	PodSpec *LocalPodSpec
	Done    chan *cniproto.AddReply
}

func NewCniPodAddEvent(podSpec *LocalPodSpec) *CniPodAddEvent {
	return &CniPodAddEvent{
		PodSpec: podSpec,
		Done:    make(chan *cniproto.AddReply, 1),
	}
}
