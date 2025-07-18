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
	"net"
	"reflect"
	"time"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
)

type IPFamily struct {
	Str       string
	ShortStr  string
	IsIP6     bool
	IsIP4     bool
	FamilyIdx int
}

var (
	IPFamilyV4 = IPFamily{"ip4", "4", false, true, 0}
	IPFamilyV6 = IPFamily{"ip6", "6", true, false, 1}
	IPFamilies = []IPFamily{IPFamilyV4, IPFamilyV6}
)

func IPFamilyFromIPNet(ipNet *net.IPNet) IPFamily {
	if ipNet == nil {
		return IPFamilyV4
	}
	if ipNet.IP.To4() == nil {
		return IPFamilyV6
	}
	return IPFamilyV4
}

type CleanupCall struct {
	args []interface{}
	f    interface{}
}

func (call *CleanupCall) Execute() {
	var vargs []reflect.Value
	for _, a := range call.args {
		vargs = append(vargs, reflect.ValueOf(a))
	}
	ret := reflect.ValueOf(call.f).Call(vargs)
	if len(ret) != 1 {
		return
	}
	/* If only one value is returned, we assume this is an error and log it */
	if !ret[0].IsNil() {
		err, ok := ret[0].Interface().(error)
		log.Errorf("Cleanup errored : %s, %t", err, ok)
	}
}

type CleanupStack struct {
	calls []CleanupCall
}

func (stack *CleanupStack) Execute() {
	for i := len(stack.calls) - 1; i >= 0; i-- {
		stack.calls[i].Execute()
	}
}

func (stack *CleanupStack) Push(f interface{}, args ...interface{}) {
	stack.calls = append(stack.calls, CleanupCall{
		f:    f,
		args: args,
	})
}

func (v *VppLink) NewCleanupStack() *CleanupStack {
	return &CleanupStack{
		calls: make([]CleanupCall, 0),
	}
}

func (v *VppLink) Retry(sleepBtwRetries time.Duration, retries int, f interface{}, args ...interface{}) (err error) {
	var vargs []reflect.Value
	for _, a := range args {
		vargs = append(vargs, reflect.ValueOf(a))
	}
	for i := 0; i < retries; i++ {
		ret := reflect.ValueOf(f).Call(vargs)[0]
		if !ret.IsNil() {
			err, ok := ret.Interface().(error)
			log.Warnf("Try [%d] errored : %s, %t", i, err, ok)
			time.Sleep(sleepBtwRetries)
		} else {
			return nil
		}
	}
	return errors.Errorf("Still error after %d tries", retries)
}

func BoolToU8(b bool) uint8 {
	if b {
		return 1
	} else {
		return 0
	}
}

func IsAddToStr(isAdd bool) string {
	if isAdd {
		return "add"
	} else {
		return "delete"
	}
}
