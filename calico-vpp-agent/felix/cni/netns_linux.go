// Copyright (C) 2022 Cisco Systems Inc.
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

//go:build linux

package cni

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/vishvananda/netns"
)

func NetNsExec(netnsName string, cb func() error) (err error) {
	netnsCleanup, err := NsEnter(netnsName)
	defer netnsCleanup()
	if err != nil {
		return err
	}
	return cb()
}

// NsEnter switches the goroutine to the given netnsName
// and provides the cleanup function
func NsEnter(netnsName string) (cleanup func(), err error) {
	stack := make([]func(), 0)
	cleanup = func() {
		for i := len(stack) - 1; i >= 0; i-- {
			stack[i]()
		}
	}
	if netnsName == "" {
		return cleanup, nil
	}
	runtime.LockOSThread()
	stack = append(stack, runtime.UnlockOSThread)

	origns, _ := netns.Get()
	stack = append(stack, func() {
		err := origns.Close()
		if err != nil {
			fmt.Printf("Cannot close initial netns fd %s", err)
		}
	})

	var targetns netns.NsHandle
	if strings.HasPrefix(netnsName, "pid:") {
		pid, err := strconv.ParseInt((netnsName)[4:], 10, 32)
		if err != nil {
			return cleanup, err
		}
		targetns, err = netns.GetFromPid(int(pid))
		if err != nil {
			return cleanup, errors.Wrapf(err, "Cannot get %s netns from pid", netnsName)
		}
	} else {
		targetns, err = netns.GetFromName(netnsName)
		if err != nil {
			return cleanup, errors.Wrapf(err, "Cannot get %s netns", netnsName)
		}
	}

	stack = append(stack, func() {
		err := targetns.Close()
		if err != nil {
			fmt.Printf("Cannot close target netns fd %s", err)
		}
	})

	err = netns.Set(targetns)
	if err != nil {
		return cleanup, errors.Wrapf(err, "Cannot nsenter %s", netnsName)
	}
	stack = append(stack, func() {
		if err := netns.Set(origns); err != nil {
			fmt.Printf("Cannot nsenter initial netns %s", err)
		}
	})
	return cleanup, nil
}
