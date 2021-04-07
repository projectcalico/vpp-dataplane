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
	"fmt"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/crypto_sw_scheduler"
)

func (v *VppLink) SetCryptoWorker(workerIndex uint32, enable bool) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	response := &crypto_sw_scheduler.CryptoSwSchedulerSetWorkerReply{}
	request := &crypto_sw_scheduler.CryptoSwSchedulerSetWorker{
		WorkerIndex:  workerIndex,
		CryptoEnable: enable,
	}

	v.log.Infof("crypto_sw_scheduler : set crypto enable=%d, worker %d", enable, workerIndex)
	var err = v.ch.SendRequest(request).ReceiveReply(response)
	if err != nil {
		return errors.Wrap(err, "crypto_sw_scheduler setWorker enable failed")
	} else if response.Retval != 0 {
		return fmt.Errorf("crypto_sw_scheduler setWorker enable failed with retval: %d", response.Retval)
	}
	return nil
}
