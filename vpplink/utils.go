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

package vpplink

type IDPool struct {
	freeList  []uint32
	maxFreeID uint32
}

var (
	idPools map[string]IDPool = make(map[string]IDPool)
)

func AllocateID(namespace string) (index uint32) {
	idPool, ok := idPools[namespace]
	if !ok {
		idPools[namespace] = IDPool{
			freeList:  make([]uint32, 0),
			maxFreeID: 1,
		}
		idPool = idPools[namespace]
	}
	n := len(idPool.freeList)
	if n == 0 {
		index = idPool.maxFreeID
		idPool.maxFreeID = idPool.maxFreeID + 1
	} else {
		index = idPool.freeList[n-1]
		idPool.freeList = idPool.freeList[:n-1]
	}
	return index
}

func FreeID(namespace string, index uint32) {
	idPool, ok := idPools[namespace]
	if !ok {
		return
	}
	idPool.freeList = append(idPool.freeList, index)
}
