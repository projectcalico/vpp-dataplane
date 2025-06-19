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

import (
	"fmt"
	"sync"
)

type IndexAllocator struct {
	freeIndexList []uint32
	startID       uint32
	maxFreeID     uint32
	lock          sync.Mutex
}

func NewIndexAllocator(startID uint32) *IndexAllocator {
	return &IndexAllocator{
		freeIndexList: make([]uint32, 0),
		startID:       startID,
		maxFreeID:     startID,
	}
}

func (i *IndexAllocator) AllocateIndex() (index uint32) {
	i.lock.Lock()
	defer i.lock.Unlock()

	n := len(i.freeIndexList)
	if n == 0 {
		index = i.maxFreeID
		i.maxFreeID = i.maxFreeID + 1
	} else {
		index = i.freeIndexList[n-1]
		i.freeIndexList = i.freeIndexList[:n-1]
	}
	return index
}

func (i *IndexAllocator) TakeIndex(index uint32) error {
	i.lock.Lock()
	defer i.lock.Unlock()

	if index < i.startID {
		return fmt.Errorf("index %d lower than minimal index %d", index, i.startID)
	}

	if index >= i.maxFreeID {
		for ii := i.maxFreeID; ii <= index; ii++ {
			i.freeIndexList = append(i.freeIndexList, ii)
		}
		i.maxFreeID = index + 1
		return nil
	}

	found := -1
	for ii, freeIndex := range i.freeIndexList {
		if freeIndex == index {
			found = ii
			break
		}
	}

	if found == -1 {
		return fmt.Errorf("index %d not in freelist", index)
	}

	i.freeIndexList = append(i.freeIndexList[:found], i.freeIndexList[found+1:]...)
	return nil
}

func (i *IndexAllocator) FreeIndex(index uint32) {
	i.lock.Lock()
	defer i.lock.Unlock()

	i.freeIndexList = append(i.freeIndexList, index)
}
