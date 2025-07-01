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

package calico

import (
	"context"
	"fmt"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// IPPoolsStub is stub implementation of clientv3.IPPoolInterface. It is used for managing IPPool resources.
type IPPoolsStub struct {
	ipPools map[string]*apiv3.IPPool
}

// NewIPPoolsStub creates new IPPoolsStub instance
func NewIPPoolsStub() *IPPoolsStub {
	return &IPPoolsStub{
		ipPools: make(map[string]*apiv3.IPPool),
	}
}

func (pools *IPPoolsStub) Create(ctx context.Context, res *apiv3.IPPool, opts options.SetOptions) (*apiv3.IPPool, error) {
	if res == nil {
		return nil, fmt.Errorf("ipPool can't be nil")
	}
	if res.Name == "" {
		return nil, fmt.Errorf("ipPool must have a name")
	}
	pools.ipPools[res.Name] = res
	return res, nil
}

func (pools *IPPoolsStub) Get(ctx context.Context, name string, opts options.GetOptions) (*apiv3.IPPool, error) {
	ipPool, found := pools.ipPools[name]
	if !found {
		return nil, fmt.Errorf("can't find IPPool with name %s", name)
	}
	return ipPool, nil
}

func (pools *IPPoolsStub) Update(ctx context.Context, res *apiv3.IPPool, opts options.SetOptions) (*apiv3.IPPool, error) {
	panic("not implemented")
}

func (pools *IPPoolsStub) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv3.IPPool, error) {
	panic("not implemented")
}

func (pools *IPPoolsStub) List(ctx context.Context, opts options.ListOptions) (*apiv3.IPPoolList, error) {
	panic("not implemented")
}

func (pools *IPPoolsStub) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	panic("not implemented")
}

func (pools *IPPoolsStub) UnsafeCreate(ctx context.Context, res *apiv3.IPPool, opts options.SetOptions) (*apiv3.IPPool, error) {
	panic("not implemented")
}

func (pools *IPPoolsStub) UnsafeDelete(ctx context.Context, name string, opts options.DeleteOptions) (*apiv3.IPPool, error) {
	panic("not implemented")
}
