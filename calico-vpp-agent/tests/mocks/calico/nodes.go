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
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// NodesMock is mock implementation of clientv3.NodeInterface. It is used for managing Nodes resources.
type NodesMock struct {
	nodes map[string]*libapiv3.Node
}

// NewNodesMock creates new NodesMock instance
func NewNodesMock() *NodesMock {
	return &NodesMock{
		nodes: make(map[string]*libapiv3.Node),
	}
}

func (m *NodesMock) Create(ctx context.Context, res *libapiv3.Node, opts options.SetOptions) (*libapiv3.Node, error) {
	if res == nil {
		return nil, fmt.Errorf("node can't be nil")
	}
	if res.Name == "" {
		return nil, fmt.Errorf("node must have a name")
	}
	m.nodes[res.Name] = res
	return res, nil
}

func (m *NodesMock) Get(ctx context.Context, name string, opts options.GetOptions) (*libapiv3.Node, error) {
	node, found := m.nodes[name]
	if !found {
		return nil, fmt.Errorf("can't find node with name %s", name)
	}
	return node, nil
}

func (m *NodesMock) Update(ctx context.Context, res *libapiv3.Node, opts options.SetOptions) (*libapiv3.Node, error) {
	if res == nil {
		return nil, fmt.Errorf("node can't be nil")
	}
	if res.Name == "" {
		return nil, fmt.Errorf("node must have a name")
	}
	m.nodes[res.Name] = res
	return res, nil
}

func (m *NodesMock) Delete(ctx context.Context, name string, opts options.DeleteOptions) (*libapiv3.Node, error) {
	panic("not implemented")
}

func (m *NodesMock) List(ctx context.Context, opts options.ListOptions) (*libapiv3.NodeList, error) {
	panic("not implemented")
}

func (m *NodesMock) Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error) {
	panic("not implemented")
}
