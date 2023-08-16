// Copyright (C) 2023 Cisco Systems Inc.
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

	fib_types "github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/fib_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_session_redirect"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

func (v *VppLink) AddSessionRedirect(redirect *types.SessionRedirect, paths ...*types.RoutePath) (err error) {
	client := ip_session_redirect.NewServiceClient(v.GetConnection())

	fibPaths := make([]fib_types.FibPath, 0, len(paths))
	for _, routePath := range paths {
		fibPaths = append(fibPaths, routePath.ToFibPath(false))
	}
	match, err := redirect.GetMatch()
	if err != nil {
		return err
	}
	_, err = client.IPSessionRedirectAddV2(v.GetContext(), &ip_session_redirect.IPSessionRedirectAddV2{
		TableIndex: redirect.TableIndex,
		MatchLen:   uint8(len(match)),
		Match:      match,
		NPaths:     uint8(len(fibPaths)),
		Paths:      fibPaths,
	})
	if err != nil {
		return fmt.Errorf("failed to add ip session redirect: %w", err)
	}
	return nil
}

func (v *VppLink) DelSessionRedirect(redirect *types.SessionRedirect) error {
	client := ip_session_redirect.NewServiceClient(v.GetConnection())

	match, err := redirect.GetMatch()
	if err != nil {
		return err
	}
	_, err = client.IPSessionRedirectDel(v.GetContext(), &ip_session_redirect.IPSessionRedirectDel{
		TableIndex: redirect.TableIndex,
		MatchLen:   uint8(len(match)),
		Match:      match,
	})
	if err != nil {
		return fmt.Errorf("failed to del ip session redirect: %w", err)
	}
	return nil
}
