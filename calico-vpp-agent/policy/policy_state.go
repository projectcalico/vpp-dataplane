// Copyright (C) 2020 Cisco Systems Inc.
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

package policy

type PolicyState struct {
	IPSets            map[string]*IPSet
	Policies          map[PolicyID]*Policy
	multinetPolicies  map[string]map[PolicyID]*Policy
	Profiles          map[string]*Policy
	WorkloadEndpoints map[WorkloadEndpointID]*WorkloadEndpoint
	HostEndpoints     map[HostEndpointID]*HostEndpoint
}

func NewPolicyState() *PolicyState {
	return &PolicyState{
		IPSets:            make(map[string]*IPSet),
		Policies:          make(map[PolicyID]*Policy),
		multinetPolicies:  make(map[string]map[PolicyID]*Policy),
		Profiles:          make(map[string]*Policy),
		WorkloadEndpoints: make(map[WorkloadEndpointID]*WorkloadEndpoint),
		HostEndpoints:     make(map[HostEndpointID]*HostEndpoint),
	}
}
