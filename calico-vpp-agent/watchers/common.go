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

package watchers

import (
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
)

func NewK8SClient(timeout time.Duration, addToSchemes []func(s *runtime.Scheme) error) (*client.WithWatch, error) {
	scheme := runtime.NewScheme()
	for _, addToScheme := range addToSchemes {
		_ = addToScheme(scheme)
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	mapper, err := apiutil.NewDiscoveryRESTMapper(config)
	if err != nil {
		return nil, err
	}

	k8sClient, err := client.NewWithWatch(config, client.Options{Scheme: scheme, Mapper: mapper})
	if err != nil {
		return nil, err
	}

	return &k8sClient, nil
}
