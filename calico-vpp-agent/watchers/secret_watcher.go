// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

package watchers

import (
	"os"
	"sync"
	"time"

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type secretWatchData struct {
	// The channel that we should write to when we no longer want this watch
	stopCh chan struct{}

	// Secret value
	secret *v1.Secret
}

type secretWatcher struct {
	namespace    string
	k8sClientset *kubernetes.Clientset
	mutex        sync.Mutex
	watches      map[string]*secretWatchData
}

func NewSecretWatcher(k8sclient *kubernetes.Clientset) *secretWatcher {
	sw := &secretWatcher{
		watches:      make(map[string]*secretWatchData),
		k8sClientset: k8sclient,
	}

	// Find the namespace we're running in (for the unlikely case where we
	// are being run in a namespace other than calico-vpp-dataplane)
	sw.namespace = os.Getenv("NAMESPACE")
	if sw.namespace == "" {
		// Default to calico-vpp-dataplane.
		sw.namespace = "calico-vpp-dataplane"
	}

	return sw
}

func (sw *secretWatcher) ensureWatchingSecret(name string) {
	if _, ok := sw.watches[name]; ok {
		log.Debugf("Already watching secret '%v' (namespace %v)", name, sw.namespace)
	} else {
		log.Debugf("Start a watch for secret '%v' (namespace %v)", name, sw.namespace)
		// We're not watching this secret yet, so start a watch for it.
		_, controller := cache.NewInformerWithOptions(
			cache.InformerOptions{
				ListerWatcher: cache.NewListWatchFromClient(
					sw.k8sClientset.CoreV1().RESTClient(),
					"secrets",
					sw.namespace,
					fields.OneTermEqualSelector("metadata.name", name),
				),
				ObjectType: &v1.Secret{},
				Handler:    sw,
			},
		)
		sw.watches[name] = &secretWatchData{stopCh: make(chan struct{})}
		go controller.Run(sw.watches[name].stopCh)
		log.Debugf("Controller for secret '%v' is now running", name)

		// Block for up to 0.5s until the controller has synced.  This is just an
		// optimization to avoid churning the emitted BGP peer config when the secret is
		// already available.  If the secret takes a bit longer to appear, we will cope
		// with that too, but asynchronously and with some possible BIRD config churn.
		sw.allowTimeForControllerSync(name, controller, 500*time.Millisecond)
	}
}

func (sw *secretWatcher) allowTimeForControllerSync(name string, controller cache.Controller, timeAllowed time.Duration) {
	sw.mutex.Unlock()
	defer sw.mutex.Lock()
	log.Debug("Unlocked")

	startTime := time.Now()
	for {
		// Note: There is a lock associated with the controller's Queue, and HasSynced()
		// needs to take and release that lock.  The same lock is held when the controller
		// calls our OnAdd, OnUpdate and OnDelete callbacks.
		if controller.HasSynced() {
			log.Debugf("Controller for secret '%v' has synced", name)
			break
		} else {
			log.Debugf("Controller for secret '%v' has not synced yet", name)
		}
		if time.Since(startTime) > timeAllowed {
			log.Warningf("Controller for secret '%v' did not sync within %v", name, timeAllowed)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	log.Debug("Relock...")
}

func (sw *secretWatcher) OnAdd(obj interface{}, isInInitialList bool) {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()
	log.Debug("Secret added")
	secret, ok := obj.(*v1.Secret)
	if !ok {
		panic("secret add, old is not *v1.Secret")
	}
	sw.watches[secret.Name].secret = secret
	common.SendEvent(common.CalicoVppEvent{
		Type: common.SecretAdded,
		New: &common.SecretAddedEvent{
			Secret: &common.SecretData{
				Name: secret.Name,
				Data: secret.Data,
			},
		},
	})
}

func (sw *secretWatcher) OnUpdate(oldObj, newObj interface{}) {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()
	_, ok := oldObj.(*v1.Secret)
	if !ok {
		panic("secret update, old is not *v1.Secret")
	}
	secret, ok := newObj.(*v1.Secret)
	if !ok {
		panic("secret update, new is not *v1.Secret")
	}
	log.Debug("Secret updated")
	sw.watches[secret.Name].secret = secret
	common.SendEvent(common.CalicoVppEvent{
		Type: common.SecretChanged,
		New:  &common.SecretChangedEvent{SecretName: secret.Name},
	})
}

func (sw *secretWatcher) OnDelete(obj interface{}) {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()
	log.Debug("Secret deleted")
	secret, ok := obj.(*v1.Secret)
	if !ok {
		panic("secret delete, old is not *v1.Secret")
	}
	sw.watches[secret.Name].secret = nil
	common.SendEvent(common.CalicoVppEvent{
		Type: common.SecretDeleted,
		New:  &common.SecretDeletedEvent{SecretName: secret.Name},
	})
}

// OnPeerListUpdated updates the list of active secrets, starts watching new ones, and sweeps stale ones
func (sw *secretWatcher) OnPeerListUpdated(peers []calicov3.BGPPeer) {
	sw.mutex.Lock()
	defer sw.mutex.Unlock()

	activeSecrets := make(map[string]struct{})
	for _, peer := range peers {
		if peer.Spec.Password != nil && peer.Spec.Password.SecretKeyRef != nil {
			secretName := peer.Spec.Password.SecretKeyRef.Name
			activeSecrets[secretName] = struct{}{}
			// Start watching this secret if we're not already
			sw.ensureWatchingSecret(secretName)
		}
	}

	// Sweep stale secrets
	for name, watchData := range sw.watches {
		if _, ok := activeSecrets[name]; !ok {
			log.Debugf("Deleting secret '%s'", name)
			close(watchData.stopCh)
			delete(sw.watches, name)
		}
	}
}
