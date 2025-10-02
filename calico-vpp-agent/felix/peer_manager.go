// Copyright (C) 2025 Cisco Systems Inc.
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

package felix

import (
	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"k8s.io/client-go/kubernetes"

	calicov3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/watchers"
)

// PeerManager coordinates the new peer management architecture
type PeerManager struct {
	log         *logrus.Entry
	peerHandler *PeerHandler
	peerWatcher *watchers.PeerWatcher
}

// SecretChangeHandler interface for handling secret changes
type SecretChangeHandler interface {
	OnSecretChanged(secretName string)
}

// NewPeerManager creates a fully integrated peer manager
func NewPeerManager(clientv3 calicov3cli.Interface, k8sClient *kubernetes.Clientset, felixServer *Server, log *logrus.Entry) (*PeerManager, error) {
	// Create the secret watcher
	secretWatcher, err := watchers.NewSecretWatcher(k8sClient)
	if err != nil {
		return nil, err
	}

	// Create peer handler with the secret watcher for cleanup and as secret getter
	peerHandler := NewPeerHandler(clientv3, felixServer.GetCache(), secretWatcher, secretWatcher, log)

	// Register the peer handler with the connectivity handler for node state changes
	connectivityHandler := felixServer.GetConnectivityHandler()
	if connectivityHandler != nil {
		connectivityHandler.RegisterPeerNodeStateChangeHandler(peerHandler)
	} else {
		log.Warn("Connectivity handler is nil, skipping peer node state change handler registration")
	}

	// Create peer watcher
	peerWatcher := watchers.NewPeerWatcher(clientv3, peerHandler, log)

	peerManager := &PeerManager{
		log:         log,
		peerHandler: peerHandler,
		peerWatcher: peerWatcher,
	}

	// Register the peer handler as a secret change handler
	secretWatcher.RegisterSecretChangeHandler(peerManager)

	return peerManager, nil
}

func (p *PeerManager) Start(t *tomb.Tomb) error {
	p.log.Info("Starting peer manager")

	// Start the peer watcher (this runs in the main loop)
	return p.peerWatcher.WatchBGPPeers(t)
}

// SetBGPConf sets BGP configuration on the peer handler
func (p *PeerManager) SetBGPConf(bgpConf *calicov3.BGPConfigurationSpec) {
	p.peerWatcher.SetBGPConf(bgpConf)
}

// SetBGPPeerHandler sets the BGP peer handler on the internal peer handler
func (p *PeerManager) SetBGPPeerHandler(handler BGPPeerHandler) {
	p.peerHandler.SetBGPPeerHandler(handler)
}

// OnSecretChanged implements SecretChangeHandler
// Directly calls peer handler with current state from peer watcher
func (p *PeerManager) OnSecretChanged(secretName string) {
	p.peerHandler.OnSecretChanged(secretName, p.peerWatcher.GetState())
}
