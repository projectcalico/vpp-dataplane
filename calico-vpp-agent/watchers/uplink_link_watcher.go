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
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/config"
)

type LinkWatcher struct {
	UplinkStatuses map[string]config.UplinkStatus
	close          chan struct{}
	netlinkFailed  chan struct{}
	closeLock      sync.Mutex
	log            *log.Entry
}

func NewLinkWatcher(uplinkStatus map[string]config.UplinkStatus, log *log.Entry) *LinkWatcher {
	return &LinkWatcher{
		UplinkStatuses: uplinkStatus,
		log:            log,
	}
}

func (r *LinkWatcher) netlinkError(err error) {
	r.log.Warnf("error from netlink: %v", err)
	r.netlinkFailed <- struct{}{}
}

func (r *LinkWatcher) ResetMTU(link netlink.Link, mtu int) (err error) {
	//TODO
	return netlink.LinkSetMTU(link, mtu)
}

func (r *LinkWatcher) safeClose() {
	r.closeLock.Lock()
	if r.close != nil {
		close(r.close)
		r.close = nil
	}
	r.closeLock.Unlock()
}

func (r *LinkWatcher) WatchLinks(t *tomb.Tomb) error {
	r.netlinkFailed = make(chan struct{}, 1)
	var link netlink.Link

	for {
		r.closeLock.Lock()
		updates := make(chan netlink.LinkUpdate, 10)
		r.close = make(chan struct{})
		r.closeLock.Unlock()
		r.log.Infof("Subscribing to netlink link updates")
		err := netlink.LinkSubscribeWithOptions(updates, r.close, netlink.LinkSubscribeOptions{
			ErrorCallback: r.netlinkError,
		})
		if err != nil {
			r.log.Errorf("error watching for links, sleeping before retrying")
			r.safeClose()
			goto restart
		}
		for _, v := range r.UplinkStatuses {
			link, err = netlink.LinkByIndex(v.LinkIndex)
			if err != nil || link.Attrs().Name != v.Name {
				r.log.Errorf("error getting link to watch: %v %v", link, err)
				r.safeClose()
				goto restart
			}
			// Set the MTU on watch restart
			if err = netlink.LinkSetMTU(link, v.Mtu); err != nil {
				r.log.Errorf("error resetting MTU, sleeping before retrying: %v", err)
				r.safeClose()
				goto restart
			}
		}
		for {
			select {
			case <-t.Dying():
				r.closeLock.Lock()
				defer r.closeLock.Unlock()
				if r.close != nil {
					close(r.close)
					r.close = nil
				}
				r.log.Warn("Link watcher stopped")
				return nil
			case <-r.netlinkFailed:
				r.log.Info("Link watcher stopped / failed")
				goto restart
			case update, ok := <-updates:
				if !ok {
					/* channel closed, restart */
					goto restart
				}
				found := false
				v := config.UplinkStatus{}
				for _, v = range r.UplinkStatuses {
					if update.Attrs().Index == v.LinkIndex {
						found = true
						break
					}
				}
				if found {
					if update.Attrs().Name == v.Name {
						if update.Attrs().MTU != v.Mtu {
							if err = netlink.LinkSetMTU(update.Link, v.Mtu); err != nil {
								r.log.Warnf("Error resetting link mtu: %v", err)
								r.safeClose()
								goto restart
							}
						} else {
							r.log.Infof("Got link update, MTU unchanged")
						}
					} else {
						r.log.Infof("Ignoring link update for index %d but name %s", update.Attrs().Index, update.Attrs().Name)
					}
				} else {
					r.log.Infof("Ignoring link update for index %d", update.Attrs().Index)
				}
			}
		}
	restart:
		time.Sleep(2 * time.Second)
	}
}
