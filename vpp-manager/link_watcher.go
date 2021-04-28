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

package main

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type LinkWatcher struct {
	LinkIndex     int
	LinkName      string
	MTU           int
	close         chan struct{}
	netlinkFailed chan struct{}
	stop          bool
	closeLock     sync.Mutex
}

func (r *LinkWatcher) Stop() {
	log.Infof("Stopping link watcher")
	r.closeLock.Lock()
	defer r.closeLock.Unlock()
	r.stop = true
	if r.close != nil {
		close(r.close)
		r.close = nil
	}
}

func (r *LinkWatcher) netlinkError(err error) {
	if r.stop {
		return
	}
	log.Warnf("error from netlink: %v", err)
	r.netlinkFailed <- struct{}{}
}

func (r *LinkWatcher) ResetMTU(link netlink.Link) (err error) {
	//TODO
	return netlink.LinkSetMTU(link, r.MTU)
}

func (r *LinkWatcher) safeClose() {
	r.closeLock.Lock()
	if r.close != nil {
		close(r.close)
		r.close = nil
	}
	r.closeLock.Unlock()
}

func (r *LinkWatcher) WatchLinks() {
	r.netlinkFailed = make(chan struct{}, 1)
	r.stop = false
	var link netlink.Link

	for {
		r.closeLock.Lock()
		if r.stop {
			log.Infof("Link watcher exited")
			return
		}
		updates := make(chan netlink.LinkUpdate, 10)
		r.close = make(chan struct{})
		r.closeLock.Unlock()
		log.Infof("Subscribing to netlink link updates")
		err := netlink.LinkSubscribeWithOptions(updates, r.close, netlink.LinkSubscribeOptions{
			ErrorCallback: r.netlinkError,
		})
		if err != nil {
			log.Errorf("error watching for links, sleeping before retrying")
			r.safeClose()
			goto restart
		}
		link, err = netlink.LinkByIndex(r.LinkIndex)
		if err != nil || link.Attrs().Name != r.LinkName {
			log.Errorf("error getting link to watch: %v %v", link, err)
			r.safeClose()
			goto restart
		}
		// Set the MTU on watch restart
		if err = r.ResetMTU(link); err != nil {
			log.Errorf("error resetting MTU, sleeping before retrying: %v", err)
			r.safeClose()
			goto restart
		}
		for {
			select {
			case <-r.netlinkFailed:
				if r.stop {
					log.Infof("Link watcher exiting")
					return
				}
				log.Info("Link watcher stopped / failed")
				goto restart
			case update := <-updates:
				if update.Attrs().Index == r.LinkIndex {
					if update.Attrs().Name == r.LinkName {
						if update.Attrs().MTU != r.MTU {
							if err = r.ResetMTU(update); err != nil {
								log.Warnf("Error resetting link mtu: %v", err)
								r.safeClose()
								goto restart
							}
						} else {
							log.Infof("Got link update, MTU unchanged")
						}
					} else {
						log.Infof("Ignoring link update for index %d but name %d", update.Attrs().Index, update.Attrs().Name)
					}
				} else {
					log.Infof("Ignoring link update for index %d", update.Attrs().Index)
				}
			}
		}
	restart:
		time.Sleep(2 * time.Second)
	}
}
