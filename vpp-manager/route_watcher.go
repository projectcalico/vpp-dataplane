// Copyright (C) 2019 Cisco Systems Inc.
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
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type RouteWatcher struct {
	routes            []*netlink.Route
	close             chan struct{}
	netlinkFailed     chan struct{}
	addrClose         chan struct{}
	addrNetlinkFailed chan struct{}
	addrUpdate        chan struct{}
	stop              bool
	lock              sync.Mutex
	closeLock         sync.Mutex
}

func (r *RouteWatcher) AddRoute(route *netlink.Route) (err error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if err = netlink.RouteReplace(route); err != nil {
		return err
	}
	r.routes = append(r.routes, route)
	return nil
}

func (r *RouteWatcher) DelRoute(route *netlink.Route) (err error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if err = netlink.RouteDel(route); err != nil {
		return err
	}
	for i, watched := range r.routes {
		if watched.Dst.String() == route.Dst.String() {
			r.routes[i] = r.routes[len(r.routes)-1]
			r.routes = r.routes[:len(r.routes)-1]
			break
		}
	}
	return nil
}

func (r *RouteWatcher) Stop() {
	log.Infof("Stopping route watcher")
	r.closeLock.Lock()
	defer r.closeLock.Unlock()
	r.stop = true
	if r.close != nil {
		close(r.close)
		r.close = nil
	}
	if r.addrClose != nil {
		close(r.addrClose)
		r.addrClose = nil
	}
}

func (r *RouteWatcher) netlinkError(err error) {
	if r.stop {
		return
	}
	log.Warnf("error from netlink: %v", err)
	r.netlinkFailed <- struct{}{}
}

func (r *RouteWatcher) addrNetlinkError(err error) {
	if r.stop {
		return
	}
	log.Warnf("error from netlink: %v", err)
	r.addrNetlinkFailed <- struct{}{}
}

func (r *RouteWatcher) RestoreAllRoutes() (err error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	for _, route := range r.routes {
		err = netlink.RouteReplace(route)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *RouteWatcher) safeClose() {
	r.closeLock.Lock()
	if r.close != nil {
		close(r.close)
		r.close = nil
	}
	r.closeLock.Unlock()
}

func (r *RouteWatcher) WatchRoutes() {
	r.netlinkFailed = make(chan struct{}, 1)
	r.addrUpdate = make(chan struct{}, 10)
	r.stop = false

	go r.watchAddresses()

	for {
		r.closeLock.Lock()
		if r.stop {
			log.Infof("Route watcher exited")
			return
		}
		updates := make(chan netlink.RouteUpdate, 10)
		r.close = make(chan struct{})
		r.closeLock.Unlock()
		log.Infof("Subscribing to netlink route updates")
		err := netlink.RouteSubscribeWithOptions(updates, r.close, netlink.RouteSubscribeOptions{
			ErrorCallback: r.netlinkError,
		})
		if err != nil {
			log.Errorf("error watching for routes, sleeping before retrying")
			r.safeClose()
			goto restart
		}
		// Stupidly re-add all of our routes after we start watching to make sure they're there
		if err = r.RestoreAllRoutes(); err != nil {
			log.Errorf("error adding routes, sleeping before retrying: %v", err)
			r.safeClose()
			goto restart
		}
		for {
			select {
			case <-r.netlinkFailed:
				if r.stop {
					log.Infof("Route watcher exiting")
					return
				}
				log.Info("Route watcher stopped / failed")
				goto restart
			case update := <-updates:
				if update.Type == syscall.RTM_DELROUTE {
					r.lock.Lock()
					for _, route := range r.routes {
						// See if it is one of our routes
						if update.Dst != nil && update.Dst.String() == route.Dst.String() {
							log.Infof("Re-adding route %+v", route)
							err = netlink.RouteReplace(route)
							if err != nil {
								log.Errorf("error adding route %+v: %v, restarting watcher", route, err)
								r.safeClose()
								goto restart
							}
							break
						}
					}
					r.lock.Unlock()
				}
			case <-r.addrUpdate:
				log.Infof("Address update, restoring all routes")
				if err = r.RestoreAllRoutes(); err != nil {
					log.Errorf("error adding routes, sleeping before retrying: %v", err)
					r.safeClose()
					goto restart
				}
			}
		}
	restart:
		time.Sleep(2 * time.Second)
	}
}

func (r *RouteWatcher) watchAddresses() {
	r.addrNetlinkFailed = make(chan struct{}, 1)

	for {
		r.closeLock.Lock()
		if r.stop {
			log.Infof("Address watcher exited")
			return
		}
		updates := make(chan netlink.AddrUpdate, 10)
		r.addrClose = make(chan struct{})
		r.closeLock.Unlock()
		log.Infof("Subscribing to netlink address updates")
		err := netlink.AddrSubscribeWithOptions(updates, r.close, netlink.AddrSubscribeOptions{
			ErrorCallback: r.addrNetlinkError,
		})
		if err != nil {
			log.Errorf("error watching for addresses, sleeping before retrying")
			r.closeLock.Lock()
			if r.addrClose != nil {
				close(r.addrClose)
				r.addrClose = nil
			}
			r.closeLock.Unlock()
			goto restart
		}

		for {
			select {
			case <-r.addrNetlinkFailed:
				if r.stop {
					log.Infof("Address watcher exiting")
					return
				}
				log.Info("Address watcher stopped / failed")
				goto restart
			case <-updates:
				r.addrUpdate <- struct{}{}
			}
		}
	restart:
		time.Sleep(2 * time.Second)
	}
}
