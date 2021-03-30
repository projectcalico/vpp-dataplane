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
	routes        []*netlink.Route
	close         chan struct{}
	netlinkFailed chan struct{}
	stop          bool
	lock          sync.Mutex
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
	log.Infof("stopping route watcher")
	r.stop = true
	r.close <- struct{}{}
}

func (r *RouteWatcher) netlinkError(err error) {
	if r.stop {
		return
	}
	log.Warnf("error from netlink: %v", err)
	r.netlinkFailed <- struct{}{}
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

func (r *RouteWatcher) WatchRoutes() {
	updates := make(chan netlink.RouteUpdate)
	r.close = make(chan struct{})
	r.netlinkFailed = make(chan struct{})
	r.stop = false

	for {
		log.Infof("Subscribing to netlink route updates")
		err := netlink.RouteSubscribeWithOptions(updates, r.close, netlink.RouteSubscribeOptions{
			ErrorCallback: r.netlinkError,
		})
		if err != nil {
			log.Errorf("error watching for routes, sleeping before retrying")
			time.Sleep(2 * time.Second)
			continue
		}
		// Stupidly re-add all of our routes after we start watching to make sure they're there
		if err = r.RestoreAllRoutes(); err != nil {
			log.Errorf("error adding routes, sleeping before retrying: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
	watch:
		for {
			select {
			case <-r.netlinkFailed:
				if r.stop {
					log.Infof("Route watcher exiting")
					return
				}
				log.Info("Route watcher stopped / failed")
				time.Sleep(2 * time.Second)
				break watch
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
								r.close <- struct{}{}
							}
							break
						}
					}
					r.lock.Unlock()
				}
			}
		}
	}
}
