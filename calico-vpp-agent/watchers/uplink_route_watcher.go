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

package watchers

import (
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/proto"
	"github.com/projectcalico/vpp-dataplane/config"
	"github.com/projectcalico/vpp-dataplane/vpplink"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"gopkg.in/tomb.v2"
)

type RouteWatcher struct {
	routes            []netlink.Route
	close             chan struct{}
	netlinkFailed     chan struct{}
	addrClose         chan struct{}
	addrNetlinkFailed chan struct{}
	addrUpdate        chan struct{}
	closeLock         sync.Mutex
	routeEventChan    chan common.CalicoVppEvent
	FakeNextHopIP4    net.IP
	FakeNextHopIP6    net.IP
}

func NewRouteWatcher(fakeNextHopIP4, fakeNextHopIP6 net.IP) *RouteWatcher {
	routeWatcher := &RouteWatcher{
		routeEventChan: make(chan common.CalicoVppEvent, common.ChanSize),
		FakeNextHopIP4: fakeNextHopIP4,
		FakeNextHopIP6: fakeNextHopIP6,
	}
	reg := common.RegisterHandler(routeWatcher.routeEventChan, "route watcher events")
	reg.ExpectEvents(
		common.IpamConfChanged,
	)
	return routeWatcher
}

func copyRoute(route *netlink.Route) netlink.Route {
	routeCopy := *route
	dst := *route.Dst
	routeCopy.Dst = &dst
	return routeCopy
}

func (r *RouteWatcher) AddRoute(route *netlink.Route) (err error) {
	if err = netlink.RouteReplace(route); err != nil {
		return err
	}

	r.routes = append(r.routes, copyRoute(route))

	return nil
}

func (r *RouteWatcher) DelRoute(route *netlink.Route) (err error) {
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

func (r *RouteWatcher) netlinkError(err error) {
	log.Warnf("error from netlink: %v", err)
	r.netlinkFailed <- struct{}{}
}

func (r *RouteWatcher) addrNetlinkError(err error) {
	log.Warnf("error from netlink: %v", err)
	r.addrNetlinkFailed <- struct{}{}
}

func (r *RouteWatcher) RestoreAllRoutes() (err error) {
	for _, route := range r.routes {
		err = netlink.RouteReplace(&route)
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

func (r *RouteWatcher) safeAddrClose() {
	r.closeLock.Lock()
	if r.addrClose != nil {
		close(r.addrClose)
		r.addrClose = nil
	}
	r.closeLock.Unlock()
}

func GetUplinkMtu() int {
	hostMtu := vpplink.MAX_MTU
	if len(common.VppManagerInfo.UplinkStatuses) != 0 {
		for _, v := range common.VppManagerInfo.UplinkStatuses {
			if v.Mtu < hostMtu {
				hostMtu = v.Mtu
			}
		}
	}
	encapSize := config.DefaultEncapSize
	// Use the linux interface MTU as default value if nothing is configured from env
	return hostMtu - encapSize
}

func (r *RouteWatcher) getNetworkRoute(network string) (route *netlink.Route, err error) {
	log.Infof("Added ip pool %s", network)
	_, cidr, err := net.ParseCIDR(network)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing %s", network)
	}

	gw := r.FakeNextHopIP4
	if cidr.IP.To4() == nil {
		gw = r.FakeNextHopIP6
	}

	return &netlink.Route{
		Dst:      cidr,
		Gw:       gw,
		Protocol: syscall.RTPROT_STATIC,
		MTU:      GetUplinkMtu(),
	}, nil
}

func (r *RouteWatcher) WatchRoutes(t *tomb.Tomb) error {
	r.netlinkFailed = make(chan struct{}, 1)
	r.addrUpdate = make(chan struct{}, 10)

	go r.watchAddresses(t)
	for _, serviceCIDR := range *config.ServiceCIDRs {
		// Add a route for the service prefix through VPP. This is required even if kube-proxy is
		// running on the host to ensure correct source address selection if the host has multiple interfaces
		log.Infof("Adding route to service prefix %s through VPP", serviceCIDR.String())
		gw := common.VppManagerInfo.FakeNextHopIP4
		if serviceCIDR.IP.To4() == nil {
			gw = common.VppManagerInfo.FakeNextHopIP6
		}
		err := r.AddRoute(&netlink.Route{
			Dst:      serviceCIDR,
			Gw:       gw,
			Protocol: syscall.RTPROT_STATIC,
			MTU:      GetUplinkMtu(),
		})
		if err != nil {
			log.Error(err, "cannot add tap route to service %s", serviceCIDR.String())
		}
	}
	for {
		r.closeLock.Lock()
		updates := make(chan netlink.RouteUpdate, 10)
		r.close = make(chan struct{})
		r.closeLock.Unlock()
		log.Infof("Subscribing to netlink route updates")
		err := netlink.RouteSubscribeWithOptions(updates, r.close, netlink.RouteSubscribeOptions{
			ErrorCallback: r.netlinkError,
		})
		if err != nil {
			log.Errorf("error watching for routes %v", err)
			goto restart
		}
		// Stupidly re-add all of our routes after we start watching to make sure they're there
		if err = r.RestoreAllRoutes(); err != nil {
			log.Errorf("error adding routes %v", err)
			goto restart
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
				log.Warn("Route watcher stopped")
				return nil
			case event := <-r.routeEventChan:
				switch event.Type {
				case common.IpamConfChanged:
					old, _ := event.Old.(*proto.IPAMPool)
					new, _ := event.New.(*proto.IPAMPool)
					if new == nil {
						key := old.Cidr
						route, err := r.getNetworkRoute(key)
						if err != nil {
							return errors.Wrap(err, "Error deleting net")
						}
						err = r.DelRoute(route)
						return errors.Wrapf(err, "cannot delete pool route %s through vpp tap", key)
					} else {
						key := new.Cidr
						route, err := r.getNetworkRoute(key)
						if err != nil {
							return errors.Wrap(err, "Error adding net")
						}
						err = r.AddRoute(route)
						return errors.Wrapf(err, "cannot add pool route %s through vpp tap", key)
					}
				}
			case <-r.netlinkFailed:
				goto restart
			case update, ok := <-updates:
				if !ok {
					goto restart
				}
				if update.Type == syscall.RTM_DELROUTE {
					for _, route := range r.routes {
						// See if it is one of our routes
						if update.Dst != nil && update.Dst.String() == route.Dst.String() {
							log.Infof("Re-adding route %+v", route)
							err = netlink.RouteReplace(&route)
							if err != nil {
								log.Errorf("error adding route %+v: %v", route, err)
								goto restart
							}
							break
						}
					}
				}
			case <-r.addrUpdate:
				log.Infof("Address update, restoring all routes")
				if err = r.RestoreAllRoutes(); err != nil {
					log.Errorf("error adding routes: %v", err)
					goto restart
				}
			}
		}
	restart:
		r.safeClose()
		time.Sleep(2 * time.Second)
		log.Info("Restarting route watcher")
	}
}

func (r *RouteWatcher) watchAddresses(t *tomb.Tomb) {
	r.addrNetlinkFailed = make(chan struct{}, 1)

	for {
		r.closeLock.Lock()
		updates := make(chan netlink.AddrUpdate, 10)
		r.addrClose = make(chan struct{})
		r.closeLock.Unlock()
		log.Infof("Subscribing to netlink address updates")
		err := netlink.AddrSubscribeWithOptions(updates, r.addrClose, netlink.AddrSubscribeOptions{
			ErrorCallback: r.addrNetlinkError,
		})
		if err != nil {
			log.Errorf("error watching for addresses, sleeping before retrying")
			goto restart
		}

		for {
			select {
			case <-t.Dying():
				r.closeLock.Lock()
				defer r.closeLock.Unlock()
				if r.addrClose != nil {
					close(r.addrClose)
					r.addrClose = nil
				}
				log.Info("Route watcher stopped")
				return
			case <-r.addrNetlinkFailed:
				log.Info("Address watcher stopped / failed")
				goto restart
			case _, ok := <-updates:
				if !ok {
					goto restart
				}
				r.addrUpdate <- struct{}{}
			}
		}
	restart:
		r.safeAddrClose()
		time.Sleep(2 * time.Second)
	}
}
