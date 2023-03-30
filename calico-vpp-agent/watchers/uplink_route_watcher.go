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
	"github.com/projectcalico/calico/felix/proto"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"

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
	eventChan         chan common.CalicoVppEvent
	log               *log.Entry
}

func NewRouteWatcher(log *log.Entry) *RouteWatcher {
	routeWatcher := &RouteWatcher{
		eventChan: make(chan common.CalicoVppEvent, common.ChanSize),
		log:       log,
	}
	reg := common.RegisterHandler(routeWatcher.eventChan, "route watcher events")
	reg.ExpectEvents(
		common.IpamConfChanged,
		common.NetAddedOrUpdated,
		common.NetDeleted,
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
	r.log.Warnf("error from netlink: %v", err)
	r.netlinkFailed <- struct{}{}
}

func (r *RouteWatcher) addrNetlinkError(err error) {
	r.log.Warnf("error from netlink: %v", err)
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

func (r *RouteWatcher) getNetworkRoute(network string, physicalNet string) (route []*netlink.Route, err error) {
	_, cidr, err := net.ParseCIDR(network)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing %s", network)
	}
	var routes []*netlink.Route
	var order int
	for _, uplinkStatus := range common.VppManagerInfo.UplinkStatuses {
		if uplinkStatus.PhysicalNetworkName == physicalNet {
			gw := uplinkStatus.FakeNextHopIP4
			if cidr.IP.To4() == nil {
				gw = uplinkStatus.FakeNextHopIP6
			}
			var priority int
			if uplinkStatus.IsMain {
				priority = 0
			} else {
				order += 1
				priority = order
			}
			routes = append(routes, &netlink.Route{
				Dst:      cidr,
				Gw:       gw,
				Protocol: syscall.RTPROT_STATIC,
				MTU:      GetUplinkMtu(),
				Priority: priority,
			})
		}
	}
	return routes, nil
}

func (r *RouteWatcher) WatchRoutes(t *tomb.Tomb) error {
	r.netlinkFailed = make(chan struct{}, 1)
	r.addrUpdate = make(chan struct{}, 10)

	go r.watchAddresses(t)
	for _, serviceCIDR := range *config.ServiceCIDRs {
		// Add a route for the service prefix through VPP. This is required even if kube-proxy is
		// running on the host to ensure correct source address selection if the host has multiple interfaces
		r.log.Infof("Adding route to service prefix %s through VPP", serviceCIDR.String())
		var order int
		for _, uplinkStatus := range common.VppManagerInfo.UplinkStatuses {
			gw := uplinkStatus.FakeNextHopIP4
			if serviceCIDR.IP.To4() == nil {
				gw = uplinkStatus.FakeNextHopIP6
			}
			var priority int
			if uplinkStatus.IsMain {
				priority = 0
			} else {
				order += 1
				priority = order
			}
			err := r.AddRoute(&netlink.Route{
				Dst:      serviceCIDR,
				Gw:       gw,
				Protocol: syscall.RTPROT_STATIC,
				MTU:      GetUplinkMtu(),
				Priority: priority,
			})
			if err != nil {
				r.log.Error(err, "cannot add route through vpp tap for service CIDR: %s", serviceCIDR.String())
			}
		}
	}
	for {
		r.closeLock.Lock()
		netlinkUpdates := make(chan netlink.RouteUpdate, 10)
		r.close = make(chan struct{})
		r.closeLock.Unlock()
		r.log.Infof("Subscribing to netlink route updates")
		err := netlink.RouteSubscribeWithOptions(netlinkUpdates, r.close, netlink.RouteSubscribeOptions{
			ErrorCallback: r.netlinkError,
		})
		if err != nil {
			r.log.Errorf("error watching for routes %v", err)
			goto restart
		}
		// Stupidly re-add all of our routes after we start watching to make sure they're there
		if err = r.RestoreAllRoutes(); err != nil {
			r.log.Errorf("error adding routes %v", err)
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
				r.log.Warn("Route watcher stopped")
				return nil
			case event := <-r.eventChan:
				switch event.Type {
				case common.NetDeleted:
					netDef := event.Old.(*NetworkDefinition)
					key := netDef.Range
					routes, err := r.getNetworkRoute(key, netDef.PhysicalNetworkName)
					if err != nil {
						r.log.Error("Error getting route from ipam update:", err)
						goto restart
					}
					for _, route := range routes {
						err = r.DelRoute(route)
						if err != nil {
							r.log.Errorf("Cannot add pool route %s through vpp tap: %v", key, err)
							goto restart
						}
					}
				case common.NetAddedOrUpdated:
					netDef := event.New.(*NetworkDefinition)
					key := netDef.Range
					routes, err := r.getNetworkRoute(key, netDef.PhysicalNetworkName)
					if err != nil {
						r.log.Error("Error getting route from ipam update:", err)
						goto restart
					}
					for _, route := range routes {
						err = r.AddRoute(route)
						if err != nil {
							r.log.Errorf("Cannot add pool route %s through vpp tap: %v", key, err)
							goto restart
						}
					}
				case common.IpamConfChanged:
					old, _ := event.Old.(*proto.IPAMPool)
					new, _ := event.New.(*proto.IPAMPool)
					r.log.Debugf("Received IPAM config update in route watcher old:%+v new:%+v", old, new)
					if new == nil {
						key := old.Cidr
						routes, err := r.getNetworkRoute(key, "")
						if err != nil {
							r.log.Error("Error getting route from ipam update:", err)
							goto restart
						}
						for _, route := range routes {
							err = r.DelRoute(route)
							if err != nil {
								r.log.Errorf("Cannot delete pool route %s through vpp tap: %v", key, err)
								goto restart
							}
						}
					} else {
						key := new.Cidr
						routes, err := r.getNetworkRoute(key, "")
						if err != nil {
							r.log.Error("Error getting route from ipam update:", err)
							goto restart
						}
						for _, route := range routes {
							err = r.AddRoute(route)
							if err != nil {
								r.log.Errorf("Cannot add pool route %s through vpp tap: %v", key, err)
								goto restart
							}
						}
					}
				}
			case <-r.netlinkFailed:
				goto restart
			case update, ok := <-netlinkUpdates:
				if !ok {
					goto restart
				}
				if update.Type == syscall.RTM_DELROUTE {
					for _, route := range r.routes {
						// See if it is one of our routes
						if update.Dst != nil && update.Dst.String() == route.Dst.String() {
							r.log.Infof("Re-adding route %+v", route)
							err = netlink.RouteReplace(&route)
							if err != nil {
								r.log.Errorf("error adding route %+v: %v", route, err)
								goto restart
							}
							break
						}
					}
				}
			case <-r.addrUpdate:
				r.log.Infof("Address update, restoring all routes")
				if err = r.RestoreAllRoutes(); err != nil {
					r.log.Errorf("error adding routes: %v", err)
					goto restart
				}
			}
		}
	restart:
		r.safeClose()
		time.Sleep(2 * time.Second)
		r.log.Info("Restarting route watcher")
	}
}

func (r *RouteWatcher) watchAddresses(t *tomb.Tomb) {
	r.addrNetlinkFailed = make(chan struct{}, 1)

	for {
		r.closeLock.Lock()
		netlinkUpdates := make(chan netlink.AddrUpdate, 10)
		r.addrClose = make(chan struct{})
		r.closeLock.Unlock()
		log.Infof("Subscribing to netlink address updates")
		err := netlink.AddrSubscribeWithOptions(netlinkUpdates, r.addrClose, netlink.AddrSubscribeOptions{
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
			case _, ok := <-netlinkUpdates:
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
