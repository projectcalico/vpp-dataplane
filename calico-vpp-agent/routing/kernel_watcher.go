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

package routing

import (
	"fmt"
	"net"
	"syscall"

	bgpapi "github.com/osrg/gobgp/api"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
)

// watchKernelRoute receives netlink route update notification and announces
// kernel/boot routes using BGP.
func (s *Server) watchKernelRoute() error {
	err := s.loadKernelRoute()
	if err != nil {
		return err
	}

	ch := make(chan netlink.RouteUpdate)
	err = netlink.RouteSubscribe(ch, nil)
	if err != nil {
		return err
	}
	for update := range ch {
		s.log.Debugf("kernel update: %s", update)
		if update.Table == syscall.RT_TABLE_MAIN &&
			(update.Protocol == syscall.RTPROT_KERNEL || update.Protocol == syscall.RTPROT_BOOT) {
			// TODO: handle ipPool deletion. RTM_DELROUTE message
			// can belong to previously valid ipPool.
			if s.ipam.match(*update.Dst) == nil {
				continue
			}
			isWithdrawal := false
			switch update.Type {
			case syscall.RTM_DELROUTE:
				isWithdrawal = true
			case syscall.RTM_NEWROUTE:
			default:
				s.log.Debugf("unhandled rtm type: %d", update.Type)
				continue
			}
			path, err := s.makePath(update.Dst.String(), isWithdrawal)
			if err != nil {
				return err
			}
			s.log.Debugf("made path from kernel update: %s", path)
			if _, err = s.bgpServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
				TableType: bgpapi.TableType_GLOBAL,
				Path:      path,
			}); err != nil {
				return err
			}
		} else if update.Table == syscall.RT_TABLE_LOCAL {
			// This means the interface address is updated
			// Some routes we injected may be deleted by the kernel
			// Reload routes from BGP RIB and inject again
			ip, _, _ := net.ParseCIDR(update.Dst.String())
			family := "4"
			if ip.To4() == nil {
				family = "6"
			}
			s.reloadCh <- family
		}
	}
	return fmt.Errorf("netlink route subscription ended")
}

func (s *Server) loadKernelRoute() error {
	<-s.prefixReady
	filter := &netlink.Route{
		Table: syscall.RT_TABLE_MAIN,
	}
	list, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, route := range list {
		if route.Dst == nil {
			continue
		}
		if s.ipam.match(*route.Dst) == nil {
			continue
		}
		if route.Protocol == syscall.RTPROT_KERNEL || route.Protocol == syscall.RTPROT_BOOT {
			path, err := s.makePath(route.Dst.String(), false)
			if err != nil {
				return err
			}
			s.log.Tracef("made path from kernel route: %s", path)
			if _, err = s.bgpServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
				TableType: bgpapi.TableType_GLOBAL,
				Path:      path,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}
