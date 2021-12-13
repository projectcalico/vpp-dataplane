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

	"github.com/golang/protobuf/ptypes"
	bgpapi "github.com/osrg/gobgp/api"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
	tomb "gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
)

func (w *Server) getNexthop(path *bgpapi.Path) string {
	for _, attr := range path.Pattrs {
		nhAttr := &bgpapi.NextHopAttribute{}
		mpReachAttr := &bgpapi.MpReachNLRIAttribute{}
		if err := ptypes.UnmarshalAny(attr, nhAttr); err == nil {
			return nhAttr.NextHop
		}
		if err := ptypes.UnmarshalAny(attr, mpReachAttr); err == nil {
			if len(mpReachAttr.NextHops) != 1 {
				w.log.Fatalf("Cannot process more than one Nlri in path attributes: %+v", mpReachAttr)
			}
			return mpReachAttr.NextHops[0]
		}
	}
	return ""
}

// injectRoute is a helper function to inject BGP routes to VPP
// TODO: multipath support
func (w *Server) injectRoute(path *bgpapi.Path) error {
	var dst net.IPNet
	ipAddrPrefixNlri := &bgpapi.IPAddressPrefix{}
	otherNodeIP := net.ParseIP(w.getNexthop(path))
	if otherNodeIP == nil {
		return fmt.Errorf("Cannot determine path nexthop: %+v", path)
	}

	if err := ptypes.UnmarshalAny(path.Nlri, ipAddrPrefixNlri); err == nil {
		dst.IP = net.ParseIP(ipAddrPrefixNlri.Prefix)
		if dst.IP == nil {
			return fmt.Errorf("Cannot parse nlri addr: %s", ipAddrPrefixNlri.Prefix)
		} else if dst.IP.To4() == nil {
			dst.Mask = net.CIDRMask(int(ipAddrPrefixNlri.PrefixLen), 128)
		} else {
			dst.Mask = net.CIDRMask(int(ipAddrPrefixNlri.PrefixLen), 32)
		}
	} else {
		return fmt.Errorf("Cannot handle Nlri: %+v", path.Nlri)
	}

	cn := &common.NodeConnectivity{
		Dst:     dst,
		NextHop: otherNodeIP,
	}
	if path.IsWithdraw {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.ConnectivityDeleted,
			Old:  cn,
		})
	} else {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.ConnectivityAdded,
			New:  cn,
		})
	}
	return nil
}

// watchBGPPath watches BGP routes from other peers and inject them into
// linux kernel
// TODO: multipath support
func (w *Server) WatchBGPPath(t *tomb.Tomb) error {
	var err error
	startMonitor := func(f *bgpapi.Family) (context.CancelFunc, error) {
		ctx, stopFunc := context.WithCancel(context.Background())
		err := w.BGPServer.MonitorTable(
			ctx,
			&bgpapi.MonitorTableRequest{
				TableType: bgpapi.TableType_GLOBAL,
				Name:      "",
				Family:    f,
				Current:   false,
			},
			func(path *bgpapi.Path) {
				if path == nil {
					w.log.Warnf("nil path update, skipping")
					return
				}
				w.log.Infof("Got path update from %s as %d", path.SourceId, path.SourceAsn)
				if path.NeighborIp == "<nil>" { // Weird GoBGP API behaviour
					w.log.Debugf("Ignoring internal path")
					return
				}
				if err := w.injectRoute(path); err != nil {
					w.log.Errorf("cannot inject route: %v", err)
				}
			},
		)
		return stopFunc, err
	}

	var stopV4Monitor, stopV6Monitor context.CancelFunc
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(w.nodeBGPSpec)
	if nodeIP4 != nil {
		stopV4Monitor, err = startMonitor(&common.BgpFamilyUnicastIPv4)
		if err != nil {
			return errors.Wrap(err, "error starting v4 path monitor")
		}
	}
	if nodeIP6 != nil {
		stopV6Monitor, err = startMonitor(&common.BgpFamilyUnicastIPv6)
		if err != nil {
			return errors.Wrap(err, "error starting v6 path monitor")
		}
	}
	for {
		select {
		case <-t.Dying():
			if nodeIP4 != nil {
				stopV4Monitor()
			}
			if nodeIP6 != nil {
				stopV6Monitor()
			}
			w.log.Infof("Routing Server asked to stop")
			return nil
		case evt := <-w.routingServerEventChan:
			switch evt.Type {
			case common.LocalPodAddressAdded:
				addr := evt.New.(*net.IPNet)
				err := w.announceLocalAddress(addr)
				if err != nil {
					return err
				}
			case common.LocalPodAddressDeleted:
				addr := evt.Old.(*net.IPNet)
				err := w.withdrawLocalAddress(addr)
				if err != nil {
					return err
				}
			case common.BGPReloadIP4:
				if nodeIP4 != nil {
					stopV4Monitor()
					stopV4Monitor, err = startMonitor(&common.BgpFamilyUnicastIPv4)
					if err != nil {
						return err
					}
				}
			case common.BGPReloadIP6:
				if nodeIP6 != nil {
					stopV6Monitor()
					stopV6Monitor, err = startMonitor(&common.BgpFamilyUnicastIPv6)
					if err != nil {
						return err
					}
				}
			case common.BGPPathAdded:
				path := evt.New.(*bgpapi.Path)
				_, err = w.BGPServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
					TableType: bgpapi.TableType_GLOBAL,
					Path:      path,
				})
				if err != nil {
					return err
				}
			case common.BGPPathDeleted:
				path := evt.Old.(*bgpapi.Path)
				err = w.BGPServer.DeletePath(context.Background(), &bgpapi.DeletePathRequest{
					TableType: bgpapi.TableType_GLOBAL,
					Path:      path,
				})
				if err != nil {
					return err
				}
			case common.BGPDefinedSetAdded:
				ps := evt.New.(*bgpapi.DefinedSet)
				err := w.BGPServer.AddDefinedSet(
					context.Background(),
					&bgpapi.AddDefinedSetRequest{DefinedSet: ps},
				)
				if err != nil {
					return err
				}
			case common.BGPDefinedSetDeleted:
				ps := evt.Old.(*bgpapi.DefinedSet)
				err := w.BGPServer.DeleteDefinedSet(
					context.Background(),
					&bgpapi.DeleteDefinedSetRequest{DefinedSet: ps, All: false},
				)
				if err != nil {
					return err
				}
			case common.BGPPeerAdded:
				peer := evt.New.(*bgpapi.Peer)
				w.log.Infof("Adding BGP neighbor: %s AS:%d",
					peer.Conf.NeighborAddress, peer.Conf.PeerAs)
				err := w.BGPServer.AddPeer(
					context.Background(),
					&bgpapi.AddPeerRequest{Peer: peer},
				)
				if err != nil {
					return err
				}
			case common.BGPPeerDeleted:
				addr := evt.New.(string)
				w.log.Infof("Deleting BGP neighbor: %s", addr)
				err := w.BGPServer.DeletePeer(
					context.Background(),
					&bgpapi.DeletePeerRequest{Address: addr},
				)
				if err != nil {
					return err
				}
			case common.BGPPeerUpdated:
				peer := evt.New.(*bgpapi.Peer)
				w.log.Infof("Updating BGP neighbor: %s AS:%d",
					peer.Conf.NeighborAddress, peer.Conf.PeerAs)
				_, err = w.BGPServer.UpdatePeer(
					context.Background(),
					&bgpapi.UpdatePeerRequest{Peer: peer},
				)
				if err != nil {
					return err
				}
			}
		}
	}
}
