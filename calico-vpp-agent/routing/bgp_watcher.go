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
	"google.golang.org/protobuf/types/known/anypb"
	tomb "gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
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
	labeledVPNIPAddressPrefixNlri := &bgpapi.LabeledVPNIPAddressPrefix{}
	vpn := false
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
		err := ptypes.UnmarshalAny(path.Nlri, labeledVPNIPAddressPrefixNlri)
		if err == nil {
			dst.IP = net.ParseIP(labeledVPNIPAddressPrefixNlri.Prefix)
			if dst.IP == nil {
				return fmt.Errorf("Cannot parse nlri addr: %s", labeledVPNIPAddressPrefixNlri.Prefix)
			} else if dst.IP.To4() == nil {
				dst.Mask = net.CIDRMask(int(labeledVPNIPAddressPrefixNlri.PrefixLen), 128)
			} else {
				dst.Mask = net.CIDRMask(int(labeledVPNIPAddressPrefixNlri.PrefixLen), 32)
			}
			vpn = true
		} else {
			return fmt.Errorf("Cannot handle Nlri: %+v", path.Nlri)
		}
	}

	cn := &common.NodeConnectivity{
		Dst:     dst,
		NextHop: otherNodeIP,
	}
	if vpn {
		rd := &bgpapi.RouteDistinguisherTwoOctetAS{}
		ptypes.UnmarshalAny(labeledVPNIPAddressPrefixNlri.Rd, rd)
		cn.Vni = rd.Assigned
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

func (w *Server) getSRPolicy(path *bgpapi.Path) (srv6Policy *types.SrPolicy, srv6tunnel *common.SRv6Tunnel, srnrli *bgpapi.SRPolicyNLRI, err error) {
	srnrli = &bgpapi.SRPolicyNLRI{}
	tun := &bgpapi.TunnelEncapAttribute{}
	subTLVSegList := &bgpapi.TunnelEncapSubTLVSRSegmentList{}
	segments := []bgpapi.SegmentTypeB{}
	srv6bsid := &bgpapi.SRBindingSID{}
	srv6tunnel = &common.SRv6Tunnel{}

	if err := ptypes.UnmarshalAny(path.Nlri, srnrli); err != nil {
		return nil, nil, nil, err
	}
	srv6tunnel.Dst = net.IP(srnrli.Endpoint)

	for _, pattr := range path.Pattrs {
		if err := ptypes.UnmarshalAny(pattr, tun); err == nil {
			for _, tlv := range tun.Tlvs {
				// unmarshal Tlvs
				for _, innerTlv := range tlv.Tlvs {
					// search for TunnelEncapSubTLVSRSegmentList
					if err := ptypes.UnmarshalAny(innerTlv, subTLVSegList); err == nil {
						for _, seglist := range subTLVSegList.Segments {
							segment := &bgpapi.SegmentTypeB{}
							if err = ptypes.UnmarshalAny(seglist, segment); err == nil {
								segments = append(segments, *segment)
							}
						}
					}
					// search for TunnelEncapSubTLVSRBindingSID
					srbsids := &anypb.Any{}
					if err := ptypes.UnmarshalAny(innerTlv, srbsids); err == nil {
						w.log.Debugf("getSRPolicy TunnelEncapSubTLVSRBindingSID")
						if err := ptypes.UnmarshalAny(srbsids, srv6bsid); err != nil {
							return nil, nil, nil, err
						}

					}

					// search for TunnelEncapSubTLVSRPriority
					subTLVSRPriority := &bgpapi.TunnelEncapSubTLVSRPriority{}
					if err := ptypes.UnmarshalAny(innerTlv, subTLVSRPriority); err == nil {
						w.log.Debugf("getSRPolicyPriority TunnelEncapSubTLVSRPriority")
						srv6tunnel.Priority = subTLVSRPriority.Priority
					}

				}
			}
		}

	}

	policySidListsids := [16]ip_types.IP6Address{}
	for i, segment := range segments {
		policySidListsids[i] = types.ToVppIP6Address(net.IP(segment.Sid))
	}
	srv6Policy = &types.SrPolicy{
		Bsid:     types.ToVppIP6Address(net.IP(srv6bsid.Sid)),
		IsSpray:  false,
		IsEncap:  true,
		FibTable: 0,
		SidLists: []types.Srv6SidList{{
			NumSids: uint8(len(segments)),
			Weight:  1,
			Sids:    policySidListsids,
		}},
	}
	srv6tunnel.Bsid = srv6Policy.Bsid.ToIP()
	srv6tunnel.Policy = srv6Policy

	srv6tunnel.Behavior = uint8(segments[len(segments)-1].GetEndpointBehaviorStructure().Behavior)

	return srv6Policy, srv6tunnel, srnrli, err
}

func (w *Server) injectSRv6Policy(path *bgpapi.Path) error {
	_, srv6tunnel, srnrli, err := w.getSRPolicy(path)

	if err != nil {
		return errors.Wrap(err, "error injectSRv6Policy")
	}

	cn := &common.NodeConnectivity{
		Dst:              net.IPNet{},
		NextHop:          srnrli.Endpoint,
		ResolvedProvider: "",
		Custom:           srv6tunnel,
	}
	if path.IsWithdraw {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.SRv6PolicyDeleted,
			Old:  cn,
		})
	} else {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.SRv6PolicyAdded,
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
				if f == &common.BgpFamilySRv6IPv6 {
					w.log.Debugf("Path SRv6")
					if err := w.injectSRv6Policy(path); err != nil {
						w.log.Errorf("cannot inject SRv6: %v", err)
					}
					return
				}
				if path.NeighborIp == "<nil>" { // Weird GoBGP API behaviour
					w.log.Debugf("Ignoring internal path")
					return
				}
				w.log.Infof("Got path update from=%s as=%d family=%s", path.SourceId, path.SourceAsn, f.String())
				if err := w.injectRoute(path); err != nil {
					w.log.Errorf("cannot inject route: %v", err)
				}
			},
		)
		return stopFunc, err
	}

	var stopV4Monitor, stopV6Monitor, stopSRv6IP6Monitor, stopV4VPNMonitor context.CancelFunc
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(w.nodeBGPSpec)
	if nodeIP4 != nil {
		stopV4Monitor, err = startMonitor(&common.BgpFamilyUnicastIPv4)
		if err != nil {
			return errors.Wrap(err, "error starting v4 path monitor")
		}
		stopV4VPNMonitor, err = startMonitor(&common.BgpFamilyUnicastIPv4VPN)
		if err != nil {
			return errors.Wrap(err, "error starting v4vpn path monitor")
		}
	}
	if nodeIP6 != nil {
		stopV6Monitor, err = startMonitor(&common.BgpFamilyUnicastIPv6)
		if err != nil {
			return errors.Wrap(err, "error starting SRv6IP6 path monitor")
		}
		if config.EnableSRv6 {
			stopSRv6IP6Monitor, err = startMonitor(&common.BgpFamilySRv6IPv6)
			if err != nil {
				return errors.Wrap(err, "error starting SRv6IP6 path monitor")
			}
		}

	}
	for {
		select {
		case <-t.Dying():
			if nodeIP4 != nil {
				stopV4Monitor()
				stopV4VPNMonitor()
			}
			if nodeIP6 != nil {
				stopV6Monitor()
				if config.EnableSRv6 {
					stopSRv6IP6Monitor()
				}
			}
			w.log.Infof("Routing Server asked to stop")
			return nil
		case evt := <-w.routingServerEventChan:
			/* Note: we will only receive events we ask for when registering the chan */
			switch evt.Type {
			case common.LocalNetworkPodAddressAdded:
				networkPod := evt.New.(cni.NetworkPod)
				err := w.announceLocalAddress(networkPod.ContainerIP, networkPod.NetworkVni)
				if err != nil {
					return err
				}
			case common.LocalPodAddressAdded:
				addr := evt.New.(*net.IPNet)
				err := w.announceLocalAddress(addr, 0)
				if err != nil {
					return err
				}
			case common.LocalPodAddressDeleted:
				addr := evt.Old.(*net.IPNet)
				err := w.withdrawLocalAddress(addr, 0)
				if err != nil {
					return err
				}
			case common.LocalNetworkPodAddressDeleted:
				networkPod := evt.Old.(cni.NetworkPod)
				err := w.withdrawLocalAddress(networkPod.ContainerIP, networkPod.NetworkVni)
				if err != nil {
					return err
				}
			case common.BGPReloadIP4:
				if nodeIP4 != nil {
					stopV4Monitor()
					stopV4Monitor, err = startMonitor(&common.BgpFamilyUnicastIPv4)
					if err != nil {
						return errors.Wrap(err, "error re-starting ip4 path monitor")
					}
					stopV4VPNMonitor()
					stopV4VPNMonitor, err = startMonitor(&common.BgpFamilyUnicastIPv4VPN)
					if err != nil {
						return errors.Wrap(err, "error re-starting ip4vpn path monitor")
					}
				}
			case common.BGPReloadIP6:
				if nodeIP6 != nil {
					stopV6Monitor()
					stopV6Monitor, err = startMonitor(&common.BgpFamilyUnicastIPv6)
					if err != nil {
						return errors.Wrap(err, "error re-starting ip6 path monitor")
					}
					if config.EnableSRv6 {
						stopSRv6IP6Monitor()
						stopSRv6IP6Monitor, err = startMonitor(&common.BgpFamilySRv6IPv6)
						if err != nil {
							return errors.Wrap(err, "error re-starting SRv6IP6 path monitor")
						}
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
				w.log.Infof("bgp(add) new neighbor=%s AS=%d",
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
				w.log.Infof("bgp(del) neighbor=%s", addr)
				err := w.BGPServer.DeletePeer(
					context.Background(),
					&bgpapi.DeletePeerRequest{Address: addr},
				)
				if err != nil {
					return err
				}
			case common.BGPPeerUpdated:
				peer := evt.New.(*bgpapi.Peer)
				w.log.Infof("bgp(upd) neighbor=%s AS=%d",
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
