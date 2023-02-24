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

	bgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
	"google.golang.org/protobuf/types/known/anypb"
	tomb "gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"

	// needed for GoBGP building (in ../Makefile, gobgp target)
	_ "github.com/inconshreveable/mousetrap"
	_ "github.com/spf13/cobra"
)

func (w *Server) getNexthop(path *bgpapi.Path) string {
	for _, attr := range path.Pattrs {
		nhAttr := &bgpapi.NextHopAttribute{}
		mpReachAttr := &bgpapi.MpReachNLRIAttribute{}
		if err := attr.UnmarshalTo(nhAttr); err == nil {
			return nhAttr.NextHop
		}
		if err := attr.UnmarshalTo(mpReachAttr); err == nil {
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

	if err := path.Nlri.UnmarshalTo(ipAddrPrefixNlri); err == nil {
		dst.IP = net.ParseIP(ipAddrPrefixNlri.Prefix)
		if dst.IP == nil {
			return fmt.Errorf("Cannot parse nlri addr: %s", ipAddrPrefixNlri.Prefix)
		} else if dst.IP.To4() == nil {
			dst.Mask = net.CIDRMask(int(ipAddrPrefixNlri.PrefixLen), 128)
		} else {
			dst.Mask = net.CIDRMask(int(ipAddrPrefixNlri.PrefixLen), 32)
		}
	} else {
		err := path.Nlri.UnmarshalTo(labeledVPNIPAddressPrefixNlri)
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
		rd := &bgpapi.RouteDistinguisherTwoOctetASN{}
		err := labeledVPNIPAddressPrefixNlri.Rd.UnmarshalTo(rd)
		if err != nil {
			return errors.Wrap(err, "Error Unmarshalling labeledVPNIPAddressPrefixNlri.Rd")
		}
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
	segments := []*bgpapi.SegmentTypeB{}
	srv6bsid := &bgpapi.SRBindingSID{}
	srv6tunnel = &common.SRv6Tunnel{}

	if err := path.Nlri.UnmarshalTo(srnrli); err != nil {
		return nil, nil, nil, err
	}
	srv6tunnel.Dst = net.IP(srnrli.Endpoint)

	for _, pattr := range path.Pattrs {
		if err := pattr.UnmarshalTo(tun); err == nil {
			for _, tlv := range tun.Tlvs {
				// unmarshal Tlvs
				for _, innerTlv := range tlv.Tlvs {
					// search for TunnelEncapSubTLVSRSegmentList
					if err := innerTlv.UnmarshalTo(subTLVSegList); err == nil {
						for _, seglist := range subTLVSegList.Segments {
							segment := &bgpapi.SegmentTypeB{}
							if err = seglist.UnmarshalTo(segment); err == nil {
								segments = append(segments, segment)
							}
						}
					}
					// search for TunnelEncapSubTLVSRBindingSID
					srbsids := &anypb.Any{}
					if err := innerTlv.UnmarshalTo(srbsids); err == nil {
						w.log.Debugf("getSRPolicy TunnelEncapSubTLVSRBindingSID")
						if err := srbsids.UnmarshalTo(srv6bsid); err != nil {
							return nil, nil, nil, err
						}

					}

					// search for TunnelEncapSubTLVSRPriority
					subTLVSRPriority := &bgpapi.TunnelEncapSubTLVSRPriority{}
					if err := innerTlv.UnmarshalTo(subTLVSRPriority); err == nil {
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

func (w *Server) startBGPMonitoring() (func(), error) {
	nodeIP4, nodeIP6 := common.GetBGPSpecAddresses(w.nodeBGPSpec)
	ctx, stopFunc := context.WithCancel(context.Background())
	err := w.BGPServer.WatchEvent(ctx,
		&bgpapi.WatchEventRequest{
			Table: &bgpapi.WatchEventRequest_Table{
				Filters: []*bgpapi.WatchEventRequest_Table_Filter{{
					Type: bgpapi.WatchEventRequest_Table_Filter_BEST,
				}},
			},
		},
		func(r *bgpapi.WatchEventResponse) {
			if table := r.GetTable(); table != nil {
				for _, path := range table.GetPaths() {
					if path == nil || path.GetFamily() == nil {
						w.log.Warnf("nil path update, skipping")
						continue
					}
					if nodeIP4 == nil && path.GetFamily().Afi == bgpapi.Family_AFI_IP {
						w.log.Debugf("Ignoring ipv4 path with no node ip4")
						continue
					}
					if nodeIP6 == nil && path.GetFamily().Afi == bgpapi.Family_AFI_IP6 {
						w.log.Debugf("Ignoring ipv6 path with no node ip6")
						continue
					}
					if path.GetNeighborIp() == "<nil>" || path.GetNeighborIp() == "" { // Weird GoBGP API behaviour
						w.log.Debugf("Ignoring internal path")
						continue
					}
					if *config.GetCalicoVppFeatureGates().SRv6Enabled && path.GetFamily() == &common.BgpFamilySRv6IPv6 {
						w.log.Debugf("Path SRv6")
						err := w.injectSRv6Policy(path)
						if err != nil {
							w.log.Errorf("cannot inject SRv6: %v", err)
						}
						continue
					}
					w.log.Infof("Got path update from=%s as=%d family=%s", path.GetSourceId(), path.GetSourceAsn(), path.GetFamily())
					err := w.injectRoute(path)
					if err != nil {
						w.log.Errorf("cannot inject route: %v", err)
					}
				}
			}
		},
	)
	return stopFunc, err
}

// watchBGPPath watches BGP routes from other peers and inject them into linux kernel
// TODO: multipath support
func (w *Server) WatchBGPPath(t *tomb.Tomb) error {
	stopBGPMonitoring, err := w.startBGPMonitoring()
	if err != nil {
		return errors.Wrap(err, "error starting BGP monitoring")
	}

	for {
		select {
		case <-t.Dying():
			stopBGPMonitoring()
			w.log.Infof("Routing Server asked to stop")
			return nil
		case evt := <-w.routingServerEventChan:
			/* Note: we will only receive events we ask for when registering the chan */
			switch evt.Type {
			case common.LocalPodAddressAdded:
				networkPod := evt.New.(cni.NetworkPod)
				err := w.announceLocalAddress(networkPod.ContainerIP, networkPod.NetworkVni)
				if err != nil {
					return err
				}
			case common.LocalPodAddressDeleted:
				networkPod := evt.Old.(cni.NetworkPod)
				err := w.withdrawLocalAddress(networkPod.ContainerIP, networkPod.NetworkVni)
				if err != nil {
					return err
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
					peer.Conf.NeighborAddress, peer.Conf.PeerAsn)
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
					peer.Conf.NeighborAddress, peer.Conf.PeerAsn)
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
