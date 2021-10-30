package watchers

import (
	"context"
	bgpapi "github.com/osrg/gobgp/api"
	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/routing/common"
	"github.com/projectcalico/vpp-dataplane/vpplink/binapi/vppapi/ip_types"
	"github.com/projectcalico/vpp-dataplane/vpplink/types"
	"github.com/sirupsen/logrus"
	"time"

	"github.com/projectcalico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/libcalico-go/lib/net"
)

type LocalSIDWatcher struct {
	*common.RoutingData
	log *logrus.Entry
}

const (
	localSIDWatchInterval = 10 * time.Second
)

func (w *LocalSIDWatcher) WatchLocalSID() error {
	w.log.Infof("WatchLocalSID")
	time.Sleep(localSIDWatchInterval)

	assignedLocalSIDs := make(map[string]bool)
	for {
		list, err := w.Vpp.ListSRv6Localsid()
		if err != nil {
			return errors.Wrap(err, "error getting assigned SRv6 LocalSIDs")
		}
		for _, localsid := range list {
			w.log.Debugf("LocalSID: %s", localsid.String())
			if _, found := assignedLocalSIDs[localsid.Localsid.String()]; found {
				w.log.Debugf("Old assigned LocalSID: %s", localsid.Localsid.String())
			} else {
				w.log.Debugf("New assigned LocalSID: %s", localsid.Localsid.String())
				err := w.AdvertiseSRv6Policy(localsid)
				if err != nil {
					return errors.Wrap(err, "error advertising assigned SRv6 LocalSID")
				}
				time.Sleep(localSIDWatchInterval / 2)
				assignedLocalSIDs[localsid.Localsid.String()] = true
			}
		}
		time.Sleep(localSIDWatchInterval)
	}

	return nil
}

func (p *LocalSIDWatcher) AdvertiseSRv6Policy(localsid *types.SrLocalsid) (err error) {
	p.log.Infof("AdvertiseSRv6Policy for LocalSID: %s", localsid.Localsid.String())
	srpolicyBSID, err := p.getSidFromPool(config.SRv6policyIPPool)
	if err != nil {
		return errors.Wrap(err, "Error getSidFromPool")
	} else {
		var trafficType int
		if localsid.Behavior == types.SrBehaviorDT4 {
			trafficType = 4
		} else if localsid.Behavior == types.SrBehaviorDT6 {
			trafficType = 6
		}
		newPath, err := common.MakePathSRv6Tunnel(localsid.Localsid.ToIP(), srpolicyBSID.ToIP(), p.Ipv6, trafficType, false)
		if err == nil {
			_, err := p.BGPServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
				TableType: bgpapi.TableType_GLOBAL,
				Path:      newPath,
			})
			if err != nil {
				p.log.Errorf("SRv6Provider Error bgpserver.AddPath: %v", err)
			}

		}
	}

	return err
}

func (p *LocalSIDWatcher) getSidFromPool(ipnet string) (newSidAddr ip_types.IP6Address, err error) {
	poolIPNet := []cnet.IPNet{cnet.MustParseNetwork(ipnet)}
	_, newSids, err := p.Clientv3.IPAM().AutoAssign(context.Background(), ipam.AutoAssignArgs{
		Num6:      1,
		IPv6Pools: poolIPNet,
	})
	if err != nil || newSids == nil {
		p.log.Infof("SRv6Provider Error assigning ip LocalSid")
		return newSidAddr, errors.Wrapf(err, "SRv6Provider Error assigning ip LocalSid")
	}

	newSidAddr = types.ToVppIP6Address(newSids.IPs[0].IP)

	return newSidAddr, nil
}

func NewLocalSIDWatcher(routingData *common.RoutingData, log *logrus.Entry) *LocalSIDWatcher {
	w := &LocalSIDWatcher{
		RoutingData: routingData,
		log:         log,
	}
	w.log.Printf("NewLocalSIDWatcher")
	return w
}
