package watchers

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type LocalSIDWatcher struct {
	log         *logrus.Entry
	vpp         *vpplink.VppLink
	clientv3    calicov3cli.Interface
	nodeBGPSpec *common.LocalNodeSpec
}

const (
	localSIDWatchInterval = 10 * time.Second
)

func (w *LocalSIDWatcher) WatchLocalSID(t *tomb.Tomb) error {
	w.log.Infof("WatchLocalSID")
	time.Sleep(localSIDWatchInterval)

	assignedLocalSIDs := make(map[string]bool)
	for t.Alive() {
		list, err := w.vpp.ListSRv6Localsid()
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

func (w *LocalSIDWatcher) AdvertiseSRv6Policy(localsid *types.SrLocalsid) (err error) {
	w.log.Infof("AdvertiseSRv6Policy for LocalSID: %s", localsid.Localsid.String())
	srpolicyBSID, err := w.getSidFromPool(config.GetCalicoVppSrv6().PolicyPool)
	if err != nil {
		return errors.Wrap(err, "Error getSidFromPool")
	} else {
		trafficType := 4
		switch localsid.Behavior {
		case types.SrBehaviorDT4: // use 4
		case types.SrBehaviorDT6:
			trafficType = 6
		}
		_, nodeIPv6 := common.GetBGPSpecAddresses(w.nodeBGPSpec)
		if nodeIPv6 == nil {
			return fmt.Errorf("no ip6 found for node")
		}
		newPath, err := common.MakePathSRv6Tunnel(localsid.Localsid.ToIP(), srpolicyBSID.ToIP(), *nodeIPv6, trafficType, false)
		if err == nil {
			common.SendEvent(common.CalicoVppEvent{
				Type: common.BGPPathAdded,
				New:  newPath,
			})
		}
	}

	return err
}

func (w *LocalSIDWatcher) getSidFromPool(ipnet string) (newSidAddr ip_types.IP6Address, err error) {
	poolIPNet := []cnet.IPNet{cnet.MustParseNetwork(ipnet)}
	_, newSids, err := w.clientv3.IPAM().AutoAssign(context.Background(), ipam.AutoAssignArgs{
		Num6:        1,
		IPv6Pools:   poolIPNet,
		IntendedUse: "Tunnel",
	})
	if err != nil || newSids == nil {
		w.log.Infof("SRv6Provider Error assigning ip LocalSid")
		return newSidAddr, errors.Wrapf(err, "SRv6Provider Error assigning ip LocalSid")
	}

	newSidAddr = types.ToVppIP6Address(newSids.IPs[0].IP)

	return newSidAddr, nil
}

func (w *LocalSIDWatcher) SetOurBGPSpec(nodeBGPSpec *common.LocalNodeSpec) {
	w.nodeBGPSpec = nodeBGPSpec
}

func NewLocalSIDWatcher(vpp *vpplink.VppLink, clientv3 calicov3cli.Interface, log *logrus.Entry) *LocalSIDWatcher {
	w := &LocalSIDWatcher{
		vpp:      vpp,
		log:      log,
		clientv3: clientv3,
	}
	return w
}
