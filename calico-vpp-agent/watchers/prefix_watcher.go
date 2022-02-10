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
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes"
	bgpapi "github.com/osrg/gobgp/api"
	"github.com/pkg/errors"
	oldv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"

	calicocli "github.com/projectcalico/calico/libcalico-go/lib/client"
	tomb "gopkg.in/tomb.v2"
)

type PrefixWatcher struct {
	log         *logrus.Entry
	client      *calicocli.Client
	nodeBGPSpec *oldv3.NodeBGPSpec
}

const (
	prefixWatchInterval = 5 * time.Second
)

// watchPrefix watches etcd /calico/ipam/v2/host/$NODENAME and add/delete
// aggregated routes which are assigned to the node.
// This function also updates policy appropriately.
func (w *PrefixWatcher) WatchPrefix(t *tomb.Tomb) error {
	assignedPrefixes := make(map[string]bool)
	// There is no need to react instantly to these changes, and the calico API
	// doesn't provide a way to watch for changes, so we just poll every minute
	for t.Alive() {
	restart:
		w.log.Debugf("Reconciliating prefix affinities...")
		newPrefixes, err := w.getAssignedPrefixes()
		if err != nil {
			w.log.Errorf("error getting assigned prefixes %v", err)
			time.Sleep(3 * time.Second)
			goto restart
		}
		w.log.Debugf("Found %d assigned prefixes", len(newPrefixes))
		newAssignedPrefixes := make(map[string]bool)
		var toAdd []*bgpapi.Path
		for _, prefix := range newPrefixes {
			if _, found := assignedPrefixes[prefix]; found {
				w.log.Debugf("Prefix %s is still assigned to us", prefix)
				assignedPrefixes[prefix] = true     // Prefix is still there, set value to true so we don't delete it
				newAssignedPrefixes[prefix] = false // Record it in new map
			} else {
				w.log.Debugf("New assigned prefix: %s", prefix)
				newAssignedPrefixes[prefix] = false
				ip4, ip6 := common.GetBGPSpecAddresses(w.nodeBGPSpec)
				path, err := common.MakePath(prefix, false /* isWithdrawal */, ip4, ip6, 0)
				if err != nil {
					return errors.Wrap(err, "error making new path for assigned prefix")
				}
				toAdd = append(toAdd, path)
			}
		}
		if err = w.updateBGPPaths(toAdd); err != nil {
			return errors.Wrap(err, "error adding prefix announcements")
		}
		// Remove paths that don't exist anymore
		var toRemove []*bgpapi.Path
		for p, stillThere := range assignedPrefixes {
			if !stillThere {
				w.log.Infof("Prefix %s is not assigned to us anymore", p)
				ip4, ip6 := common.GetBGPSpecAddresses(w.nodeBGPSpec)
				path, err := common.MakePath(p, true /* isWithdrawal */, ip4, ip6, 0)
				if err != nil {
					return errors.Wrap(err, "error making new path for removed prefix")
				}
				toRemove = append(toRemove, path)
			}
		}
		if err = w.updateBGPPaths(toRemove); err != nil {
			return errors.Wrap(err, "error removing prefix announcements")
		}
		assignedPrefixes = newAssignedPrefixes

		time.Sleep(prefixWatchInterval)
	}

	w.log.Infof("Prefix Watcher asked to exit")

	return nil
}

// getAssignedPrefixes retrives prefixes assigned to the node and returns them as a
// list of BGP path.
// using backend directly since libcalico-go doesn't seem to have a method to return
// assigned prefixes yet.
func (w *PrefixWatcher) getAssignedPrefixes() ([]string, error) {
	var ps []string

	f := func(ipVersion int) error {
		blockList, err := w.client.Backend.List(
			context.Background(),
			model.BlockAffinityListOptions{Host: config.NodeName, IPVersion: ipVersion},
			"",
		)
		if err != nil {
			return err
		}
		for _, block := range blockList.KVPairs {
			w.log.Debugf("Found assigned prefix: %+v", block)
			key := block.Key.(model.BlockAffinityKey)
			value := block.Value.(*model.BlockAffinity)
			if value.State == model.StateConfirmed && !value.Deleted {
				ps = append(ps, key.CIDR.String())
			}
		}
		return nil
	}

	ip4, ip6 := common.GetBGPSpecAddresses(w.nodeBGPSpec)
	if ip4 != nil {
		if err := f(4); err != nil {
			return nil, err
		}
	}
	if ip6 != nil {
		if err := f(6); err != nil {
			return nil, err
		}
	}
	return ps, nil
}

// TODO rename this
func (w *PrefixWatcher) updateBGPPaths(paths []*bgpapi.Path) error {
	for _, path := range paths {
		err := w.updateOneBGPPath(path)
		if err != nil {
			return errors.Wrapf(err, "error processing path %+v", path)
		}
	}
	return nil
}

// _updatePrefixSet updates 'aggregated' and 'host' prefix-sets
// we add the exact prefix to 'aggregated' set, and add corresponding longer
// prefixes to 'host' set.
//
// e.g. prefix: "192.168.1.0/26" del: false
//      add "192.168.1.0/26"     to 'aggregated' set
//      add "192.168.1.0/26..32" to 'host'       set
//
func (w *PrefixWatcher) updateOneBGPPath(path *bgpapi.Path) error {
	ipAddrPrefixNlri := &bgpapi.IPAddressPrefix{}
	err := ptypes.UnmarshalAny(path.Nlri, ipAddrPrefixNlri)
	if err != nil {
		return fmt.Errorf("Cannot handle Nlri: %+v", path.Nlri)
	}
	prefixLen := ipAddrPrefixNlri.PrefixLen
	prefixAddr := ipAddrPrefixNlri.Prefix
	isv6 := strings.Contains(prefixAddr, ":")
	del := path.IsWithdraw
	prefix := prefixAddr + "/" + strconv.FormatUint(uint64(prefixLen), 10)
	w.log.Infof("Updating local prefix set with %s", prefix)
	// Add path to aggregated prefix set, allowing to export it
	ps := &bgpapi.DefinedSet{
		DefinedType: bgpapi.DefinedType_PREFIX,
		Name:        common.GetAggPrefixSetName(isv6),
		Prefixes: []*bgpapi.Prefix{
			&bgpapi.Prefix{
				IpPrefix:      prefix,
				MaskLengthMin: prefixLen,
				MaskLengthMax: prefixLen,
			},
		},
	}
	if del {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.BGPDefinedSetDeleted,
			Old:  ps,
		})
	} else {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.BGPDefinedSetAdded,
			New:  ps,
		})
	}
	// Add all contained prefixes to host prefix set, forbidding the export of containers /32s or /128s
	max := uint32(32)
	if isv6 {
		w.log.Debugf("Address %s detected as v6", prefixAddr)
		max = 128
	}
	ps = &bgpapi.DefinedSet{
		DefinedType: bgpapi.DefinedType_PREFIX,
		Name:        common.GetHostPrefixSetName(isv6),
		Prefixes: []*bgpapi.Prefix{
			&bgpapi.Prefix{
				IpPrefix:      prefix,
				MaskLengthMax: max,
				MaskLengthMin: prefixLen,
			},
		},
	}
	if del {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.BGPDefinedSetDeleted,
			Old:  ps,
		})
	} else {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.BGPDefinedSetAdded,
			New:  ps,
		})
	}

	// Finally add/remove path to/from the main table to annouce it to our peers
	if del {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.BGPPathDeleted,
			Old:  path,
		})
	} else {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.BGPPathAdded,
			New:  path,
		})
	}

	return nil
}

func (w *PrefixWatcher) SetOurBGPSpec(nodeBGPSpec *oldv3.NodeBGPSpec) {
	w.nodeBGPSpec = nodeBGPSpec
}

func NewPrefixWatcher(client *calicocli.Client, log *logrus.Entry) *PrefixWatcher {
	w := PrefixWatcher{
		client: client,
		log:    log,
	}
	return &w
}
