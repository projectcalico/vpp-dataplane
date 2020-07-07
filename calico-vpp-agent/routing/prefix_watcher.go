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

package routing

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/config"
	"github.com/golang/protobuf/ptypes"
	bgpapi "github.com/osrg/gobgp/api"
	"github.com/pkg/errors"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"golang.org/x/net/context"
)

// watchPrefix watches etcd /calico/ipam/v2/host/$NODENAME and add/delete
// aggregated routes which are assigned to the node.
// This function also updates policy appropriately.
func (s *Server) watchPrefix() error {
	assignedPrefixes := make(map[string]bool)
	// There is no need to react instantly to these changes, and the calico API
	// doesn't provide a way to watch for changes, so we just poll every minute
	for {
		s.log.Debugf("Reconciliating prefix affinities...")
		newPrefixes, err := s.getAssignedPrefixes()
		if err != nil {
			return errors.Wrap(err, "error getting assigned prefixes")
		}
		s.log.Debugf("Found %d assigned prefixes", len(newPrefixes))
		newAssignedPrefixes := make(map[string]bool)
		var toAdd []*bgpapi.Path
		for _, prefix := range newPrefixes {
			if _, found := assignedPrefixes[prefix]; found {
				s.log.Debugf("Prefix %s is still assigned to us", prefix)
				assignedPrefixes[prefix] = true     // Prefix is still there, set value to true so we don't delete it
				newAssignedPrefixes[prefix] = false // Record it in new map
			} else {
				s.log.Debugf("New assigned prefix: %s", prefix)
				newAssignedPrefixes[prefix] = false
				path, err := s.makePath(prefix, false)
				if err != nil {
					return errors.Wrap(err, "error making new path for assigned prefix")
				}
				toAdd = append(toAdd, path)
			}
		}
		if err = s.updateBGPPaths(toAdd); err != nil {
			return errors.Wrap(err, "error adding prefix announcements")
		}
		// Remove paths that don't exist anymore
		var toRemove []*bgpapi.Path
		for p, stillThere := range assignedPrefixes {
			if !stillThere {
				s.log.Infof("Prefix %s is not assigned to us anymore", p)
				path, err := s.makePath(p, true)
				if err != nil {
					return errors.Wrap(err, "error making new path for removed prefix")
				}
				toRemove = append(toRemove, path)
			}
		}
		if err = s.updateBGPPaths(toRemove); err != nil {
			return errors.Wrap(err, "error removing prefix announcements")
		}
		assignedPrefixes = newAssignedPrefixes

		time.Sleep(prefixWatchInterval)
	}
	return nil
}

// getAssignedPrefixes retrives prefixes assigned to the node and returns them as a
// list of BGP path.
// using backend directly since libcalico-go doesn't seem to have a method to return
// assigned prefixes yet.
func (s *Server) getAssignedPrefixes() ([]string, error) {
	var ps []string

	f := func(ipVersion int) error {
		blockList, err := s.client.Backend.List(
			context.Background(),
			model.BlockAffinityListOptions{Host: config.NodeName, IPVersion: ipVersion},
			"",
		)
		if err != nil {
			return err
		}
		for _, block := range blockList.KVPairs {
			s.log.Debugf("Found assigned prefix: %+v", block)
			key := block.Key.(model.BlockAffinityKey)
			value := block.Value.(*model.BlockAffinity)
			if value.State == model.StateConfirmed && !value.Deleted {
				ps = append(ps, key.CIDR.String())
			}
		}
		return nil
	}

	if s.ipv4 != nil {
		if err := f(4); err != nil {
			return nil, err
		}
	}
	if s.ipv6 != nil {
		if err := f(6); err != nil {
			return nil, err
		}
	}
	return ps, nil
}

// TODO rename this
func (s *Server) updateBGPPaths(paths []*bgpapi.Path) error {
	for _, path := range paths {
		err := s.updateOneBGPPath(path)
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
func (s *Server) updateOneBGPPath(path *bgpapi.Path) error {
	s.log.Infof("Updating local prefix set with %+v", path)
	ipAddrPrefixNlri := &bgpapi.IPAddressPrefix{}
	var prefixAddr string = ""
	var prefixLen uint32 = 0xffff
	var err error = nil
	if err := ptypes.UnmarshalAny(path.Nlri, ipAddrPrefixNlri); err == nil {
		prefixAddr = ipAddrPrefixNlri.Prefix
		prefixLen = ipAddrPrefixNlri.PrefixLen
	} else {
		return fmt.Errorf("Cannot handle Nlri: %+v", path.Nlri)
	}
	del := path.IsWithdraw
	prefix := prefixAddr + "/" + strconv.FormatUint(uint64(prefixLen), 10)
	// Add path to aggregated prefix set, allowing to export it
	ps := &bgpapi.DefinedSet{
		DefinedType: bgpapi.DefinedType_PREFIX,
		Name:        aggregatedPrefixSetName,
		Prefixes: []*bgpapi.Prefix{
			&bgpapi.Prefix{
				IpPrefix:      prefix,
				MaskLengthMin: prefixLen,
				MaskLengthMax: prefixLen,
			},
		},
	}
	if del {
		err = s.bgpServer.DeleteDefinedSet(
			context.Background(),
			&bgpapi.DeleteDefinedSetRequest{DefinedSet: ps, All: false},
		)
	} else {
		err = s.bgpServer.AddDefinedSet(
			context.Background(),
			&bgpapi.AddDefinedSetRequest{DefinedSet: ps},
		)
	}
	if err != nil {
		return errors.Wrapf(err, "error adding / deleting defined set %+v", ps)
	}
	// Add all contained prefixes to host prefix set, forbidding the export of containers /32s or /128s
	max := uint32(32)
	if strings.Contains(prefixAddr, ":") {
		s.log.Debugf("Address %s detected as v6", prefixAddr)
		max = 128
	}
	ps = &bgpapi.DefinedSet{
		DefinedType: bgpapi.DefinedType_PREFIX,
		Name:        hostPrefixSetName,
		Prefixes: []*bgpapi.Prefix{
			&bgpapi.Prefix{
				IpPrefix:      prefix,
				MaskLengthMax: max,
				MaskLengthMin: prefixLen,
			},
		},
	}
	if del {
		err = s.bgpServer.DeleteDefinedSet(
			context.Background(),
			&bgpapi.DeleteDefinedSetRequest{DefinedSet: ps, All: false},
		)
	} else {
		err = s.bgpServer.AddDefinedSet(
			context.Background(),
			&bgpapi.AddDefinedSetRequest{DefinedSet: ps},
		)
	}
	if err != nil {
		return errors.Wrapf(err, "error adding / deleting defined set %+v", ps)
	}

	// Finally add/remove path to/from the main table to annouce it to our peers
	if del {
		err = s.bgpServer.DeletePath(context.Background(), &bgpapi.DeletePathRequest{
			TableType: bgpapi.TableType_GLOBAL,
			Path:      path,
		})
	} else {
		_, err = s.bgpServer.AddPath(context.Background(), &bgpapi.AddPathRequest{
			TableType: bgpapi.TableType_GLOBAL,
			Path:      path,
		})
	}

	return errors.Wrapf(err, "error adding / deleting path %+v", path)
}
