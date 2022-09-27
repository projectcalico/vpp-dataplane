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

package startup

import (
	"encoding/gob"
	"fmt"
	"net"
	"os"

	"github.com/pkg/errors"
	common_config "github.com/projectcalico/vpp-dataplane/common-config"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/config"
	"github.com/projectcalico/vpp-dataplane/vpp-manager/utils"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func getInterfaceConfig(params *config.VppManagerParams) (conf []*config.LinuxInterfaceState, err error) {
	errs := []error{}
	conf = []*config.LinuxInterfaceState{}
	for _, ifSpec := range params.UplinksSpecs {
		configuration, err := loadInterfaceConfigFromLinux(ifSpec)
		errs = append(errs, err)
		conf = append(conf, configuration)
	}
	allLoaded := true
	for i := range errs {
		if errs[i] != nil {
			allLoaded = false
			log.Warnf("Could not load config from linux (%v)", errs[i])
		}
	}
	if allLoaded {
		err = saveConfig(params, conf)
		if err != nil {
			log.Warnf("Could not save interface config: %v", err)
		}
	} else {
		// Loading config failed, try loading from save file
		confFile, err2 := loadInterfaceConfigFromFile(params)
		if err2 != nil {
			return nil, err2
		}
		// If loaded from file replace non loaded interface configs
		for i := range conf {
			if conf[i] == nil {
				for j := range confFile {
					if confFile[j].InterfaceName == params.UplinksSpecs[i].InterfaceName {
						conf[i] = confFile[j]
					}
				}
			}
		}
		for i := range conf {
			if conf[i] == nil {
				return nil, fmt.Errorf("interface configs not found")
			}
		}
		log.Infof("Loaded config. Interfaces marked as down since loading config from linux failed.")
		// This ensures we don't try to set the interface down in runVpp()
		for _, config := range conf {
			config.IsUp = false
		}
	}
	return conf, nil
}

func loadInterfaceConfigFromLinux(ifSpec common_config.UplinkInterfaceSpec) (*config.LinuxInterfaceState, error) {
	conf := config.LinuxInterfaceState{}
	link, err := netlink.LinkByName(ifSpec.InterfaceName)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot find interface named %s", ifSpec.InterfaceName)
	}
	conf.IsUp = (link.Attrs().Flags & net.FlagUp) != 0
	if conf.IsUp {
		// Grab addresses and routes
		conf.Addresses, err = netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot list %s addresses", ifSpec.InterfaceName)
		}

		conf.Routes, err = netlink.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot list %s routes", ifSpec.InterfaceName)
		}
		conf.SortRoutes()
	}
	conf.HardwareAddr = link.Attrs().HardwareAddr
	conf.NodeIP4 = getNodeAddress(&conf, false /* isV6 */)
	conf.NodeIP6 = getNodeAddress(&conf, true /* isV6 */)
	conf.Hasv4 = (conf.NodeIP4 != "")
	conf.Hasv6 = (conf.NodeIP6 != "")
	if !conf.Hasv4 && !conf.Hasv6 {
		return nil, errors.Errorf("no address found for node")
	}

	conf.DoSwapDriver = false
	conf.PromiscOn = link.Attrs().Promisc == 1
	conf.NumTxQueues = link.Attrs().NumTxQueues
	conf.NumRxQueues = link.Attrs().NumRxQueues
	conf.Mtu = link.Attrs().MTU
	_, conf.IsTunTap = link.(*netlink.Tuntap)
	_, conf.IsVeth = link.(*netlink.Veth)

	pciId, err := utils.GetInterfacePciId(ifSpec.InterfaceName)
	// We allow PCI not to be found e.g for AF_PACKET
	if err != nil || pciId == "" {
		log.Warnf("Could not find pci device for %s", ifSpec.InterfaceName)
	} else {
		conf.PciId = pciId
		driver, err := utils.GetDriverNameFromPci(pciId)
		if err != nil {
			return nil, err
		}
		conf.Driver = driver
		if ifSpec.NewDriverName != "" && ifSpec.NewDriverName != conf.Driver {
			conf.DoSwapDriver = true
		}
	}
	conf.InterfaceName = ifSpec.InterfaceName
	return &conf, nil
}

func getNodeAddress(conf *config.LinuxInterfaceState, isV6 bool) string {
	for _, addr := range conf.Addresses {
		if vpplink.IsIP6(addr.IP) == isV6 {
			if !isV6 || !addr.IP.IsLinkLocalUnicast() {
				return addr.IPNet.String()
			}
		}
	}
	return ""
}

func clearSavedConfig(params *config.VppManagerParams) {
	if params.IfConfigSavePath == "" {
		return
	}
	err := os.Remove(params.IfConfigSavePath)
	if err != nil {
		log.Warnf("could not delete saved interface config: %v", err)
	}
}

func saveConfig(params *config.VppManagerParams, conf []*config.LinuxInterfaceState) error {
	if params.IfConfigSavePath == "" {
		return nil
	}
	file, err := os.Create(params.IfConfigSavePath)
	if err != nil {
		return errors.Wrap(err, "error opening save file")
	}
	enc := gob.NewEncoder(file)
	err = enc.Encode(conf)
	if err != nil {
		file.Close()
		clearSavedConfig(params)
		return errors.Wrap(err, "error encoding data")
	}
	err = file.Close()
	if err != nil {
		return errors.Wrap(err, "error closing file")
	}
	return nil
}

func loadInterfaceConfigFromFile(params *config.VppManagerParams) ([]*config.LinuxInterfaceState, error) {
	conf := []*config.LinuxInterfaceState{}
	if params.IfConfigSavePath == "" {
		return nil, fmt.Errorf("interface config save file not configured")
	}
	file, err := os.Open(params.IfConfigSavePath)
	if err != nil {
		return nil, errors.Wrap(err, "error opening save file")
	}
	dec := gob.NewDecoder(file)
	err = dec.Decode(&conf)
	if err != nil {
		return nil, errors.Wrap(err, "decode error")
	}
	file.Close()
	return conf, nil
}
