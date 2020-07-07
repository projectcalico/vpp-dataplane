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

package main

import (
	"encoding/gob"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/yookoala/realpath"
)

type interfaceConfig struct {
	PciId        string
	Driver       string
	IsUp         bool
	Addresses    []netlink.Addr
	Routes       []netlink.Route
	HardwareAddr net.HardwareAddr
	DoSwapDriver bool
	Hasv4        bool
	Hasv6        bool
	NodeIP4      string
	NodeIP6      string
}

func (c *interfaceConfig) AddressString() string {
	var str []string
	for _, addr := range c.Addresses {
		str = append(str, addr.String())
	}
	return strings.Join(str, ",")
}

func (c *interfaceConfig) RouteString() string {
	var str []string
	for _, route := range c.Routes {
		if route.Dst == nil {
			str = append(str, "<nil Dst>")
		} else {
			str = append(str, route.String())
		}
	}
	return strings.Join(str, ",")
}

func getInterfaceConfig() (err error) {
	conf, err := loadInterfaceConfigFromLinux()
	if err == nil {
		err = saveConfig(conf)
		if err != nil {
			log.Warnf("Could not save interface config: %v", err)
		}
	} else {
		// Loading config failed, try loading from save file
		log.Warnf("Could not load config from linux, trying file...")
		conf, err := loadInterfaceConfigFromFile()
		if err != nil {
			log.Warnf("Could not load saved config: %v", err)
			// Return original error
			return err
		}
		log.Infof("Loaded config. Interface marked as down since loading config from linux failed.")
		// This ensures we don't try to set the interface down in runVpp()
		conf.IsUp = false
	}
	initialConfig = conf
	return nil
}

func loadInterfaceConfigFromLinux() (*interfaceConfig, error) {
	conf := interfaceConfig{}
	link, err := netlink.LinkByName(params.mainInterface)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot find interface named %s", params.mainInterface)
	}
	conf.IsUp = (link.Attrs().Flags & net.FlagUp) != 0
	if conf.IsUp {
		// Grab addresses and routes
		conf.Addresses, err = netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot list %s addresses", params.mainInterface)
		}
		conf.Routes, err = netlink.RouteList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot list %s routes", params.mainInterface)
		}
	}
	conf.HardwareAddr = link.Attrs().HardwareAddr
	conf.NodeIP4 = getNodeAddress(&conf, false /* isV6 */)
	conf.NodeIP6 = getNodeAddress(&conf, true /* isV6 */)
	conf.Hasv4 = (conf.NodeIP4 != "")
	conf.Hasv6 = (conf.NodeIP6 != "")
	if !conf.Hasv4 && !conf.Hasv6 {
		return nil, errors.Errorf("no address found for node")
	}

	// We allow PCI not to be found e.g for AF_PACKET
	// Grab PCI id - last PCI id in the real path to /sys/class/net/<device name>
	deviceLinkPath := fmt.Sprintf("/sys/class/net/%s/device", params.mainInterface)
	devicePath, err := realpath.Realpath(deviceLinkPath)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot resolve pci device path for %s", params.mainInterface)
	}
	pciID := regexp.MustCompile("[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}.[0-9a-f]")
	conf.DoSwapDriver = false
	matches := pciID.FindAllString(devicePath, -1)
	if matches == nil {
		log.Warnf("Could not find pci device for %s: path is %s", params.mainInterface, devicePath)
	} else {
		conf.PciId = matches[len(matches)-1]
		// Grab Driver id for the pci device
		driverLinkPath := fmt.Sprintf("/sys/bus/pci/devices/%s/driver", conf.PciId)
		driverPath, err := os.Readlink(driverLinkPath)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot find driver for %s", conf.PciId)
		}
		conf.Driver = driverPath[strings.LastIndex(driverPath, "/")+1:]
		if params.newDriverName != "" && params.newDriverName != conf.Driver {
			conf.DoSwapDriver = true
		}
	}
	return &conf, nil
}

func getNodeAddress(conf *interfaceConfig, isV6 bool) string {
	for _, addr := range conf.Addresses {
		if vpplink.IsIP6(addr.IP) == isV6 {
			if !isV6 || !addr.IP.IsLinkLocalUnicast() {
				return addr.IPNet.String()
			}
		}
	}
	return ""
}

func clearSavedConfig() {
	if params.ifConfigSavePath == "" {
		return
	}
	err := os.Remove(params.ifConfigSavePath)
	if err != nil {
		log.Warnf("could not delete saved interface config: %v", err)
	}
}

func saveConfig(conf *interfaceConfig) error {
	if params.ifConfigSavePath == "" {
		return nil
	}
	file, err := os.Create(params.ifConfigSavePath)
	if err != nil {
		return errors.Wrap(err, "error opening save file")
	}
	enc := gob.NewEncoder(file)
	err = enc.Encode(*conf)
	if err != nil {
		file.Close()
		clearSavedConfig()
		return errors.Wrap(err, "error encoding data")
	}
	err = file.Close()
	if err != nil {
		return errors.Wrap(err, "error closing file")
	}
	return nil
}

func loadInterfaceConfigFromFile() (*interfaceConfig, error) {
	conf := interfaceConfig{}
	if params.ifConfigSavePath == "" {
		return nil, fmt.Errorf("interface config save file not configured")
	}
	file, err := os.Open(params.ifConfigSavePath)
	if err != nil {
		return nil, errors.Wrap(err, "error opening save file")
	}
	dec := gob.NewDecoder(file)
	err = dec.Decode(&conf)
	if err != nil {
		return nil, errors.Wrap(err, "decode error")
	}
	file.Close()
	return &conf, nil
}
