// Copyright (C) 2022 Cisco Systems Inc.
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

package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	apipb "github.com/osrg/gobgp/v3/api"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type EnvVarParser struct {
	parse       func() error
	valueString string
}

var (
	parsers = make(map[string]*EnvVarParser)
)

func PrintEnvVarConfig(log *logrus.Logger) {
	for varName, parser := range parsers {
		log.Infof("Config:%s=%s", varName, parser.valueString)
	}
}

func ParseAllEnvVars() []error {
	errs := make([]error, 0)
	for _, parser := range parsers {
		err := parser.parse()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func ParseEnvVars(varNames ...string) []error {
	errs := make([]error, 0)
	for _, varName := range varNames {
		parser, found := parsers[varName]
		if found {
			err := parser.parse()
			if err != nil {
				errs = append(errs, err)
			}
		} else {
			errs = append(errs, errors.Errorf("No parser found for varName %s", varName))
		}
	}
	return errs
}

func isEnvVarSupported(str string) bool {
	_, found := parsers[str]
	return found
}

type Validable interface {
	Validate() error
}

func envVar[T any](varName string, defaultValue T, required bool, parser func(string) (T, error)) *T {
	v := defaultValue
	p := &EnvVarParser{valueString: fmt.Sprintf("%v", v)}
	parsers[varName] = p
	p.parse = func() error {
		if value := os.Getenv(varName); value != "" {
			var err error
			v, err = parser(value)
			if err != nil {
				return errors.Wrapf(err, "Failed to parse %s: %s, defaulting...", varName, value)
			}
		} else if required {
			return errors.Errorf("Missing required environment variable %s", varName)
		}
		p.valueString = fmt.Sprintf("%v", v)
		// If the variable type implements Validable, we run it as part of the parsing process.
		// this enables setting default values, or asserting type constraints
		if va, ok := any(v).(Validable); ok {
			err := va.Validate()
			if err != nil {
				return errors.Errorf("Failed to validate environment variable %s", varName)
			}
		}
		return nil
	}
	return &v
}

func EnvVar[T any](varName string, defaultValue T, parser func(string) (T, error)) *T {
	return envVar(varName, defaultValue, false /*required*/, parser)
}
func RequiredEnvVar[T any](varName string, defaultValue T, parser func(string) (T, error)) *T {
	return envVar(varName, defaultValue, true /*required*/, parser)
}
func StringEnvVar(varName string, defaultValue string) *string {
	return EnvVar(varName, defaultValue, func(value string) (string, error) { return value, nil })
}
func RequiredStringEnvVar(varName string) *string {
	return RequiredEnvVar(varName, "", func(value string) (string, error) { return value, nil })
}

func StringListEnvVar(varName string, defaultValue []string) *[]string {
	return EnvVar(varName, defaultValue, func(value string) ([]string, error) {
		return strings.Split(value, ","), nil
	})
}

func BoolEnvVar(varName string, defaultValue bool) *bool {
	return EnvVar(varName, defaultValue, strconv.ParseBool)
}

func RequiredAddrEnvVar(varName string) *net.IP {
	return RequiredEnvVar(varName, net.IP{}, func(value string) (addr net.IP, err error) {
		addr = net.ParseIP(value)
		if addr == nil {
			err = errors.Errorf("Failed to parse IP: %s", value)
		}
		return
	})
}

func AddrEnvVar(varName string, defaultValue net.IP) *net.IP {
	return EnvVar(varName, defaultValue, func(value string) (addr net.IP, err error) {
		addr = net.ParseIP(value)
		if addr == nil {
			err = errors.Errorf("Failed to parse IP: %s", value)
		}
		return
	})
}

func prefixParser(value string) (net.IPNet, error) {
	addr, pfx, err := net.ParseCIDR(value)
	if err != nil {
		return *pfx, err
	}
	pfx.IP = addr
	return *pfx, nil
}

func RequiredPrefixEnvVar(varName string) *net.IPNet {
	return RequiredEnvVar(varName, net.IPNet{}, prefixParser)
}
func PrefixEnvVar(varName string) *net.IPNet { return EnvVar(varName, net.IPNet{}, prefixParser) }

func prefixListParser(value string) ([]*net.IPNet, error) {
	chunks := strings.Split(value, ",")
	pfxList := make([]*net.IPNet, 0)
	for _, elem := range chunks {
		addr, pfx, err := net.ParseCIDR(elem)
		if err != nil {
			return pfxList, err
		}
		pfx.IP = addr
		pfxList = append(pfxList, pfx)
	}
	return pfxList, nil
}

func RequiredPrefixListEnvVar(varName string) *[]*net.IPNet {
	return RequiredEnvVar(varName, []*net.IPNet{}, prefixListParser)
}
func PrefixListEnvVar(varName string) *[]*net.IPNet {
	return EnvVar(varName, []*net.IPNet{}, prefixListParser)
}

func addrListParser(value string) ([]net.IP, error) {
	chunks := strings.Split(value, ",")
	addrList := make([]net.IP, 0)
	for _, elem := range chunks {
		addr := net.ParseIP(elem)
		if addr.To4() == nil {
			return addrList, errors.Errorf("Failed to parse, %s is not an IPv4 address", elem)
		}
		addrList = append(addrList, addr)
	}
	return addrList, nil
}

func RequiredAddrListEnvVar(varName string) *[]net.IP {
	return RequiredEnvVar(varName, []net.IP{}, addrListParser)
}
func AddrListEnvVar(varName string) *[]net.IP { return EnvVar(varName, []net.IP{}, addrListParser) }

func Uint16EnvVar(varName string, defaultValue uint16) *uint16 {
	return EnvVar(varName, defaultValue, func(value string) (uint16, error) {
		v, err := strconv.ParseUint(value, 10, 16)
		return uint16(v), err
	})
}

func Uint32EnvVar(varName string, defaultValue uint32) *uint32 {
	return EnvVar(varName, defaultValue, func(value string) (uint32, error) {
		v, err := strconv.ParseUint(value, 10, 32)
		return uint32(v), err
	})
}

func IntEnvVar(varName string, defaultValue int) *int {
	return EnvVar(varName, defaultValue, func(value string) (int, error) {
		v, err := strconv.ParseInt(value, 10, 32)
		return int(v), err
	})
}

// JSONEnvVar allows to declare envvars containing structs formatted as json
// * defaultValue should be a pointer to a SomeStructType
// * this returns a **SomeStructType
// * if SomeStructType implements Validable (pointer receiver) it will be run as part
// of the parsing process, allowing to set defaults.
func JSONEnvVar[T any](varName string, defaultValue T) *T {
	return EnvVar(varName, defaultValue, func(value string) (T, error) {
		err := json.Unmarshal([]byte(value), defaultValue)
		return defaultValue, err
	})
}

func BGPLogLevelParse(lvl string) (apipb.SetLogLevelRequest_Level, error) {
	switch strings.ToLower(lvl) {
	case "panic":
		return apipb.SetLogLevelRequest_PANIC, nil
	case "fatal":
		return apipb.SetLogLevelRequest_FATAL, nil
	case "error":
		return apipb.SetLogLevelRequest_ERROR, nil
	case "warn", "warning":
		return apipb.SetLogLevelRequest_WARN, nil
	case "info":
		return apipb.SetLogLevelRequest_INFO, nil
	case "debug":
		return apipb.SetLogLevelRequest_DEBUG, nil
	case "trace":
		return apipb.SetLogLevelRequest_TRACE, nil
	}

	var l apipb.SetLogLevelRequest_Level
	return l, fmt.Errorf("not a valid logrus Level: %q", lvl)
}

func BGPServerModeParse(mode string) (BGPServerModeType, error) {
	switch strings.ToLower(mode) {
	case strings.ToLower(string(BGPServerModeDualStack)):
		return BGPServerModeDualStack, nil
	case "v4only":
		return BGPServerModeV4Only, nil
	}

	return BGPServerModeDualStack, fmt.Errorf("not a valid BGP server mode: %q", mode)
}
