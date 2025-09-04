// Copyright (C) 2025 Cisco Systems Inc.
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
	"context"
	"crypto/sha512"
	"encoding/base64"
	"os"
	"os/signal"
	"runtime/coverage"
	"syscall"

	"github.com/sirupsen/logrus"
)

/* 8 base64 character hash */
func HashText(text string) string {
	h := sha512.Sum512([]byte(text))
	return base64.StdEncoding.EncodeToString(h[:])[:VrfTagHashLen]
}

func TruncateStr(text string, size int) string {
	if len(text) > size {
		return text[:size]
	}
	return text
}

// HandleUsr2Signal implements the USR2 signal
// that outputs the covarge data, provided the binary
// is compiled with -cover and GOCOVERDIR is set.
// This allows us to not require a proper binary
// termination in order to get coverage data.
func HandleUsr2Signal(ctx context.Context, log *logrus.Entry) {
	usr2SignalChannel := make(chan os.Signal, 1)
	signal.Notify(usr2SignalChannel, syscall.SIGUSR2)
	go func() {
		for {
			select {
			case <-usr2SignalChannel:
				log.Warnf("Received SIGUSR2, writing coverage to %s", os.Getenv("GOCOVERDIR"))
				if os.Getenv("GOCOVERDIR") != "" {
					err := os.Mkdir(os.Getenv("GOCOVERDIR"), 0750)
					if err != nil && !os.IsExist(err) {
						log.WithError(err).Errorf("Could not create dir %s", os.Getenv("GOCOVERDIR"))
						continue
					}
					err = coverage.WriteCountersDir(os.Getenv("GOCOVERDIR"))
					if err != nil {
						log.WithError(err).Error("Could not write counters dir")
					}
					err = coverage.WriteMetaDir(os.Getenv("GOCOVERDIR"))
					if err != nil {
						log.WithError(err).Error("Could not write meta dir")
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}
