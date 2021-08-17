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

package prometheus

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"git.fd.io/govpp.git/adapter"
	"git.fd.io/govpp.git/adapter/statsclient"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/sirupsen/logrus"
)

var exported_data string
var sc *statsclient.StatsClient
var g_server *Server
var lock sync.Mutex
var Channel chan PodSpecEvent

type PodSpecEvent struct {
	Event string
	Pod   storage.LocalPodSpec
}

type Server struct {
	log           *logrus.Entry
	vpp           *vpplink.VppLink
	podInterfaces []storage.LocalPodSpec
}

func viewHandler(w http.ResponseWriter, r *http.Request) {
	ifNames, dumpStats, _ := vpplink.Statsclientfunc(sc)
	exported_data = g_server.statsToPrometheusFormat(ifNames, dumpStats)
	fmt.Fprint(w, exported_data)
}

func NewServer(vpp *vpplink.VppLink, l *logrus.Entry) (*Server, error) {
	server := &Server{
		log: l,
		vpp: vpp,
	}
	return server, nil
}

func (s *Server) statsToPrometheusFormat(ifNames adapter.NameStat, dumpStats []adapter.StatEntry) (text string) {
	for _, sta := range dumpStats {
		if string(sta.Name) != "/if/names" {
			metricNames := []string{strings.Replace(string(sta.Name[4:]), "-", "_", -1)}
			if sta.Type == adapter.CombinedCounterVector {
				metricName := metricNames[0]
				metricNames = []string{metricName + "_packet", metricName + "_bytes"}
			}
			if sta.Type == adapter.SimpleCounterVector {
				values := sta.Data.(adapter.SimpleCounterStat)
				for worker := range values {
					for j := range values[worker] {
						if string(ifNames[j]) != "" {
							s.update_text(ifNames, &text, metricNames[0], strconv.Itoa(int(values[worker][j])), worker, j)
						}
					}
				}
			} else if sta.Type == adapter.CombinedCounterVector {
				values := sta.Data.(adapter.CombinedCounterStat)
				for k := range metricNames {
					for worker := range values {
						for j := range values[worker] {
							if string(ifNames[j]) != "" {
								s.update_text(ifNames, &text, metricNames[k], strconv.Itoa(int(values[worker][j][k])), worker, j)
							}
						}
					}
				}
			}
		}
	}
	return text
}

func (s *Server) update_text(ifNames adapter.NameStat, text *string, metricName string, value string, worker int, j int) *string {
	_, swifindex := s.vpp.SearchInterfaceWithName(string(ifNames[j]))
	lock.Lock()
	defer lock.Unlock()
	for _, pod := range s.podInterfaces {
		if swifindex == pod.SwIfIndex {
			namespace := pod.WorkloadID[:strings.Index(pod.WorkloadID, "/")]
			podName := pod.WorkloadID[strings.Index(pod.WorkloadID, "/")+1:]
			nameInPod := pod.InterfaceName
			*text = *text + "# HELP " + metricName + " any help msg\n"
			*text = *text + "# TYPE " + metricName + " counter\n"
			*text = *text + metricName + "{" + "interfaceName=\"" + string(ifNames[j]) + "\",worker=\"" + strconv.Itoa(worker) +
				"\",namespace=\"" + namespace + "\",podName=\"" + podName + "\",nameInPod=\"" + nameInPod + "\"} " + value + "\n"
		}
	}
	return text
}

func (s *Server) Serve() {
	s.log.Infof("Serve() Prometheus exporter")
	go func() {
		for {
			event := <-Channel
			if event.Event == "add" {
				lock.Lock()
				s.podInterfaces = append(s.podInterfaces, event.Pod)
				lock.Unlock()
			}
		}
	}()
	sc = statsclient.NewStatsClient("")
	err := sc.Connect()
	if err != nil {
		s.log.WithError(err).Errorf("could not connect statsclient")
		return
	}
	g_server = s

	http.HandleFunc("/metrics", viewHandler)
	err = http.ListenAndServe(":2112", nil)
	if err != nil {
		s.log.WithError(err).Errorf("Could not listen and serve on 2112")
		return
	}
	sc.Disconnect()

}
