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

var g_server *Server

type Event int

const (
	Add    Event = 0
	Delete Event = 1
)

type PodSpecEvent struct {
	Event Event
	Pod   storage.LocalPodSpec
}

type Server struct {
	log           *logrus.Entry
	vpp           *vpplink.VppLink
	podInterfaces []storage.LocalPodSpec
	exported_data string
	sc            *statsclient.StatsClient
	channel       chan PodSpecEvent
	lock          sync.Mutex
}

func viewHandler(w http.ResponseWriter, r *http.Request) {
	ifNames, dumpStats, _ := vpplink.StatsClientFunc(g_server.sc)
	g_server.exported_data = g_server.statsToPrometheusFormat(ifNames, dumpStats)
	fmt.Fprint(w, g_server.exported_data)
}

func NewServer(vpp *vpplink.VppLink, l *logrus.Entry) (*Server, error) {
	server := &Server{
		log:     l,
		vpp:     vpp,
		channel: make(chan PodSpecEvent, 10),
	}
	return server, nil
}

// PodAdded is called by the CNI server when a vpp interface is added
func (s *Server) PodAdded(podSpec *storage.LocalPodSpec, swIfIndex uint32) {
	podSpec.SwIfIndex = swIfIndex
	s.channel <- PodSpecEvent{Event: Add, Pod: *podSpec}
}

// PodRemoved is called by the CNI server when a vpp interface is deleted
func (s *Server) PodRemoved(podSpec *storage.LocalPodSpec) {
	s.channel <- PodSpecEvent{Event: Delete, Pod: *podSpec}
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
							s.updateText(ifNames, &text, metricNames[0], strconv.Itoa(int(values[worker][j])), worker, j)
						}
					}
				}
			} else if sta.Type == adapter.CombinedCounterVector {
				values := sta.Data.(adapter.CombinedCounterStat)
				for k := range metricNames {
					for worker := range values {
						for j := range values[worker] {
							if string(ifNames[j]) != "" {
								s.updateText(ifNames, &text, metricNames[k], strconv.Itoa(int(values[worker][j][k])), worker, j)
							}
						}
					}
				}
			}
		}
	}
	return text
}

func (s *Server) updateText(ifNames adapter.NameStat, text *string, metricName string, value string, worker int, j int) *string {
	_, swifindex := s.vpp.SearchInterfaceWithName(string(ifNames[j]))
	s.lock.Lock()
	defer s.lock.Unlock()
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
			event := <-s.channel
			if event.Event == Add {
				s.lock.Lock()
				s.podInterfaces = append(s.podInterfaces, event.Pod)
				s.lock.Unlock()
			}
		}
	}()
	s.sc = statsclient.NewStatsClient("")
	err := s.sc.Connect()
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
	s.sc.Disconnect()

}
