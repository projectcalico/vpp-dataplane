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
	"net/http"
	"time"

	"strconv"
	"strings"
	"sync"

	"git.fd.io/govpp.git/adapter"
	"git.fd.io/govpp.git/adapter/statsclient"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

type Event int

const (
	Add    Event = 0
	Delete Event = 1
)

type Server struct {
	log           *logrus.Entry
	vpp           *vpplink.VppLink
	podInterfaces []storage.LocalPodSpec
	sc            *statsclient.StatsClient
	channel       chan PodSpecEvent
	lock          sync.Mutex
	counterValue  map[prometheus.Counter]float64
	counterVecs   map[string]*prometheus.CounterVec
}

type PodSpecEvent struct {
	Event Event
	Pod   storage.LocalPodSpec
}

func (s *Server) recordMetrics() {
	go func() {
		for {
			time.Sleep(time.Second * 5)
			ifNames, dumpStats, _ := vpplink.StatsClientFunc(s.sc)
			for _, sta := range dumpStats {
				if string(sta.Name) != "/if/names" {
					names := []string{strings.Replace(string(sta.Name[4:]), "-", "_", -1)}
					if sta.Type == adapter.CombinedCounterVector {
						names = []string{names[0] + "_packet", names[0] + "_bytes"}
					}
					for k, name := range names {
						metric, exists := s.counterVecs[name]
						if !exists {
							metric = promauto.NewCounterVec(prometheus.CounterOpts{
								Name: name,
							}, []string{"interfaceName", "worker", "namespace", "podName", "nameInPod"})
							s.counterVecs[name] = metric
						}
						s.lock.Lock()
						if sta.Type == adapter.SimpleCounterVector {
							values := sta.Data.(adapter.SimpleCounterStat)
							for worker := range values {
								for ifIdx := range values[worker] {
									_, swifindex := s.vpp.SearchInterfaceWithName(string(ifNames[ifIdx]))
									for _, pod := range s.podInterfaces {
										if swifindex == pod.SwIfIndex {
											counter, _ := s.addCounter(metric, ifNames, ifIdx, worker, pod)
											counter.Add(float64(values[worker][ifIdx]) - s.counterValue[counter])
											s.counterValue[counter] = float64(values[worker][ifIdx])
										}
									}
								}
							}
						} else if sta.Type == adapter.CombinedCounterVector {
							values := sta.Data.(adapter.CombinedCounterStat)
							for worker := range values {
								for ifIdx := range values[worker] {
									_, swifindex := s.vpp.SearchInterfaceWithName(string(ifNames[ifIdx]))
									for _, pod := range s.podInterfaces {
										if swifindex == pod.SwIfIndex {
											counter, _ := s.addCounter(metric, ifNames, ifIdx, worker, pod)
											counter.Add(float64(values[worker][ifIdx][k]) - s.counterValue[counter])
											s.counterValue[counter] = float64(values[worker][ifIdx][k])
										}
									}
								}
							}
						}
						s.lock.Unlock()
					}
				}
			}
		}
	}()
}

func (s *Server) addCounter(metric *prometheus.CounterVec, ifNames adapter.NameStat, ifIdx int, worker int, pod storage.LocalPodSpec) (prometheus.Counter, error){
	counter, err := metric.GetMetricWith(prometheus.Labels{"interfaceName": string(ifNames[ifIdx]), "worker": strconv.Itoa(worker),
		"namespace": pod.WorkloadID[:strings.Index(pod.WorkloadID, "/")], "podName": pod.WorkloadID[strings.Index(pod.WorkloadID, "/")+1:],
		"nameInPod": pod.InterfaceName})
	if err != nil {
		return nil, err
	}
	_, exists := s.counterValue[counter]
	if !exists {
		s.counterValue[counter] = 0
	}
	return counter, err
}

func NewServer(vpp *vpplink.VppLink, l *logrus.Entry) (*Server, error) {
	server := &Server{
		log:          l,
		vpp:          vpp,
		channel:      make(chan PodSpecEvent, 10),
		counterValue: make(map[prometheus.Counter]float64),
		counterVecs:  make(map[string]*prometheus.CounterVec),
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

	s.recordMetrics()
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":2112", nil)
	s.sc.Disconnect()
}
