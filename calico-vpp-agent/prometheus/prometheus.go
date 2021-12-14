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
	"context"
	"log"
	"net/http"
	"time"

	"strconv"
	"strings"
	"sync"

	"git.fd.io/govpp.git/adapter"
	"git.fd.io/govpp.git/adapter/statsclient"
	metricspb "github.com/census-instrumentation/opencensus-proto/gen-go/metrics/v1"
	"github.com/orijtech/prometheus-go-metrics-exporter"
	"github.com/projectcalico/vpp-dataplane/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/vpplink"
	"github.com/sirupsen/logrus"
)

type Event int

const (
	Add    Event = 0
	Delete Event = 1

	recordMetricInterval int64 = 5
)

type Server struct {
	log                      *logrus.Entry
	vpp                      *vpplink.VppLink
	mainTombDying            <-chan struct{}
	podInterfacesBySwifIndex map[uint32]storage.LocalPodSpec
	podInterfacesByKey       map[string]storage.LocalPodSpec
	sc                       *statsclient.StatsClient
	channel                  chan PodSpecEvent
	lock                     sync.Mutex
}

type PodSpecEvent struct {
	Event Event
	Pod   storage.LocalPodSpec
}

func (s *Server) recordMetrics() {
	pe, err := prometheus.New(prometheus.Options{})
	if err != nil {
		log.Fatalf("Failed to create new exporter: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", pe)
	go func() {
		http.ListenAndServe(":8888", mux)
	}()
	for {
		time.Sleep(time.Second * time.Duration(recordMetricInterval))
		select {
		case <-s.mainTombDying:
			s.log.Infof("prometheusServer DYING...")
			return
		default:
			ifNames, dumpStats, _ := vpplink.GetInterfaceStats(s.sc)
			for _, sta := range dumpStats {
				if string(sta.Name) != "/if/names" {
					names := []string{strings.Replace(string(sta.Name[4:]), "-", "_", -1)}
					if sta.Type == adapter.CombinedCounterVector {
						names = []string{names[0] + "_packets", names[0] + "_bytes"}
					}
					s.exportMetricsForStat(names, sta, ifNames, pe)
				}
			}
		}
	}
}

var units = map[int]string{0: "packets", 1: "bytes"}
var descriptions = map[string]string{
	"drops": "number of drops on interface",
	"ip4":   "IPv4 received packets",
	"ip6":   "IPv6 received packets",
	"punt":  "number of punts on interface",

	"rx_bytes":   "total number of bytes received over the interface",
	"tx_bytes":   "total number of bytes transmitted by the interface",
	"rx_packets": "total number of packets received over the interface",
	"tx_packets": "total number of packets transmitted by the interface",

	"tx_broadcast_packets": "number of multipoint communications transmitted by the interface in packets",
	"rx_broadcast_packets": "number of multipoint communications received by the interface in packets",
	"tx_broadcast_bytes":   "number of multipoint communications transmitted by the interface in bytes",
	"rx_broadcast_bytes":   "number of multipoint communications received by the interface in bytes",

	"tx_unicast_packets": "number of point-to-point communications transmitted by the interface in packets",
	"rx_unicast_packets": "number of point-to-point communications received by the interface in packets",
	"tx_unicast_bytes":   "number of point-to-point communications transmitted by the interface in bytes",
	"rx_unicast_bytes":   "number of point-to-point communications received by the interface in bytes",

	"tx_multicast_packets": "number of one-to-many communications transmitted by the interface in packets",
	"rx_multicast_packets": "number of one-to-many communications received by the interface in packets",
	"tx_multicast_bytes":   "number of one-to-many communications transmitted by the interface in bytes",
	"rx_multicast_bytes":   "number of one-to-many communications received by the interface in bytes",

	"rx_error": "total number of erroneous received packets",
	"tx_error": "total number of erroneous transmitted packets",

	"rx_miss": "total of rx packets dropped because there are no available buffer",
	"tx_miss": "total of tx packets dropped because there are no available buffer",

	"rx_no_buf": "total number of rx mbuf allocation failures",
	"tx_no_buf": "total number of tx mbuf allocation failures",
}

func (s *Server) exportMetricsForStat(names []string, sta adapter.StatEntry, ifNames adapter.NameStat, pe *prometheus.Exporter) {
	for k, name := range names {
		description, ok := descriptions[name]
		if !ok {
			description = name + " of interface"
		}
		metric := &metricspb.Metric{
			MetricDescriptor: &metricspb.MetricDescriptor{
				Name:        name,
				Unit:        "",
				Description: description,
				LabelKeys: []*metricspb.LabelKey{
					{Key: "worker", Description: "VPP worker index"},
					{Key: "namespace", Description: "Kubernetes namespace of the pod"},
					{Key: "podName", Description: "Name of the pod"},
					{Key: "nameInPod", Description: "Name of interface in the pod"},
				},
			},
			Timeseries: []*metricspb.TimeSeries{},
		}
		s.lock.Lock()
		if sta.Type == adapter.SimpleCounterVector {
			values := sta.Data.(adapter.SimpleCounterStat)
			for worker := range values {
				for ifIdx := range values[worker] {
					if string(ifNames[ifIdx]) != "" {
						if pod, ok := s.podInterfacesBySwifIndex[uint32(ifIdx)]; ok {
							metric.Timeseries = append(metric.Timeseries, getTimeSeries(worker, pod, float64(values[worker][ifIdx])))
						}
					}
				}
			}
		} else if sta.Type == adapter.CombinedCounterVector {
			metric.MetricDescriptor.Unit = units[k]
			values := sta.Data.(adapter.CombinedCounterStat)
			for worker := range values {
				for ifIdx := range values[worker] {
					if string(ifNames[ifIdx]) != "" {
						if pod, ok := s.podInterfacesBySwifIndex[uint32(ifIdx)]; ok {
							metric.Timeseries = append(metric.Timeseries, getTimeSeries(worker, pod, float64(values[worker][ifIdx][k])))
						}
					}
				}
			}
		}
		s.lock.Unlock()
		// empty timeseries prevents exporter from updating
		if len(metric.Timeseries) == 0 {
			metric.Timeseries = []*metricspb.TimeSeries{{}}
		}
		pe.ExportMetric(context.Background(), nil, nil, metric)
	}
}

func getTimeSeries(worker int, pod storage.LocalPodSpec, value float64) *metricspb.TimeSeries {
	return &metricspb.TimeSeries{
		LabelValues: []*metricspb.LabelValue{
			{Value: strconv.Itoa(worker)},
			{Value: pod.WorkloadID[:strings.Index(pod.WorkloadID, "/")]},
			{Value: pod.WorkloadID[strings.Index(pod.WorkloadID, "/")+1:]},
			{Value: pod.InterfaceName},
		},
		Points: []*metricspb.Point{
			{
				Value: &metricspb.Point_DoubleValue{
					DoubleValue: value,
				},
			},
		},
	}
}

func NewServer(vpp *vpplink.VppLink, l *logrus.Entry, dying <-chan struct{}) (*Server, error) {
	server := &Server{
		log:                      l,
		vpp:                      vpp,
		mainTombDying:            dying,
		channel:                  make(chan PodSpecEvent, 10),
		podInterfacesByKey:       make(map[string]storage.LocalPodSpec),
		podInterfacesBySwifIndex: make(map[uint32]storage.LocalPodSpec),
	}
	return server, nil
}

// PodAdded is called by the CNI server when a vpp interface is added
func (s *Server) PodAdded(podSpec *storage.LocalPodSpec) {
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
				s.podInterfacesBySwifIndex[event.Pod.TunTapSwIfIndex] = event.Pod
				s.podInterfacesByKey[event.Pod.Key()] = event.Pod
				s.lock.Unlock()
			} else if event.Event == Delete {
				s.lock.Lock()
				initialPod := s.podInterfacesByKey[event.Pod.Key()]
				delete(s.podInterfacesByKey, initialPod.Key())
				delete(s.podInterfacesBySwifIndex, initialPod.TunTapSwIfIndex)
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
}
