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
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	metricspb "github.com/census-instrumentation/opencensus-proto/gen-go/metrics/v1"
	prometheusExporter "github.com/orijtech/prometheus-go-metrics-exporter"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.fd.io/govpp/adapter"
	"go.fd.io/govpp/adapter/statsclient"
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/storage"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

type podInterfaceDetails struct {
	podNamespace  string
	podName       string
	interfaceName string
}

type PrometheusServer struct {
	log                             *logrus.Entry
	vpp                             *vpplink.VppLink
	podInterfacesDetailsBySwifIndex map[uint32]podInterfaceDetails
	podInterfacesByKey              map[string]storage.LocalPodSpec
	statsclient                     *statsclient.StatsClient
	channel                         chan common.CalicoVppEvent
	lock                            sync.Mutex
	httpServer                      *http.Server
	exporter                        *prometheusExporter.Exporter
}

func NewPrometheusServer(vpp *vpplink.VppLink, log *logrus.Entry) *PrometheusServer {
	exporter, err := prometheusExporter.New(prometheusExporter.Options{})
	if err != nil {
		log.Fatalf("Failed to create new exporter: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", exporter)
	server := &PrometheusServer{
		log:                             log,
		vpp:                             vpp,
		channel:                         make(chan common.CalicoVppEvent, 10),
		podInterfacesByKey:              make(map[string]storage.LocalPodSpec),
		podInterfacesDetailsBySwifIndex: make(map[uint32]podInterfaceDetails),
		statsclient:                     statsclient.NewStatsClient("" /* default socket name */),
		httpServer: &http.Server{
			Addr:    config.GetCalicoVppInitialConfig().PrometheusListenEndpoint,
			Handler: mux,
		},
		exporter: exporter,
	}

	if *config.GetCalicoVppFeatureGates().PrometheusEnabled {
		reg := common.RegisterHandler(server.channel, "prometheus events")
		reg.ExpectEvents(common.PodAdded, common.PodDeleted)
	}
	return server
}

func cleanVppStatName(vppStatName string) string {
	vppStatName = strings.TrimPrefix(vppStatName, "/if/")
	vppStatName = strings.Replace(vppStatName, "-", "_", -1)
	return vppStatName
}

func getVppStatDescription(vppStatName string) string {
	switch cleanVppStatName(vppStatName) {
	case "drops":
		return "number of drops on interface"
	case "ip4":
		return "IPv4 received packets"
	case "ip6":
		return "IPv6 received packets"
	case "punt":
		return "number of punts on interface"
	case "rx_bytes":
		return "total number of bytes received over the interface"
	case "tx_bytes":
		return "total number of bytes transmitted by the interface"
	case "rx_packets":
		return "total number of packets received over the interface"
	case "tx_packets":
		return "total number of packets transmitted by the interface"
	case "tx_broadcast_packets":
		return "number of multipoint communications transmitted by the interface in packets"
	case "rx_broadcast_packets":
		return "number of multipoint communications received by the interface in packets"
	case "tx_broadcast_bytes":
		return "number of multipoint communications transmitted by the interface in bytes"
	case "rx_broadcast_bytes":
		return "number of multipoint communications received by the interface in bytes"
	case "tx_unicast_packets":
		return "number of point-to-point communications transmitted by the interface in packets"
	case "rx_unicast_packets":
		return "number of point-to-point communications received by the interface in packets"
	case "tx_unicast_bytes":
		return "number of point-to-point communications transmitted by the interface in bytes"
	case "rx_unicast_bytes":
		return "number of point-to-point communications received by the interface in bytes"
	case "tx_multicast_packets":
		return "number of one-to-many communications transmitted by the interface in packets"
	case "rx_multicast_packets":
		return "number of one-to-many communications received by the interface in packets"
	case "tx_multicast_bytes":
		return "number of one-to-many communications transmitted by the interface in bytes"
	case "rx_multicast_bytes":
		return "number of one-to-many communications received by the interface in bytes"
	case "rx_error":
		return "total number of erroneous received packets"
	case "tx_error":
		return "total number of erroneous transmitted packets"
	case "rx_miss":
		return "total of rx packets dropped because there are no available buffer"
	case "tx_miss":
		return "total of tx packets dropped because there are no available buffer"
	case "rx_no_buf":
		return "total number of rx mbuf allocation failures"
	case "tx_no_buf":
		return "total number of tx mbuf allocation failures"
	default:
		return vppStatName
	}
}

func (self *PrometheusServer) exportMetrics() error {
	vppStats, err := self.statsclient.DumpStats("/if/")
	if err != nil {
		self.log.Errorf("Error running statsclient.DumpStats %v", err)
		return nil
	}
	var ifNames adapter.NameStat
	for _, vppStat := range vppStats {
		switch values := vppStat.Data.(type) {
		case adapter.NameStat:
			ifNames = values
		}
	}

	self.lock.Lock()
	for _, vppStat := range vppStats {
		switch values := vppStat.Data.(type) {
		case adapter.SimpleCounterStat:
			for worker, perWorkerValues := range values {
				for swIfIndex, counter := range perWorkerValues {
					self.exportInterfaceMetric(string(vppStat.Name), worker, swIfIndex, ifNames, uint64(counter), "")
				}
			}
		case adapter.CombinedCounterStat:
			for worker, perWorkerValues := range values {
				for swIfIndex, counter := range perWorkerValues {
					self.exportInterfaceMetric(string(vppStat.Name)+"_packets", worker, swIfIndex, ifNames, counter[0], "packets")
					self.exportInterfaceMetric(string(vppStat.Name)+"_bytes", worker, swIfIndex, ifNames, counter[1], "bytes")
				}
			}
		}
	}
	self.lock.Unlock()
	return nil
}

func (self *PrometheusServer) exportInterfaceMetric(name string, worker int, swIfIndex int, ifNames adapter.NameStat, value uint64, unit string) {
	pod := self.podInterfacesDetailsBySwifIndex[uint32(swIfIndex)]
	vppIfName := ""
	if swIfIndex < len(ifNames) {
		vppIfName = string(ifNames[swIfIndex])
	}
	err := self.exporter.ExportMetric(
		context.Background(),
		nil, /* node */
		nil, /* resource */
		&metricspb.Metric{
			MetricDescriptor: &metricspb.MetricDescriptor{
				Name:        cleanVppStatName(name),
				Unit:        unit,
				Description: getVppStatDescription(name),
				// empty timeseries prevents exporter from updating
				LabelKeys: []*metricspb.LabelKey{
					{Key: "worker", Description: "VPP worker index"},
					{Key: "namespace", Description: "Kubernetes namespace of the pod"},
					{Key: "podName", Description: "Name of the pod"},
					{Key: "podInterfaceName", Description: "Name of interface in the pod"},
					{Key: "vppInterfaceName", Description: "Name of interface in VPP"},
				},
			},
			Timeseries: []*metricspb.TimeSeries{{
				LabelValues: []*metricspb.LabelValue{
					{Value: strconv.Itoa(worker)},
					{Value: pod.podNamespace},
					{Value: pod.podName},
					{Value: pod.interfaceName},
					{Value: vppIfName},
				},
				Points: []*metricspb.Point{
					{
						Value: &metricspb.Point_DoubleValue{
							DoubleValue: float64(value),
						},
					},
				},
			}},
		},
	)
	if err != nil {
		self.log.Errorf("Error prometheus exporter.ExportMetric %v", err)
	}
}

func (self *PrometheusServer) ServePrometheus(t *tomb.Tomb) error {
	if !(*config.GetCalicoVppFeatureGates().PrometheusEnabled) {
		return nil
	}
	self.log.Infof("Serve() Prometheus exporter")
	go func() {
		for t.Alive() {
			/* Note: we will only receive events we ask for when registering the chan */
			evt := <-self.channel
			switch evt.Type {
			case common.PodAdded:
				podSpec, ok := evt.New.(*storage.LocalPodSpec)
				if !ok {
					self.log.Errorf("evt.New is not a *storage.LocalPodSpec %v", evt.New)
					continue
				}
				splittedWorkloadId := strings.SplitN(podSpec.WorkloadID, "/", 2)
				if len(splittedWorkloadId) != 2 {
					continue
				}
				self.lock.Lock()
				if podSpec.TunTapSwIfIndex == vpplink.InvalidSwIfIndex {
					memifName := podSpec.InterfaceName
					if podSpec.NetworkName == "" {
						memifName = "vpp/memif-" + podSpec.InterfaceName
					}
					self.podInterfacesDetailsBySwifIndex[podSpec.MemifSwIfIndex] = podInterfaceDetails{
						podNamespace:  splittedWorkloadId[0],
						podName:       splittedWorkloadId[1],
						interfaceName: memifName,
					}
				} else {
					self.podInterfacesDetailsBySwifIndex[podSpec.TunTapSwIfIndex] = podInterfaceDetails{
						podNamespace:  splittedWorkloadId[0],
						podName:       splittedWorkloadId[1],
						interfaceName: podSpec.InterfaceName,
					}
				}
				self.podInterfacesByKey[podSpec.Key()] = *podSpec
				self.lock.Unlock()
			case common.PodDeleted:
				self.lock.Lock()
				podSpec, ok := evt.Old.(*storage.LocalPodSpec)
				if !ok {
					self.log.Errorf("evt.Old is not a *storage.LocalPodSpec %v", evt.Old)
					continue
				}
				initialPod := self.podInterfacesByKey[podSpec.Key()]
				delete(self.podInterfacesByKey, initialPod.Key())
				if podSpec.TunTapSwIfIndex == vpplink.InvalidSwIfIndex {
					delete(self.podInterfacesDetailsBySwifIndex, initialPod.MemifSwIfIndex)
				} else {
					delete(self.podInterfacesDetailsBySwifIndex, initialPod.TunTapSwIfIndex)
				}
				self.lock.Unlock()
			}
		}
	}()
	err := self.statsclient.Connect()
	if err != nil {
		return errors.Wrap(err, "could not connect statsclient")
	}

	go self.httpServer.ListenAndServe()
	ticker := time.NewTicker(*config.GetCalicoVppInitialConfig().PrometheusRecordMetricInterval)
	for ; t.Alive(); <-ticker.C {
		self.exportMetrics()
	}
	ticker.Stop()
	self.log.Warn("Prometheus Server returned")
	err = self.httpServer.Shutdown(context.Background())
	if err != nil {
		return errors.Wrap(err, "Could not shutdown http server")
	}

	return nil
}
