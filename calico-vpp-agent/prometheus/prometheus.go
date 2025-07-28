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

func cleanVppIfStatName(vppStatName string) string {
	vppStatName = strings.TrimPrefix(vppStatName, "/if/")
	vppStatName = strings.Replace(vppStatName, "-", "_", -1)
	return vppStatName
}

func cleanVppTCPStatName(vppStatName string, prefix string) string {
	vppStatName = strings.TrimPrefix(vppStatName, prefix)
	vppStatName = strings.Replace(vppStatName, "-", "_", -1)
	vppStatName = strings.Replace(vppStatName, "/", "_", -1)
	return vppStatName
}

func cleanVppSessionStatName(vppStatName string) string {
	vppStatName = strings.TrimPrefix(vppStatName, "/sys/session/")
	vppStatName = strings.Replace(vppStatName, "/", "_", -1)
	return vppStatName
}

const (
	UnitPackets = "packets"
	UnitBytes   = "bytes"
)

func (self *PrometheusServer) exportMetrics() error {
	ifStats, err := self.statsclient.DumpStats("/if/")
	if err != nil {
		self.log.Errorf("Error running statsclient.DumpStats for Interface stats %v", err)
		return nil
	}
	var ifNames adapter.NameStat
	for _, vppStat := range ifStats {
		switch values := vppStat.Data.(type) {
		case adapter.NameStat:
			ifNames = values
		}
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	// Export Interface stats
	for _, vppStat := range ifStats {
		switch values := vppStat.Data.(type) {
		case adapter.SimpleCounterStat:
			self.exportInterfaceSimpleCounterStat(string(vppStat.Name), ifNames, values)
		case adapter.CombinedCounterStat:
			self.exportInterfaceCombinedCounterStat(string(vppStat.Name)+"_packets", ifNames, UnitPackets, values)
			self.exportInterfaceCombinedCounterStat(string(vppStat.Name)+"_bytes", ifNames, UnitBytes, values)
		}
	}

	// Export TCP stats
	tcpStats, err := self.statsclient.DumpStats("/sys/tcp")
	if err != nil {
		self.log.Errorf("Error running statsclient.DumpStats for TCP stats %v", err)
		return nil
	}
	for _, vppStat := range tcpStats {
		switch values := vppStat.Data.(type) {
		case adapter.SimpleCounterStat:
			self.exportTCPSimpleCounterStat(cleanVppTCPStatName(string(vppStat.Name), "/sys/"), values)
		}
	}

	// Export TCP4 error stats
	tcp4ErrStats, err := self.statsclient.DumpStats("/err/tcp4")
	if err != nil {
		self.log.Errorf("Error running statsclient.DumpStats for TCP4 error stats %v", err)
		return nil
	}
	for _, vppStat := range tcp4ErrStats {
		switch values := vppStat.Data.(type) {
		case adapter.SimpleCounterStat:
			self.exportTCPSimpleCounterStat(cleanVppTCPStatName(string(vppStat.Name), "/err/"), values)
		}
	}

	// Export TCP6 error stats
	tcp6ErrStats, err := self.statsclient.DumpStats("/err/tcp6")
	if err != nil {
		self.log.Errorf("Error running statsclient.DumpStats for TCP6 error stats %v", err)
		return nil
	}
	for _, vppStat := range tcp6ErrStats {
		switch values := vppStat.Data.(type) {
		case adapter.SimpleCounterStat:
			self.exportTCPSimpleCounterStat(cleanVppTCPStatName(string(vppStat.Name), "/err/"), values)
		}
	}

	// Export Session stats
	sessionStats, err := self.statsclient.DumpStats("/sys/session")
	if err != nil {
		self.log.Errorf("Error running statsclient.DumpStats for Session stats %v", err)
		return nil
	}
	for _, vppStat := range sessionStats {
		switch values := vppStat.Data.(type) {
		case adapter.SimpleCounterStat:
			self.exportSessionSimpleCounter(string(vppStat.Name), values)
		case adapter.ScalarStat:
			// ScalarStat is a single value, not per-worker
			self.exportSessionScalarStat(string(vppStat.Name), int64(values))
		}
	}

	return nil
}

func (self *PrometheusServer) exportInterfaceCombinedCounterStat(name string, ifNames adapter.NameStat, unit string, values adapter.CombinedCounterStat) {
	metric := &metricspb.Metric{
		MetricDescriptor: &metricspb.MetricDescriptor{
			Name:        cleanVppIfStatName(name),
			Unit:        unit,
			Description: getVppIfStatDescription(name),
			Type:        metricspb.MetricDescriptor_CUMULATIVE_DOUBLE,
			// empty timeseries prevents exporter from updating
			LabelKeys: []*metricspb.LabelKey{
				{Key: "worker", Description: "VPP worker index"},
				{Key: "namespace", Description: "Kubernetes namespace of the pod"},
				{Key: "podName", Description: "Name of the pod"},
				{Key: "podInterfaceName", Description: "Name of interface in the pod"},
				{Key: "vppInterfaceName", Description: "Name of interface in VPP"},
			},
		},
	}
	for worker, perWorkerValues := range values {
		for swIfIndex, counter := range perWorkerValues {
			self.log.Warnf("Export for IF=%d", swIfIndex)
			pod := self.podInterfacesDetailsBySwifIndex[uint32(swIfIndex)]
			vppIfName := ""
			if swIfIndex < len(ifNames) {
				vppIfName = string(ifNames[swIfIndex])
			}
			value := float64(counter.Bytes())
			if unit == UnitPackets {
				value = float64(counter.Packets())
			}
			metric.Timeseries = append(metric.Timeseries, &metricspb.TimeSeries{
				LabelValues: []*metricspb.LabelValue{
					{Value: strconv.Itoa(worker)},
					{Value: pod.podNamespace},
					{Value: pod.podName},
					{Value: pod.interfaceName},
					{Value: vppIfName},
				},
				Points: []*metricspb.Point{{
					Value: &metricspb.Point_DoubleValue{
						DoubleValue: value,
					},
				}},
			})
		}
	}
	err := self.exporter.ExportMetric(
		context.Background(),
		nil, /* node */
		nil, /* resource */
		metric,
	)
	if err != nil {
		self.log.Errorf("Error prometheus exporter.ExportMetric %v", err)
	}
}

func (self *PrometheusServer) exportInterfaceSimpleCounterStat(name string, ifNames adapter.NameStat, values adapter.SimpleCounterStat) {
	metric := &metricspb.Metric{
		MetricDescriptor: &metricspb.MetricDescriptor{
			Name:        cleanVppIfStatName(name),
			Description: getVppIfStatDescription(name),
			Type:        metricspb.MetricDescriptor_CUMULATIVE_DOUBLE,
			// empty timeseries prevents exporter from updating
			LabelKeys: []*metricspb.LabelKey{
				{Key: "worker", Description: "VPP worker index"},
				{Key: "namespace", Description: "Kubernetes namespace of the pod"},
				{Key: "podName", Description: "Name of the pod"},
				{Key: "podInterfaceName", Description: "Name of interface in the pod"},
				{Key: "vppInterfaceName", Description: "Name of interface in VPP"},
			},
		},
	}
	for worker, perWorkerValues := range values {
		for swIfIndex, counter := range perWorkerValues {
			pod := self.podInterfacesDetailsBySwifIndex[uint32(swIfIndex)]
			vppIfName := ""
			if swIfIndex < len(ifNames) {
				vppIfName = string(ifNames[swIfIndex])
			}
			metric.Timeseries = append(metric.Timeseries, &metricspb.TimeSeries{
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
							DoubleValue: float64(counter),
						},
					},
				},
			})
		}
	}
	err := self.exporter.ExportMetric(
		context.Background(),
		nil, /* node */
		nil, /* resource */
		metric,
	)
	if err != nil {
		self.log.Errorf("Error prometheus exporter.ExportMetric %v", err)
	}
}

func (self *PrometheusServer) exportTCPSimpleCounterStat(name string, values adapter.SimpleCounterStat) {
	metric := &metricspb.Metric{
		MetricDescriptor: &metricspb.MetricDescriptor{
			Name:        name,
			Unit:        "",
			Description: getVppTCPStatDescription(name),
			Type:        metricspb.MetricDescriptor_CUMULATIVE_INT64,
			LabelKeys: []*metricspb.LabelKey{
				{Key: "worker", Description: "VPP worker index"},
			},
		},
	}
	for worker, perWorkerValues := range values {
		for _, counter := range perWorkerValues {
			metric.Timeseries = append(metric.Timeseries, &metricspb.TimeSeries{
				LabelValues: []*metricspb.LabelValue{
					{Value: strconv.Itoa(worker)},
				},
				Points: []*metricspb.Point{
					{
						Value: &metricspb.Point_Int64Value{
							Int64Value: int64(counter),
						},
					},
				},
			})
		}
	}

	err := self.exporter.ExportMetric(
		context.Background(),
		nil, /* node */
		nil, /* resource */
		metric,
	)
	if err != nil {
		self.log.Errorf("Error prometheus exporter.ExportMetric for TCP %v", err)
	}
}

func (self *PrometheusServer) exportSessionSimpleCounter(name string, values adapter.SimpleCounterStat) {
	metric := &metricspb.Metric{
		MetricDescriptor: &metricspb.MetricDescriptor{
			Name:        cleanVppSessionStatName(name),
			Unit:        "",
			Description: getVppSessionStatDescription(name),
			Type:        metricspb.MetricDescriptor_CUMULATIVE_INT64,
			LabelKeys: []*metricspb.LabelKey{
				{Key: "worker", Description: "VPP worker index"},
			},
		},
	}
	for worker, perWorkerValues := range values {
		for _, counter := range perWorkerValues {
			metric.Timeseries = append(metric.Timeseries, &metricspb.TimeSeries{
				LabelValues: []*metricspb.LabelValue{
					{Value: strconv.Itoa(worker)},
				},
				Points: []*metricspb.Point{
					{
						Value: &metricspb.Point_Int64Value{
							Int64Value: int64(counter),
						},
					},
				},
			})
		}
	}

	err := self.exporter.ExportMetric(
		context.Background(),
		nil, /* node */
		nil, /* resource */
		metric,
	)
	if err != nil {
		self.log.Errorf("Error prometheus exporter.ExportMetric for Session %v", err)
	}
}

func (self *PrometheusServer) exportSessionScalarStat(name string, value int64) {
	err := self.exporter.ExportMetric(
		context.Background(),
		nil, /* node */
		nil, /* resource */
		&metricspb.Metric{
			MetricDescriptor: &metricspb.MetricDescriptor{
				Name:        cleanVppSessionStatName(name),
				Description: getVppSessionStatDescription(name),
				Type:        metricspb.MetricDescriptor_CUMULATIVE_INT64,
			},
			Timeseries: []*metricspb.TimeSeries{{
				Points: []*metricspb.Point{
					{
						Value: &metricspb.Point_Int64Value{
							Int64Value: value,
						},
					},
				},
			}},
		},
	)
	if err != nil {
		self.log.Errorf("Error prometheus exporter.ExportMetric for Session %v", err)
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
				if podSpec.MemifSwIfIndex != vpplink.INVALID_SW_IF_INDEX {
					memifName := podSpec.InterfaceName
					if podSpec.NetworkName == "" {
						memifName = "vpp/memif-" + podSpec.InterfaceName
					}
					self.podInterfacesDetailsBySwifIndex[podSpec.MemifSwIfIndex] = podInterfaceDetails{
						podNamespace:  splittedWorkloadId[0],
						podName:       splittedWorkloadId[1],
						interfaceName: memifName,
					}
				}
				if podSpec.TunTapSwIfIndex != vpplink.INVALID_SW_IF_INDEX {
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
					self.lock.Unlock()
					continue
				}
				initialPod := self.podInterfacesByKey[podSpec.Key()]
				delete(self.podInterfacesByKey, initialPod.Key())
				if podSpec.MemifSwIfIndex != vpplink.INVALID_SW_IF_INDEX {
					delete(self.podInterfacesDetailsBySwifIndex, initialPod.MemifSwIfIndex)
				}
				if podSpec.TunTapSwIfIndex != vpplink.INVALID_SW_IF_INDEX {
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

	go (func() {
		err := self.httpServer.ListenAndServe()
		if err != nil {
			panic(err)
		}
	})()
	ticker := time.NewTicker(*config.GetCalicoVppInitialConfig().PrometheusRecordMetricInterval)
	for ; t.Alive(); <-ticker.C {
		err := self.exportMetrics()
		if err != nil {
			self.log.WithError(err).Errorf("exportMetrics errored")
		}
	}
	ticker.Stop()
	self.log.Warn("Prometheus Server returned")
	err = self.httpServer.Shutdown(context.Background())
	if err != nil {
		return errors.Wrap(err, "Could not shutdown http server")
	}

	return nil
}
