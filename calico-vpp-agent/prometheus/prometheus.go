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
	vppStatName = strings.ReplaceAll(vppStatName, "-", "_")
	return config.GetCalicoVppInitialConfig().PrometheusStatsPrefix + vppStatName
}

func cleanVppTCPStatName(vppStatName string, prefix string) string {
	vppStatName = strings.TrimPrefix(vppStatName, prefix)
	vppStatName = strings.ReplaceAll(vppStatName, "-", "_")
	vppStatName = strings.ReplaceAll(vppStatName, "/", "_")
	return config.GetCalicoVppInitialConfig().PrometheusStatsPrefix + vppStatName
}

func cleanVppSessionStatName(vppStatName string) string {
	vppStatName = strings.TrimPrefix(vppStatName, "/sys/session/")
	vppStatName = strings.ReplaceAll(vppStatName, "/", "_")
	return config.GetCalicoVppInitialConfig().PrometheusStatsPrefix + vppStatName
}

const (
	UnitPackets = "packets"
	UnitBytes   = "bytes"
)

func (p *PrometheusServer) exportMetrics() error {
	ifStats, err := p.statsclient.DumpStats("/if/")
	if err != nil {
		p.log.Errorf("Error running statsclient.DumpStats for Interface stats %v", err)
		return nil
	}
	var ifNames adapter.NameStat
	for _, vppStat := range ifStats {
		switch values := vppStat.Data.(type) {
		case adapter.NameStat:
			ifNames = values
		}
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	// Export Interface stats
	for _, vppStat := range ifStats {
		switch values := vppStat.Data.(type) {
		case adapter.SimpleCounterStat:
			p.exportInterfaceSimpleCounterStat(string(vppStat.Name), ifNames, values)
		case adapter.CombinedCounterStat:
			p.exportInterfaceCombinedCounterStat(string(vppStat.Name)+"_packets", ifNames, UnitPackets, values)
			p.exportInterfaceCombinedCounterStat(string(vppStat.Name)+"_bytes", ifNames, UnitBytes, values)
		}
	}

	// Export TCP stats
	tcpStats, err := p.statsclient.DumpStats("/sys/tcp")
	if err != nil {
		p.log.Errorf("Error running statsclient.DumpStats for TCP stats %v", err)
		return nil
	}
	for _, vppStat := range tcpStats {
		switch values := vppStat.Data.(type) {
		case adapter.SimpleCounterStat:
			p.exportTCPSimpleCounterStat(cleanVppTCPStatName(string(vppStat.Name), "/sys/"), values)
		}
	}

	// Export TCP4 error stats
	tcp4ErrStats, err := p.statsclient.DumpStats("/err/tcp4")
	if err != nil {
		p.log.Errorf("Error running statsclient.DumpStats for TCP4 error stats %v", err)
		return nil
	}
	for _, vppStat := range tcp4ErrStats {
		switch values := vppStat.Data.(type) {
		case adapter.SimpleCounterStat:
			p.exportTCPSimpleCounterStat(cleanVppTCPStatName(string(vppStat.Name), "/err/"), values)
		}
	}

	// Export TCP6 error stats
	tcp6ErrStats, err := p.statsclient.DumpStats("/err/tcp6")
	if err != nil {
		p.log.Errorf("Error running statsclient.DumpStats for TCP6 error stats %v", err)
		return nil
	}
	for _, vppStat := range tcp6ErrStats {
		switch values := vppStat.Data.(type) {
		case adapter.SimpleCounterStat:
			p.exportTCPSimpleCounterStat(cleanVppTCPStatName(string(vppStat.Name), "/err/"), values)
		}
	}

	// Export Session stats
	sessionStats, err := p.statsclient.DumpStats("/sys/session")
	if err != nil {
		p.log.Errorf("Error running statsclient.DumpStats for Session stats %v", err)
		return nil
	}
	for _, vppStat := range sessionStats {
		switch values := vppStat.Data.(type) {
		case adapter.SimpleCounterStat:
			p.exportSessionSimpleCounter(string(vppStat.Name), values)
		case adapter.ScalarStat:
			// ScalarStat is a single value, not per-worker
			p.exportSessionScalarStat(string(vppStat.Name), int64(values))
		}
	}

	return nil
}

func (p *PrometheusServer) exportInterfaceCombinedCounterStat(name string, ifNames adapter.NameStat, unit string, values adapter.CombinedCounterStat) {
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
			pod := p.podInterfacesDetailsBySwifIndex[uint32(swIfIndex)]
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
	err := p.exporter.ExportMetric(
		context.Background(),
		nil, /* node */
		nil, /* resource */
		metric,
	)
	if err != nil {
		p.log.Errorf("Error prometheus exporter.ExportMetric %v", err)
	}
}

func (p *PrometheusServer) exportInterfaceSimpleCounterStat(name string, ifNames adapter.NameStat, values adapter.SimpleCounterStat) {
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
			pod := p.podInterfacesDetailsBySwifIndex[uint32(swIfIndex)]
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
	err := p.exporter.ExportMetric(
		context.Background(),
		nil, /* node */
		nil, /* resource */
		metric,
	)
	if err != nil {
		p.log.Errorf("Error prometheus exporter.ExportMetric %v", err)
	}
}

func (p *PrometheusServer) exportTCPSimpleCounterStat(name string, values adapter.SimpleCounterStat) {
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

	err := p.exporter.ExportMetric(
		context.Background(),
		nil, /* node */
		nil, /* resource */
		metric,
	)
	if err != nil {
		p.log.Errorf("Error prometheus exporter.ExportMetric for TCP %v", err)
	}
}

func (p *PrometheusServer) exportSessionSimpleCounter(name string, values adapter.SimpleCounterStat) {
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

	err := p.exporter.ExportMetric(
		context.Background(),
		nil, /* node */
		nil, /* resource */
		metric,
	)
	if err != nil {
		p.log.Errorf("Error prometheus exporter.ExportMetric for Session %v", err)
	}
}

func (p *PrometheusServer) exportSessionScalarStat(name string, value int64) {
	err := p.exporter.ExportMetric(
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
		p.log.Errorf("Error prometheus exporter.ExportMetric for Session %v", err)
	}
}

func (p *PrometheusServer) ServePrometheus(t *tomb.Tomb) error {
	if !(*config.GetCalicoVppFeatureGates().PrometheusEnabled) {
		return nil
	}
	p.log.Infof("Serve() Prometheus exporter")
	go func() {
		for t.Alive() {
			/* Note: we will only receive events we ask for when registering the chan */
			evt := <-p.channel
			switch evt.Type {
			case common.PodAdded:
				podSpec, ok := evt.New.(*storage.LocalPodSpec)
				if !ok {
					p.log.Errorf("evt.New is not a *storage.LocalPodSpec %v", evt.New)
					continue
				}
				splittedWorkloadID := strings.SplitN(podSpec.WorkloadID, "/", 2)
				if len(splittedWorkloadID) != 2 {
					continue
				}
				p.lock.Lock()
				if podSpec.MemifSwIfIndex != vpplink.InvalidSwIfIndex {
					memifName := podSpec.InterfaceName
					if podSpec.NetworkName == "" {
						memifName = "vpp/memif-" + podSpec.InterfaceName
					}
					p.podInterfacesDetailsBySwifIndex[podSpec.MemifSwIfIndex] = podInterfaceDetails{
						podNamespace:  splittedWorkloadID[0],
						podName:       splittedWorkloadID[1],
						interfaceName: memifName,
					}
				}
				if podSpec.TunTapSwIfIndex != vpplink.InvalidSwIfIndex {
					p.podInterfacesDetailsBySwifIndex[podSpec.TunTapSwIfIndex] = podInterfaceDetails{
						podNamespace:  splittedWorkloadID[0],
						podName:       splittedWorkloadID[1],
						interfaceName: podSpec.InterfaceName,
					}
				}
				p.podInterfacesByKey[podSpec.Key()] = *podSpec
				p.lock.Unlock()
			case common.PodDeleted:
				podSpec, ok := evt.Old.(*storage.LocalPodSpec)
				if !ok {
					p.log.Errorf("evt.Old is not a *storage.LocalPodSpec %v", evt.Old)
					continue
				}
				p.lock.Lock()
				initialPod := p.podInterfacesByKey[podSpec.Key()]
				delete(p.podInterfacesByKey, initialPod.Key())
				if podSpec.MemifSwIfIndex != vpplink.InvalidSwIfIndex {
					delete(p.podInterfacesDetailsBySwifIndex, initialPod.MemifSwIfIndex)
				}
				if podSpec.TunTapSwIfIndex != vpplink.InvalidSwIfIndex {
					delete(p.podInterfacesDetailsBySwifIndex, initialPod.TunTapSwIfIndex)
				}
				p.lock.Unlock()
			}
		}
	}()
	err := p.statsclient.Connect()
	if err != nil {
		return errors.Wrap(err, "could not connect statsclient")
	}

	go func() {
		err := p.httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			p.log.Errorf("HTTP server error: %v", err)
		}
	}()
	ticker := time.NewTicker(*config.GetCalicoVppInitialConfig().PrometheusRecordMetricInterval)
	for ; t.Alive(); <-ticker.C {
		err := p.exportMetrics()
		if err != nil {
			p.log.Errorf("Error exporting metrics: %v", err)
		}
	}
	ticker.Stop()
	p.log.Warn("Prometheus Server returned")
	err = p.httpServer.Shutdown(context.Background())
	if err != nil {
		return errors.Wrap(err, "Could not shutdown http server")
	}

	return nil
}
