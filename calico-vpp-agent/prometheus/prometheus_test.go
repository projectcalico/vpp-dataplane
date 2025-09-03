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

package prometheus_test

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/prometheus"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/testutils"
	agentConf "github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

// Names of integration tests arguments
const (
	VppImageArgName           = "VPP_IMAGE"
	VppBinaryArgName          = "VPP_BINARY"
	VppContainerExtraArgsName = "VPP_CONTAINER_EXTRA_ARGS"
)

// TestPrometheusIntegration runs all the ginkgo integration test inside prometheus package
func TestPrometheusIntegration(t *testing.T) {
	// skip test if test run is not integration test run (prevent accidental run of integration tests using go test ./...)
	_, isIntegrationTestRun := os.LookupEnv(VppImageArgName)
	if !isIntegrationTestRun {
		t.Skip("skipping Prometheus integration tests (set VPP_IMAGE env variable to run these tests)")
	}

	// integrate gomega and ginkgo -> register all prometheus integration tests
	RegisterFailHandler(Fail)
	RunSpecs(t, "Prometheus Integration Suite")
}

var _ = BeforeSuite(func() {
	// Set unique container name for Prometheus tests
	testutils.VPPContainerName = "prometheus-tests-vpp"

	// extract common input for prometheus integration tests
	var found bool
	testutils.VppImage, found = os.LookupEnv(VppImageArgName)
	if !found {
		Expect(testutils.VppImage).ToNot(BeEmpty(), fmt.Sprintf("Please specify docker image containing "+
			"VPP binary using %s environment variable.", VppImageArgName))
	}
	testutils.VppBinary, found = os.LookupEnv(VppBinaryArgName)
	if !found {
		Expect(testutils.VppBinary).ToNot(BeEmpty(), fmt.Sprintf("Please specify VPP binary (full path) "+
			"inside docker image %s using %s environment variable.", testutils.VppImage, VppBinaryArgName))
	}

	vppContainerExtraArgsList, found := os.LookupEnv(VppContainerExtraArgsName)
	if found {
		testutils.VppContainerExtraArgs = append(testutils.VppContainerExtraArgs, strings.Split(vppContainerExtraArgsList, ",")...)
	}
})

var _ = Describe("Prometheus exporter functionality", func() {
	var (
		log              *logrus.Logger
		vpp              *vpplink.VppLink
		prometheusServer *prometheus.PrometheusServer
		testTomb         *tomb.Tomb
		uplinkSwIfIndex  uint32
	)

	BeforeEach(func() {
		log = logrus.New()
		common.ThePubSub = common.NewPubSub(log.WithFields(logrus.Fields{"component": "pubsub"}))

		// Enable prometheus feature gate
		agentConf.GetCalicoVppFeatureGates().PrometheusEnabled = &agentConf.True

		// Setup prometheus configuration
		config := agentConf.GetCalicoVppInitialConfig()
		config.PrometheusListenEndpoint = "localhost:9090"
		recordInterval := 1 * time.Second
		config.PrometheusRecordMetricInterval = &recordInterval
	})

	JustBeforeEach(func() {
		// Start the VPP container
		testutils.StartVPP()
		vpp, uplinkSwIfIndex = testutils.ConfigureVPP(log)

		// Wait for VPP stats socket to become available
		waitForStatsSocket("/tmp/"+testutils.VPPContainerName+"/stats.sock", 2*time.Second)

		// Create a symlink from the expected location to the actual stats socket location
		// This is a workaround for the issue where the statsclient expects /run/vpp/stats.sock
		// but our test VPP container has this at /tmp/prom-tests-vpp/stats.sock
		actualSocketPath := "/tmp/" + testutils.VPPContainerName + "/stats.sock"
		expectedSocketPath := "/run/vpp/stats.sock"

		// Create the directory if it doesn't exist
		os.MkdirAll("/run/vpp", 0755)

		// Remove any existing file/symlink and create a new symlink
		os.Remove(expectedSocketPath)
		err := os.Symlink(actualSocketPath, expectedSocketPath)
		if err != nil {
			fmt.Printf("Warning: Could not create symlink for stats socket: %v\n", err)
		}

		// Create prometheus server
		prometheusServer = prometheus.NewPrometheusServer(vpp, log.WithFields(logrus.Fields{"subcomponent": "prometheus"}))

		// Add some fake containers to test interface stats using actual VPP interface indices
		// Use the uplink interface (tap0) and local0 interface for testing
		addFakeContainer("test-namespace-1", "test-pod-1", "eth0", vpplink.InvalidSwIfIndex, uplinkSwIfIndex)
		addFakeContainer("test-namespace-2", "test-pod-2", "eth0", vpplink.InvalidSwIfIndex, 0)

		// Start prometheus server
		testTomb = &tomb.Tomb{}
		prometheusErrChan := make(chan error, 1)
		testTomb.Go(func() error {
			err := prometheusServer.ServePrometheus(testTomb)
			if err != nil {
				prometheusErrChan <- err
			}
			return err
		})

		// Wait for server to start with retry mechanism, but also check for early errors
		go func() {
			time.Sleep(3 * time.Second)
			err := <-prometheusErrChan
			if err != nil {
				panic(fmt.Sprintf("Prometheus server failed to start: %v", err))
			}
		}()

		waitForPrometheusServer("http://localhost:9090/metrics", 2*time.Second)
	})

	AfterEach(func() {
		if testTomb != nil {
			testTomb.Kill(nil)
			testTomb.Wait()
		}

		// Clean up the symlink we created
		os.Remove("/run/vpp/stats.sock")

		// Clean up the VPP container
		testutils.TeardownVPP()
	})

	Describe("Prometheus metrics export", func() {
		Context("With fake containers configured", func() {
			It("should export per-worker interface statistics for each interface separately", func() {
				By("Fetching metrics from prometheus endpoint")
				metrics, err := fetchMetricsWithRetry("http://localhost:9090/metrics", 2*time.Second)
				Expect(err).ToNot(HaveOccurred())

				fmt.Printf("=== Verify per-worker interface statistics for each interface separately ===\n")
				By("Verifying if interface metrics (rx_packets, tx_packets, rx_bytes, tx_bytes) are present")
				metricNames := []string{"rx_packets", "tx_packets", "rx_bytes", "tx_bytes"}

				for _, metricName := range metricNames {
					By(fmt.Sprintf("Parsing and verifying %s metric", metricName))
					metricEntries := parseMetrics(metrics, metricName)
					Expect(len(metricEntries)).To(BeNumerically(">", 0), fmt.Sprintf("Should have %s metrics", metricName))

					By(fmt.Sprintf("Verifying specific pod metrics are present for %s", metricName))
					foundTestNamespace1 := false
					foundTestNamespace2 := false

					for _, metric := range metricEntries {
						if metric.Labels["namespace"] == "test-namespace-1" &&
							metric.Labels["podName"] == "test-pod-1" &&
							metric.Labels["podInterfaceName"] == "eth0" &&
							metric.Labels["vppInterfaceName"] == "tap0" {
							foundTestNamespace1 = true
							fmt.Printf("Found %s metric: %+v\n", metricName, metric)
						}

						if metric.Labels["namespace"] == "test-namespace-2" &&
							metric.Labels["podName"] == "test-pod-2" &&
							metric.Labels["podInterfaceName"] == "eth0" &&
							metric.Labels["vppInterfaceName"] == "local0" {
							foundTestNamespace2 = true
							fmt.Printf("Found %s metric: %+v\n", metricName, metric)
						}
					}

					Expect(foundTestNamespace1).To(BeTrue(), fmt.Sprintf("Should find %s metric for test-namespace-1 pod", metricName))
					Expect(foundTestNamespace2).To(BeTrue(), fmt.Sprintf("Should find %s metric for test-namespace-2 pod", metricName))
				}
				fmt.Printf("=== Success! per-worker interface statistics for each interface separately found ===\n")
			})

			It("should export TCP statistics", func() {
				By("Fetching metrics from prometheus endpoint")
				metrics, err := fetchMetricsWithRetry("http://localhost:9090/metrics", 2*time.Second)
				Expect(err).ToNot(HaveOccurred())

				fmt.Printf("=== Verify TCP4/TCP6 statistics ===\n")
				By("Verifying TCP4 stats are exported")
				tcp4Metrics := findMetricNames(metrics, "tcp4")
				fmt.Printf("TCP4 metrics found: %v\n", len(tcp4Metrics))
				Expect(len(tcp4Metrics)).To(BeNumerically(">", 300), "Should contain TCP4 statistics")
				fmt.Printf("=== Success! TCP4 statistics found ===\n")

				By("Verifying TCP6 stats are exported")
				tcp6Metrics := findMetricNames(metrics, "tcp6")
				fmt.Printf("TCP6 metrics found: %v\n", len(tcp6Metrics))
				Expect(len(tcp6Metrics)).To(BeNumerically(">", 300), "Should contain TCP6 statistics")
				fmt.Printf("=== Success! TCP6 statistics found ===\n")
			})

			It("should export session statistics", func() {
				By("Fetching metrics from prometheus endpoint")
				metrics, err := fetchMetricsWithRetry("http://localhost:9090/metrics", 2*time.Second)
				Expect(err).ToNot(HaveOccurred())

				fmt.Printf("=== Verify session statistics ===\n")
				fmt.Printf("NOTE: VPP exports /sys/session stats iff sessions are established (test setup does not create any)\n")
				By("Verifying session stats are exported")
				sessionMetrics := findMetricNames(metrics, "session")
				fmt.Printf("session metrics found: %v\n", len(sessionMetrics))
				Expect(len(sessionMetrics)).To(Equal(0), "Should not contain session statistics")
				fmt.Printf("=== Success! session statistics not found as expected ===\n")
			})
		})

		Context("When pod events occur", func() {
			It("should handle pod addition events", func() {
				By("Adding a new pod")
				// Use a different interface name to distinguish this pod
				// Use tap interface with the uplink interface index
				addFakeContainer("dynamic-namespace", "dynamic-pod", "eth1", vpplink.InvalidSwIfIndex, uplinkSwIfIndex)

				// Give more time for event processing and metrics collection
				time.Sleep(2 * time.Second)

				By("Fetching metrics after pod addition")
				metrics, err := fetchMetricsWithRetry("http://localhost:9090/metrics", 2*time.Second)
				Expect(err).ToNot(HaveOccurred())

				fmt.Printf("=== Verify pod addition events with interface statistics ===\n")
				fmt.Printf("=== Verify per-worker interface statistics for each interface separately ===\n")
				By("Verifying interface metrics after pod addition")
				metricNames := []string{"rx_packets", "tx_packets", "rx_bytes", "tx_bytes"}

				for _, metricName := range metricNames {
					By(fmt.Sprintf("Parsing and verifying %s metric after pod addition", metricName))
					metricEntries := parseMetrics(metrics, metricName)
					Expect(len(metricEntries)).To(BeNumerically(">", 0), fmt.Sprintf("Should have %s metrics", metricName))

					By(fmt.Sprintf("Verifying specific pod metrics are present for %s after addition", metricName))
					foundDynamicNamespace := false
					foundTestNamespace2 := false

					for _, metric := range metricEntries {
						if metric.Labels["namespace"] == "dynamic-namespace" &&
							metric.Labels["podName"] == "dynamic-pod" &&
							metric.Labels["podInterfaceName"] == "eth1" &&
							metric.Labels["vppInterfaceName"] == "tap0" {
							foundDynamicNamespace = true
							fmt.Printf("Found %s metric for dynamic pod: %+v\n", metricName, metric)
						}

						if metric.Labels["namespace"] == "test-namespace-2" &&
							metric.Labels["podName"] == "test-pod-2" &&
							metric.Labels["podInterfaceName"] == "eth0" &&
							metric.Labels["vppInterfaceName"] == "local0" {
							foundTestNamespace2 = true
							fmt.Printf("Found %s metric for test-namespace-2 pod: %+v\n", metricName, metric)
						}
					}

					Expect(foundDynamicNamespace).To(BeTrue(), fmt.Sprintf("Should find %s metric for dynamic-namespace pod", metricName))
					Expect(foundTestNamespace2).To(BeTrue(), fmt.Sprintf("Should find %s metric for test-namespace-2 pod", metricName))
				}
				fmt.Printf("=== Success! per-worker interface statistics for each interface updated after pod addition===\n")
			})
		})
	})
})

// waitForStatsSocket waits for the VPP stats socket to become available
func waitForStatsSocket(socketPath string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			return // VPP stats socket exists
		}

		// Wait a bit before retrying
		time.Sleep(200 * time.Millisecond)
	}

	// If we get here, the VPP stats socket did not become available within the timeout
	panic(fmt.Sprintf("VPP stats socket %s did not become available within %v", socketPath, timeout))
}

// waitForPrometheusServer waits for the Prometheus server to be ready by attempting to connect
func waitForPrometheusServer(url string, timeout time.Duration) {
	client := &http.Client{Timeout: 1 * time.Second}
	deadline := time.Now().Add(timeout)

	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			fmt.Printf("Prometheus server is ready at %s\n", url)
			return // Prometheus server is ready
		}
		lastErr = err

		// Wait a bit before retrying
		time.Sleep(200 * time.Millisecond)
	}

	// If we get here, the Prometheus server did not start within the timeout
	panic(fmt.Sprintf("Prometheus server did not start within %v. Last error: %v", timeout, lastErr))
}

// fetchMetricsWithRetry attempts to fetch metrics with retry logic for more reliable testing
func fetchMetricsWithRetry(url string, timeout time.Duration) (string, error) {
	client := &http.Client{Timeout: 1 * time.Second}
	deadline := time.Now().Add(timeout)

	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				// fmt.Printf("=== METRICS OUTPUT ===\n%s\n=== END METRICS ===\n", string(body))
				return string(body), nil
			}
		}
		lastErr = err

		// Wait a bit before retrying
		time.Sleep(200 * time.Millisecond)
	}

	return "", lastErr
}

// MetricInfo represents parsed information from a metric line
type MetricInfo struct {
	MetricName string
	Labels     map[string]string
	Value      string
}

// parseMetricLine parses a single Prometheus metric line into structured information
func parseMetricLine(line string) (*MetricInfo, error) {
	// Find the opening and closing braces for labels
	labelStart := strings.Index(line, "{")
	labelEnd := strings.Index(line, "}")
	if labelStart == -1 || labelEnd == -1 || labelEnd <= labelStart {
		return nil, fmt.Errorf("invalid metric line format")
	}

	// Extract metric name (everything before the opening brace)
	metricName := strings.TrimSpace(line[:labelStart])

	// Extract labels section
	labelsStr := line[labelStart+1 : labelEnd]

	// Extract value (everything after the closing brace and space)
	valueStr := strings.TrimSpace(line[labelEnd+1:])

	// Parse individual labels
	labels := make(map[string]string)
	labelPairs := strings.Split(labelsStr, ",")

	for _, label := range labelPairs {
		label = strings.TrimSpace(label)
		parts := strings.SplitN(label, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		labels[key] = value
	}

	return &MetricInfo{
		MetricName: metricName,
		Labels:     labels,
		Value:      valueStr,
	}, nil
}

// processMetricLines processes Prometheus metrics lines and calls the provided function for each valid metric line
func processMetricLines(metricsOutput string, lineProcessor func(*MetricInfo)) {
	lines := strings.Split(metricsOutput, "\n")

	for _, line := range lines {
		// Skip comment lines and empty lines
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// Must have braces (indicating a metric with labels)
		if !strings.Contains(line, "{") {
			continue
		}

		info, err := parseMetricLine(line)
		if err == nil {
			lineProcessor(info)
		}
	}
}

// findMetricNames finds all unique metric names that contain the specified prefix
func findMetricNames(metricsOutput string, prefix string) []string {
	var metricNames []string
	nameSet := make(map[string]bool)

	processMetricLines(metricsOutput, func(info *MetricInfo) {
		// Check if this metric name starts with the prefix
		if !strings.HasPrefix(info.MetricName, prefix) {
			return
		}

		if !nameSet[info.MetricName] {
			nameSet[info.MetricName] = true
			metricNames = append(metricNames, info.MetricName)
		}
	})

	return metricNames
}

// parseMetrics parses Prometheus metrics output and returns entries for the specified metric name
func parseMetrics(metricsOutput string, metricName string) []*MetricInfo {
	var entries []*MetricInfo

	processMetricLines(metricsOutput, func(info *MetricInfo) {
		// Check if this is the specific metric we're interested in
		if info.MetricName != metricName {
			return
		}

		entries = append(entries, info)
	})

	return entries
}

// addFakeContainer simulates adding a container/pod to the prometheus server
func addFakeContainer(namespace, podName, interfaceName string, memifSwIfIndex, tunTapSwIfIndex uint32) {
	// Create fake pod spec
	podSpec := &model.LocalPodSpec{
		WorkloadID:    fmt.Sprintf("%s/%s", namespace, podName),
		InterfaceName: interfaceName,
		LocalPodSpecStatus: model.LocalPodSpecStatus{
			MemifSwIfIndex:  memifSwIfIndex,
			TunTapSwIfIndex: tunTapSwIfIndex,
		},
	}

	// Simulate pod addition event via PubSub mechanism
	event := common.CalicoVppEvent{
		Type: common.PodAdded,
		New:  podSpec,
	}

	// Send event using the common PubSub mechanism
	common.SendEvent(event)
}
