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

package capture

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

// CaptureType represents the type of packet capture
type CaptureType string

const (
	CaptureTypeTrace    CaptureType = "trace"
	CaptureTypePcap     CaptureType = "pcap"
	CaptureTypeDispatch CaptureType = "dispatch"
)

// CaptureStatus represents the current status of a capture
type CaptureStatus string

const (
	CaptureStatusIdle     CaptureStatus = "idle"
	CaptureStatusRunning  CaptureStatus = "running"
	CaptureStatusStopping CaptureStatus = "stopping"
)

// BPFFilter contains BPF filter parameters
type BPFFilter struct {
	SrcIP    string `json:"srcIP,omitempty"`
	DstIP    string `json:"dstIP,omitempty"`
	SrcPort  int    `json:"srcPort,omitempty"`
	DstPort  int    `json:"dstPort,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// CaptureRequest represents a request to start a capture
type CaptureRequest struct {
	Type          CaptureType `json:"type"`
	Count         int         `json:"count"`
	Timeout       int         `json:"timeout"`
	InterfaceType string      `json:"interfaceType,omitempty"`
	Interface     string      `json:"interface,omitempty"`
	Filter        *BPFFilter  `json:"filter,omitempty"`
}

// CaptureResponse represents the response to a capture request
type CaptureResponse struct {
	Success  bool          `json:"success"`
	Message  string        `json:"message"`
	Status   CaptureStatus `json:"status"`
	FilePath string        `json:"filePath,omitempty"`
	Error    string        `json:"error,omitempty"`
}

// StatusResponse represents the status of the capture server
type StatusResponse struct {
	Status      CaptureStatus `json:"status"`
	CaptureType CaptureType   `json:"captureType,omitempty"`
	RemainingMs int64         `json:"remainingMs,omitempty"`
	FilePath    string        `json:"filePath,omitempty"`
}

// CaptureServer handles packet capture requests with mutex for single-instance execution
type CaptureServer struct {
	log        *logrus.Entry
	vpp        *vpplink.VppLink
	httpServer *http.Server

	// Mutex to ensure only one capture runs at a time
	captureMutex sync.Mutex

	// Current capture state
	status      CaptureStatus
	captureType CaptureType
	startTime   time.Time
	timeout     int
	stopChan    chan struct{}
	filePath    string
}

// NewCaptureServer creates a new CaptureServer
func NewCaptureServer(vpp *vpplink.VppLink, log *logrus.Entry) *CaptureServer {
	port := *config.GetCalicoVppInitialConfig().CaptureServerPort

	mux := http.NewServeMux()
	server := &CaptureServer{
		log:    log,
		vpp:    vpp,
		status: CaptureStatusIdle,
		httpServer: &http.Server{
			Addr:    fmt.Sprintf(":%d", port),
			Handler: mux,
		},
	}

	// Register HTTP handlers
	mux.HandleFunc("/api/status", server.handleStatus)
	mux.HandleFunc("/api/trace", server.handleTrace)
	mux.HandleFunc("/api/pcap", server.handlePcap)
	mux.HandleFunc("/api/dispatch", server.handleDispatch)
	mux.HandleFunc("/api/stop", server.handleStop)

	return server
}

// ServeCapture starts the capture HTTP server
func (s *CaptureServer) ServeCapture(t *tomb.Tomb) error {
	s.log.Infof("Starting capture server on port %d", *config.GetCalicoVppInitialConfig().CaptureServerPort)

	go func() {
		err := s.httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			s.log.Errorf("Capture HTTP server error: %v", err)
		}
	}()

	<-t.Dying()
	s.log.Warn("Capture server shutting down")

	// Stop any running capture
	if s.status == CaptureStatusRunning && s.stopChan != nil {
		close(s.stopChan)
	}

	err := s.httpServer.Shutdown(context.Background())
	if err != nil {
		return fmt.Errorf("could not shutdown capture HTTP server: %w", err)
	}

	return nil
}

// handleStatus returns the current status of the capture server
func (s *CaptureServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.captureMutex.Lock()
	defer s.captureMutex.Unlock()

	response := StatusResponse{
		Status:      s.status,
		CaptureType: s.captureType,
		FilePath:    s.filePath,
	}

	if s.status == CaptureStatusRunning {
		elapsed := time.Since(s.startTime)
		remaining := max(0, (time.Duration(s.timeout)*time.Second - elapsed))
		response.RemainingMs = remaining.Milliseconds()
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		s.log.Warnf("Failed to encode status response: %v", err)
	}
}

// handleTrace handles trace capture requests
func (s *CaptureServer) handleTrace(w http.ResponseWriter, r *http.Request) {
	s.handleCapture(w, r, CaptureTypeTrace)
}

// handlePcap handles PCAP capture requests
func (s *CaptureServer) handlePcap(w http.ResponseWriter, r *http.Request) {
	s.handleCapture(w, r, CaptureTypePcap)
}

// handleDispatch handles dispatch trace requests
func (s *CaptureServer) handleDispatch(w http.ResponseWriter, r *http.Request) {
	s.handleCapture(w, r, CaptureTypeDispatch)
}

// parseQueryParams extracts capture parameters from query string
func (s *CaptureServer) parseQueryParams(r *http.Request) CaptureRequest {
	query := r.URL.Query()

	req := CaptureRequest{
		Count:         1000, // default
		Timeout:       30,   // default
		InterfaceType: query.Get("interfaceType"),
		Interface:     query.Get("interface"),
	}

	countStr := query.Get("count")
	if countStr != "" {
		count, err := strconv.Atoi(countStr)
		if err == nil && count > 0 {
			req.Count = count
		}
	}

	timeoutStr := query.Get("timeout")
	if timeoutStr != "" {
		timeout, err := strconv.Atoi(timeoutStr)
		if err == nil && timeout > 0 {
			req.Timeout = timeout
		}
	}

	// Parse BPF filter parameters
	srcIP := query.Get("srcIP")
	dstIP := query.Get("dstIP")
	protocol := query.Get("protocol")
	srcPort := 0
	dstPort := 0

	srcPortStr := query.Get("srcPort")
	if srcPortStr != "" {
		port, err := strconv.Atoi(srcPortStr)
		if err == nil && port > 0 && port < 65536 {
			srcPort = port
		}
	}
	dstPortStr := query.Get("dstPort")
	if dstPortStr != "" {
		port, err := strconv.Atoi(dstPortStr)
		if err == nil && port > 0 && port < 65536 {
			dstPort = port
		}
	}

	if srcIP != "" || dstIP != "" || protocol != "" || srcPort > 0 || dstPort > 0 {
		req.Filter = &BPFFilter{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Protocol: protocol,
			SrcPort:  srcPort,
			DstPort:  dstPort,
		}
	}

	return req
}

// handleCapture is the common handler for all capture types
func (s *CaptureServer) handleCapture(w http.ResponseWriter, r *http.Request, captureType CaptureType) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Try to acquire the mutex (non-blocking)
	if !s.captureMutex.TryLock() {
		response := CaptureResponse{
			Success: false,
			Message: "Another capture is already running",
			Status:  CaptureStatusRunning,
			Error:   "capture_in_progress",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			s.log.Warnf("Failed to encode capture conflict response: %v", err)
		}
		return
	}
	defer s.captureMutex.Unlock()

	// Parse request from query parameters
	req := s.parseQueryParams(r)
	req.Type = captureType

	// Start capture
	s.status = CaptureStatusRunning
	s.captureType = captureType
	s.startTime = time.Now()
	s.timeout = req.Timeout
	s.stopChan = make(chan struct{})

	s.log.Infof("Starting %s capture: count=%d, timeout=%ds", captureType, req.Count, req.Timeout)

	// Run capture in goroutine
	go s.runCapture(req)

	response := CaptureResponse{
		Success: true,
		Message: fmt.Sprintf("%s capture started", captureType),
		Status:  CaptureStatusRunning,
	}
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		s.log.Warnf("Failed to encode capture start response: %v", err)
	}
}

// handleStop stops the current capture
func (s *CaptureServer) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.captureMutex.Lock()
	defer s.captureMutex.Unlock()

	if s.status != CaptureStatusRunning {
		response := CaptureResponse{
			Success: false,
			Message: "No capture is running",
			Status:  s.status,
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(response)
		if err != nil {
			s.log.Warnf("Failed to encode stop response: %v", err)
		}
		return
	}

	// Signal stop
	if s.stopChan != nil {
		close(s.stopChan)
	}
	s.status = CaptureStatusStopping

	response := CaptureResponse{
		Success: true,
		Message: "Stop signal sent",
		Status:  CaptureStatusStopping,
	}
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		s.log.Warnf("Failed to encode stop success response: %v", err)
	}
}

// runCapture runs the actual capture using vpplink APIs
func (s *CaptureServer) runCapture(req CaptureRequest) {
	defer func() {
		s.captureMutex.Lock()
		s.status = CaptureStatusIdle
		// NOTE: We intentionally DO NOT clear captureType and filePath here
		// They are preserved so that 'capture stop' can still download the file
		// after capture has auto-stopped (timeout/packet count reached)
		// They will be cleared when a new capture starts
		s.stopChan = nil
		s.captureMutex.Unlock()
	}()

	// Set up timeout
	timeoutChan := time.After(time.Duration(req.Timeout) * time.Second)

	// Build and apply BPF filter if specified
	if req.Filter != nil {
		bpfExpr := s.buildBPFFilter(req.Filter)
		if bpfExpr != "" {
			isPcap := req.Type == CaptureTypePcap || req.Type == CaptureTypeDispatch
			err := s.applyBPFFilter(bpfExpr, isPcap)
			if err != nil {
				s.log.Warnf("Failed to apply BPF filter: %v", err)
			} else {
				defer func() {
					err := s.clearBPFFilter(isPcap)
					if err != nil {
						s.log.Warnf("Failed to clear BPF filter: %v", err)
					}
				}()
			}
		}
	}

	// Start the appropriate capture
	var err error
	switch req.Type {
	case CaptureTypeTrace:
		err = s.startTrace(req)
	case CaptureTypePcap:
		err = s.startPcap(req)
	case CaptureTypeDispatch:
		err = s.startDispatch(req)
	}

	if err != nil {
		s.log.Errorf("Failed to start %s capture: %v", req.Type, err)
		return
	}

	// Wait for completion or stop signal
	select {
	case <-timeoutChan:
		s.log.Infof("%s capture completed (timeout)", req.Type)
	case <-s.stopChan:
		s.log.Infof("%s capture stopped by user", req.Type)
	}

	// Stop the capture
	switch req.Type {
	case CaptureTypeTrace:
		s.stopTrace()
	case CaptureTypePcap:
		s.stopPcap()
	case CaptureTypeDispatch:
		s.stopDispatch()
	}

	s.cleanupAfterCapture(req)
}

// buildBPFFilter builds a BPF filter expression from the filter parameters
func (s *CaptureServer) buildBPFFilter(filter *BPFFilter) string {
	if filter == nil {
		return ""
	}

	var parts []string

	if filter.Protocol != "" {
		parts = append(parts, filter.Protocol)
	}
	if filter.SrcIP != "" {
		parts = append(parts, fmt.Sprintf("src host %s", filter.SrcIP))
	}
	if filter.DstIP != "" {
		parts = append(parts, fmt.Sprintf("dst host %s", filter.DstIP))
	}
	if filter.SrcPort > 0 {
		parts = append(parts, fmt.Sprintf("src port %d", filter.SrcPort))
	}
	if filter.DstPort > 0 {
		parts = append(parts, fmt.Sprintf("dst port %d", filter.DstPort))
	}

	if len(parts) == 0 {
		return ""
	}

	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += " and " + parts[i]
	}
	return result
}

// applyBPFFilter applies a BPF filter using vpplink
func (s *CaptureServer) applyBPFFilter(expression string, isPcap bool) error {
	s.log.Infof("Applying BPF filter: %s", expression)

	// Add the BPF filter expression
	err := s.vpp.BpfAdd(expression)
	if err != nil {
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}

	// Enable BPF filtering function
	err = s.vpp.SetBpfFunction(isPcap)
	if err != nil {
		return fmt.Errorf("failed to enable BPF filter function: %w", err)
	}

	return nil
}

// clearBPFFilter clears the BPF filter
func (s *CaptureServer) clearBPFFilter(isPcap bool) error {
	s.log.Info("Clearing BPF filter")

	// Clear the filter function
	err := s.vpp.UnsetBpfFunction(isPcap)
	if err != nil {
		return fmt.Errorf("failed to clear BPF filter function: %w", err)
	}

	// Clear the BPF filter expression
	err = s.vpp.BpfDel()
	if err != nil {
		return fmt.Errorf("failed to clear BPF filter: %w", err)
	}

	return nil
}

// startTrace starts a packet trace
func (s *CaptureServer) startTrace(req CaptureRequest) error {
	s.log.Infof("Starting trace capture on interface type: %s", req.InterfaceType)

	// Clear existing traces
	err := s.vpp.TraceClear()
	if err != nil {
		s.log.Warnf("Failed to clear existing traces: %v", err)
	}

	// Get the input node index for the interface type
	inputNode := "virtio-input" // default
	if req.InterfaceType != "" {
		inputNode = s.mapInterfaceTypeToInputNode(req.InterfaceType)
	}

	nodeIndex, err := s.vpp.GetNodeIndex(inputNode)
	if err != nil {
		return fmt.Errorf("failed to get node index for %s: %w", inputNode, err)
	}

	// Start trace capture
	useFilter := req.Filter != nil && s.buildBPFFilter(req.Filter) != ""
	err = s.vpp.TraceCapture(nodeIndex, uint32(req.Count), useFilter)
	if err != nil {
		return fmt.Errorf("failed to start trace capture: %w", err)
	}

	s.filePath = "/var/run/vpp/trace.txt"
	return nil
}

// stopTrace stops the trace and saves output to /var/run/vpp/trace.txt (shared volume)
func (s *CaptureServer) stopTrace() {
	s.log.Info("Stopping trace capture and dumping output")

	// Dump the trace output using binary API
	traceOutput, err := s.vpp.TraceDump()
	if err != nil {
		s.log.Warnf("Failed to dump trace output: %v", err)
		return
	}

	// Save trace output to shared volume /var/run/vpp (accessible from VPP container)
	if traceOutput != "" {
		err = os.WriteFile("/var/run/vpp/trace.txt", []byte(traceOutput), 0644)
		if err != nil {
			s.log.Warnf("Failed to save trace output to /var/run/vpp/trace.txt: %v", err)
		} else {
			s.log.Infof("Trace output saved to /var/run/vpp/trace.txt (%d bytes)", len(traceOutput))
		}
	} else {
		s.log.Info("No trace output captured")
	}

	// Clear the trace buffer
	err = s.vpp.TraceClear()
	if err != nil {
		s.log.Warnf("Failed to clear trace buffer: %v", err)
	}
}

// startPcap starts a PCAP capture
func (s *CaptureServer) startPcap(req CaptureRequest) error {
	s.log.Infof("Starting PCAP capture on interface: %s", req.Interface)

	useFilter := req.Filter != nil && s.buildBPFFilter(req.Filter) != ""

	// Start PCAP capture using vpplink
	// Use swIfIndex 0xFFFFFFFF for "any" interface
	swIfIndex := uint32(0xFFFFFFFF)
	err := s.vpp.PcapTraceOn("/tmp/trace.pcap", uint32(req.Count), 0, swIfIndex, true, true, false, useFilter, false, false)
	if err != nil {
		return fmt.Errorf("failed to start PCAP capture: %w", err)
	}

	s.filePath = "/tmp/trace.pcap"
	return nil
}

// stopPcap stops the PCAP capture
func (s *CaptureServer) stopPcap() {
	s.log.Info("Stopping PCAP capture")

	err := s.vpp.PcapTraceOff()
	if err != nil {
		s.log.Warnf("Failed to stop PCAP capture: %v", err)
	}
}

// startDispatch starts a dispatch trace
func (s *CaptureServer) startDispatch(req CaptureRequest) error {
	s.log.Infof("Starting dispatch trace on interface type: %s", req.InterfaceType)

	useFilter := req.Filter != nil && s.buildBPFFilter(req.Filter) != ""

	// Start dispatch trace using vpplink
	err := s.vpp.PcapDispatchTraceOn(uint32(req.Count), "/tmp/dispatch.pcap", useFilter)
	if err != nil {
		return fmt.Errorf("failed to start dispatch trace: %w", err)
	}

	s.filePath = "/tmp/dispatch.pcap"
	return nil
}

// stopDispatch stops the dispatch trace
func (s *CaptureServer) stopDispatch() {
	s.log.Info("Stopping dispatch trace")

	err := s.vpp.PcapDispatchTraceOff()
	if err != nil {
		s.log.Warnf("Failed to stop dispatch trace: %v", err)
	}
}

// cleanupAfterCapture reverts capture-specific settings so a new capture can start cleanly
func (s *CaptureServer) cleanupAfterCapture(req CaptureRequest) {
	switch req.Type {
	case CaptureTypeTrace:
		err := s.vpp.TraceSetDefaultFunction()
		if err != nil {
			s.log.Warnf("Failed to reset trace filter function: %v", err)
		}
	case CaptureTypePcap, CaptureTypeDispatch:
		err := s.vpp.PcapSetDefaultFunction()
		if err != nil {
			s.log.Warnf("Failed to reset pcap filter function: %v", err)
		}
	}

	if req.Filter != nil {
		err := s.vpp.BpfDel()
		if err != nil {
			s.log.Warnf("Failed to clear BPF filter: %v", err)
		}
	}
}

// mapInterfaceTypeToInputNode maps interface type to VPP input node
func (s *CaptureServer) mapInterfaceTypeToInputNode(interfaceType string) string {
	switch interfaceType {
	case "memif":
		return "memif-input"
	case "af_packet":
		return "af-packet-input"
	case "af_xdp":
		return "af_xdp-input"
	case "avf":
		return "avf-input"
	case "vmxnet3":
		return "vmxnet3-input"
	case "virtio", "tuntap", "":
		return "virtio-input"
	case "rdma":
		return "rdma-input"
	case "dpdk":
		return "dpdk-input"
	case "vcl":
		return "session-queue"
	default:
		return "virtio-input"
	}
}
