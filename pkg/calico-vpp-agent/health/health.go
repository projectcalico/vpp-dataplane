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

package health

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

// HealthStatus represents the current health state
type HealthStatus struct {
	Healthy    bool                       `json:"healthy"`
	Ready      bool                       `json:"ready"`
	Components map[string]ComponentStatus `json:"components"`
	Message    string                     `json:"message,omitempty"`
	LastUpdate time.Time                  `json:"lastUpdate"`
}

// ComponentStatus tracks the status of individual components
type ComponentStatus struct {
	Initialized bool      `json:"initialized"`
	Message     string    `json:"message,omitempty"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// HealthServer provides HTTP health check endpoints
type HealthServer struct {
	log         *logrus.Entry
	port        uint32
	status      HealthStatus
	statusMutex sync.RWMutex
	server      *http.Server
}

const (
	ComponentVPP        = "vpp"
	ComponentVPPManager = "vpp-manager"
	ComponentFelix      = "felix"
	ComponentAgent      = "agent"
)

// NewHealthServer creates a new health check server
func NewHealthServer(log *logrus.Entry, port uint32) *HealthServer {
	return &HealthServer{
		log:  log,
		port: port,
		status: HealthStatus{
			Healthy:    true,
			Ready:      false,
			Components: make(map[string]ComponentStatus),
			LastUpdate: time.Now(),
		},
	}
}

// SetComponentStatus updates the status of a specific component
func (hs *HealthServer) SetComponentStatus(component string, initialized bool, message string) {
	hs.statusMutex.Lock()
	defer hs.statusMutex.Unlock()

	hs.status.Components[component] = ComponentStatus{
		Initialized: initialized,
		Message:     message,
		UpdatedAt:   time.Now(),
	}
	hs.status.LastUpdate = time.Now()

	// Update overall readiness
	hs.updateReadiness()

	hs.log.WithFields(logrus.Fields{
		"component":   component,
		"initialized": initialized,
		"message":     message,
	}).Debug("Component status updated")
}

// updateReadiness determines overall readiness based on component status
func (hs *HealthServer) updateReadiness() {
	// Required components for readiness
	requiredComponents := []string{
		ComponentVPP,
		ComponentVPPManager,
		ComponentFelix,
		ComponentAgent,
	}

	allReady := true
	for _, comp := range requiredComponents {
		status, exists := hs.status.Components[comp]
		if !exists || !status.Initialized {
			allReady = false
			break
		}
	}

	hs.status.Ready = allReady

	if allReady {
		hs.status.Message = "All components initialized"
	} else {
		hs.status.Message = "Waiting for components to initialize"
	}
}

// MarkAsHealthy marks the agent as healthy (but not necessarily ready)
func (hs *HealthServer) MarkAsHealthy(message string) {
	hs.statusMutex.Lock()
	defer hs.statusMutex.Unlock()

	hs.status.Healthy = true
	if message != "" {
		hs.status.Message = message
	} else {
		hs.status.Message = "Agent is healthy"
	}
	hs.status.LastUpdate = time.Now()

	hs.log.WithField("message", message).Info("Agent marked as healthy")
}

// MarkAsUnhealthy marks the agent as unhealthy
func (hs *HealthServer) MarkAsUnhealthy(reason string) {
	hs.statusMutex.Lock()
	defer hs.statusMutex.Unlock()

	hs.status.Healthy = false
	hs.status.Ready = false
	hs.status.Message = reason
	hs.status.LastUpdate = time.Now()

	hs.log.WithField("reason", reason).Warn("Agent marked as unhealthy")
}

// GetStatus returns the current health status (thread-safe)
func (hs *HealthServer) GetStatus() HealthStatus {
	hs.statusMutex.RLock()
	defer hs.statusMutex.RUnlock()

	// Create a copy to avoid race conditions
	statusCopy := hs.status
	statusCopy.Components = make(map[string]ComponentStatus)
	for k, v := range hs.status.Components {
		statusCopy.Components[k] = v
	}

	return statusCopy
}

// livenessHandler handles the /liveness endpoint
func (hs *HealthServer) livenessHandler(w http.ResponseWriter, r *http.Request) {
	status := hs.GetStatus()

	if status.Healthy {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "Unhealthy: %s", status.Message)
	}
}

// readinessHandler handles the /readiness endpoint
func (hs *HealthServer) readinessHandler(w http.ResponseWriter, r *http.Request) {
	status := hs.GetStatus()

	if status.Ready {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Ready")
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "Not ready: %s", status.Message)
	}
}

// statusHandler handles the /status endpoint (detailed JSON)
func (hs *HealthServer) statusHandler(w http.ResponseWriter, r *http.Request) {
	status := hs.GetStatus()

	w.Header().Set("Content-Type", "application/json")

	httpStatus := http.StatusOK
	if !status.Ready {
		httpStatus = http.StatusServiceUnavailable
	}
	w.WriteHeader(httpStatus)

	if err := json.NewEncoder(w).Encode(status); err != nil {
		hs.log.WithError(err).Error("Failed to encode status response")
	}
}

func (hs *HealthServer) ServeHealth(t *tomb.Tomb) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/liveness", hs.livenessHandler)
	mux.HandleFunc("/readiness", hs.readinessHandler)
	mux.HandleFunc("/status", hs.statusHandler)

	// Create TCP listener for the health server
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", hs.port))
	if err != nil {
		// Try with a retry mechanism
		for i := 0; i < 3; i++ {
			hs.log.Warnf("Failed to bind to port %d, retrying in 5 seconds...", hs.port)
			time.Sleep(5 * time.Second)
			listener, err = net.Listen("tcp", fmt.Sprintf(":%d", hs.port))
			if err == nil {
				break
			}
		}
		if err != nil {
			return fmt.Errorf("health server error: %w", err)
		}
	}

	hs.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", hs.port),
		Handler: mux,
	}

	hs.log.Infof("Starting health check server on port %d", hs.port)

	// Start server with our custom listener
	errChan := make(chan error, 1)
	go func() {
		if err := hs.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Wait for tomb to die or server error
	select {
	case <-t.Dying():
		hs.log.Info("Shutting down health check server")
		return hs.server.Close()
	case err := <-errChan:
		return fmt.Errorf("health server error: %w", err)
	}
}
