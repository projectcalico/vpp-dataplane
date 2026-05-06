#!/bin/bash

# Test script for Calico VPP agent healthcheck endpoints
# This script can be used to verify the healthcheck implementation

set -e

HEALTHCHECK_PORT=${HEALTHCHECK_PORT:-9090}
POD_NAME=${1:-}
KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config}
LOCAL_PORT=${LOCAL_PORT:-19090}

# Function to check if kubectl is properly configured
check_kubectl_config() {
    if ! kubectl --kubeconfig="$KUBECONFIG" get nodes &>/dev/null; then
        echo "Error: Cannot connect to Kubernetes cluster. Please check your kubectl configuration."
        echo "If running with sudo, try: sudo KUBECONFIG=$KUBECONFIG $0 $POD_NAME"
        exit 1
    fi
}

# Function to clean up port-forward process
cleanup() {
    if [ -n "$PORT_FORWARD_PID" ]; then
        echo "Cleaning up port-forward (PID: $PORT_FORWARD_PID)"
        kill $PORT_FORWARD_PID 2>/dev/null || true
    fi
}

# Set up trap to clean up port-forward on exit
trap cleanup EXIT

if [ -z "$POD_NAME" ]; then
    echo "Usage: $0 <calico-vpp-pod-name>"
    echo ""
    echo "Example:"
    echo "  $0 calico-vpp-node-xxxxx"
    echo ""
    echo "Options:"
    echo "  HEALTHCHECK_PORT=<port>   Set a different healthcheck port in the container (default: 9090)"
    echo "  LOCAL_PORT=<port>    Set a different local port for port-forwarding (default: 19090)"
    echo "  KUBECONFIG=<path>    Set a different kubeconfig path"
    exit 1
fi

# Check kubectl configuration
check_kubectl_config

# Verify pod exists
if ! kubectl --kubeconfig="$KUBECONFIG" get pod -n calico-vpp-dataplane "$POD_NAME" &>/dev/null; then
    echo "Error: Pod $POD_NAME not found in namespace calico-vpp-dataplane"
    echo "Available pods:"
    kubectl --kubeconfig="$KUBECONFIG" get pods -n calico-vpp-dataplane
    exit 1
fi

echo "Testing healthcheck endpoints for pod: $POD_NAME"
echo "Using healthcheck port: $HEALTHCHECK_PORT"
echo "Using kubeconfig: $KUBECONFIG"
echo ""

# Port-forward approach (always use this since container has no curl/wget/nc)
echo "Setting up port-forward from localhost:$LOCAL_PORT to pod:$HEALTHCHECK_PORT"
kubectl --kubeconfig="$KUBECONFIG" port-forward -n calico-vpp-dataplane "$POD_NAME" $LOCAL_PORT:$HEALTHCHECK_PORT > /dev/null 2>&1 &
PORT_FORWARD_PID=$!

# Wait for port-forward to establish
echo "Waiting for port-forward to establish..."
sleep 2
echo ""

# Test if port-forward is working
if ! curl -s "http://localhost:$LOCAL_PORT/liveness" &>/dev/null; then
    echo "Error: Port-forward not working. Please check if port $LOCAL_PORT is available."
    exit 1
fi

# Test liveness endpoint
echo "=== Testing /liveness endpoint ==="
curl -s -w "\nHTTP Status: %{http_code}\n" "http://localhost:$LOCAL_PORT/liveness" || true
echo ""

# Test readiness endpoint
echo "=== Testing /readiness endpoint ==="
curl -s -w "\nHTTP Status: %{http_code}\n" "http://localhost:$LOCAL_PORT/readiness" || true
echo ""

# Test status endpoint (detailed JSON)
echo "=== Testing /status endpoint (detailed) ==="
curl -s "http://localhost:$LOCAL_PORT/status" | python3 -m json.tool || \
    curl -s "http://localhost:$LOCAL_PORT/status"
echo ""

# Check Kubernetes probe status
echo "=== Kubernetes Probe Status ==="
kubectl --kubeconfig="$KUBECONFIG" get pod -n calico-vpp-dataplane "$POD_NAME" -o jsonpath='{.status.conditions[?(@.type=="Ready")]}' | python3 -m json.tool || true
echo ""

echo "=== Pod Status ==="
kubectl --kubeconfig="$KUBECONFIG" get pod -n calico-vpp-dataplane "$POD_NAME" -o wide
echo ""