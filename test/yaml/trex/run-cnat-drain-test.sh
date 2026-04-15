#!/bin/bash
# run-cnat-drain-test.sh
#
# Automates the trex cnat session drain benchmark on an existing cluster:
#   1. Deploy trex pod
#   2. Configure MAC from VPP memif
#   3. Start trex daemon
#   4. Generate traffic profile (trex.py) from trex_template.py
#   5. Run traffic at full speed
#   6. Poll cnat sessions, record peak
#   7. Stop traffic, measure drain time via cnat scanner
#
# Configurable env vars:
#   DST_ADDRESS            Destination IP for traffic (default: 1.2.3.4)
#   SRC_ADDRESS            Source IP range start (default: 12.0.0.0)
#   SRC_ADDRESS2           Source IP range end   (default: 12.0.16.0)
#   DST_PORT               Destination UDP port (default: 4444)
#   SRC_PORT               Source port range start (default: 4444)
#   SRC_PORT2              Source port range end   (default: 4444)
#   TRAFFIC_DURATION       Seconds to run traffic before stopping (default: 60)
#   POLL_INTERVAL          Seconds between session count polls (default: 2)
#   LIMIT_FLOWS            Max concurrent flows generated (default: 10000000)
#   SESSION_DRAIN_TIMEOUT  Max seconds to wait for drain to complete (default: 300)
#   TREX_NAMESPACE         Kubernetes namespace for trex pod (default: trex)
#   VPP_NAMESPACE          Kubernetes namespace for calico-vpp (default: calico-vpp-dataplane)

set -euo pipefail

SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

DST_ADDRESS=${DST_ADDRESS:-1.2.3.4}
SRC_ADDRESS=${SRC_ADDRESS:-12.0.0.0}
SRC_ADDRESS2=${SRC_ADDRESS2:-12.16.0.0}
DST_PORT=${DST_PORT:-4444}
SRC_PORT=${SRC_PORT:-4444}
SRC_PORT2=${SRC_PORT2:-4444}
TRAFFIC_DURATION=${TRAFFIC_DURATION:-30}
POLL_INTERVAL=${POLL_INTERVAL:-2}
LIMIT_FLOWS=${LIMIT_FLOWS:-10000000}
SESSION_DRAIN_TIMEOUT=${SESSION_DRAIN_TIMEOUT:-300}
TREX_NAMESPACE=${TREX_NAMESPACE:-trex}
VPP_NAMESPACE=${VPP_NAMESPACE:-calico-vpp-dataplane}

TREX_POD=trex
TREX_PYTHONPATH=/usr/local/share/trex-interactive
TREX_EXT_LIBS=/usr/local/share/trex-external_libs

function green () { printf "\e[0;32m%s\e[0m\n" "$1"; }
function blue  () { printf "\e[0;34m%s\e[0m\n" "$1"; }
function red   () { printf "\e[0;31m%s\e[0m\n" "$1"; }

# Pipe trex console commands (via stdin) into the interactive console inside the pod.
trex_console () {
    kubectl exec -i -n "$TREX_NAMESPACE" "$TREX_POD" -- \
        env PYTHONPATH="${TREX_PYTHONPATH}" TREX_EXT_LIBS="${TREX_EXT_LIBS}" \
        python3 -m trex.console.trex_console
}

# Wait until the trex daemon responds on port 4501.
wait_for_trex_daemon () {
    local output
    for i in $(seq 1 15); do
        output=$(echo "stats" | trex_console 2>&1)
        if ! echo "$output" | grep -q 'Failed to get server response'; then
            return 0
        fi
        sleep 2
    done
    red "trex daemon did not respond after 30s — check /tmp/trex-daemon.log"
    return 1
}

# ---------------------------------------------------------------------------
# Step 1: Deploy trex pod
# ---------------------------------------------------------------------------
blue "[1/9] Deploying trex pod in namespace '$TREX_NAMESPACE'..."
kubectl create namespace "$TREX_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "$SCRIPTDIR/test.yaml"
kubectl -n "$TREX_NAMESPACE" wait --for=condition=Ready pod/"$TREX_POD" --timeout=120s
green "  trex pod is Ready"

# ---------------------------------------------------------------------------
# Step 2: Find VPP pod on the same node
# ---------------------------------------------------------------------------
blue "[2/9] Locating VPP pod on same node as trex..."
NODE=$(kubectl -n "$TREX_NAMESPACE" get pod "$TREX_POD" -o jsonpath='{.spec.nodeName}')
VPP_POD=$(kubectl -n "$VPP_NAMESPACE" get pods \
    --field-selector="spec.nodeName=${NODE}" \
    -o jsonpath='{.items[0].metadata.name}')

if [[ -z "$VPP_POD" ]]; then
    red "No calico-vpp-node pod found on node '$NODE'"
    exit 1
fi
green "  Node: $NODE"
green "  VPP pod: $VPP_POD"

# ---------------------------------------------------------------------------
# Step 3: Get memif MAC from VPP and configure trex-start
# ---------------------------------------------------------------------------
blue "[3/9] Getting memif MAC from VPP..."
MAC_ADDR=$(kubectl -n "$VPP_NAMESPACE" exec "$VPP_POD" -c vpp -- \
    vppctl sh hard 2>/dev/null \
    | grep -A3 memi \
    | grep Ether \
    | awk '{print $3}')

if [[ -z "$MAC_ADDR" ]]; then
    red "Could not read memif MAC from VPP — is the trex pod's memif attached yet?"
    exit 1
fi
green "  Memif MAC: $MAC_ADDR"

kubectl exec -n "$TREX_NAMESPACE" "$TREX_POD" -- \
    bash -c "sed -i 's/dest_mac: .*/dest_mac: ${MAC_ADDR}/g' /usr/local/bin/trex-start"
green "  Patched dest_mac in trex-start"

# ---------------------------------------------------------------------------
# Step 4: Start trex daemon in background
# ---------------------------------------------------------------------------
blue "[4/9] Starting trex daemon (trex -i)..."
# Keep the kubectl exec session open (trex-start is the foreground process of the exec).
# Backgrounding the exec itself avoids the daemon being killed when the shell exits.
kubectl exec -n "$TREX_NAMESPACE" "$TREX_POD" -- \
    bash /usr/local/bin/trex-start > /tmp/trex-daemon.log 2>&1 &
TREX_DAEMON_PID=$!
wait_for_trex_daemon
green "  trex daemon ready (pid $TREX_DAEMON_PID)"

# ---------------------------------------------------------------------------
# Step 5: Generate traffic profile /trex-scripts/trex.py from trex_template.py
# ---------------------------------------------------------------------------
blue "[5/9] Generating traffic profile /trex-scripts/trex.py..."
kubectl exec -n "$TREX_NAMESPACE" "$TREX_POD" -- \
    bash -c "export DST_ADDRESS=${DST_ADDRESS} SRC_ADDRESS=${SRC_ADDRESS} SRC_ADDRESS2=${SRC_ADDRESS2} \
                    DST_PORT=${DST_PORT} SRC_PORT=${SRC_PORT} SRC_PORT2=${SRC_PORT2} && \
             envsubst < /trex-scripts/trex_template.py > /trex-scripts/trex.py"
green "  Profile generated"

get_session_count () {
    kubectl exec -n "$VPP_NAMESPACE" "$VPP_POD" -c vpp -- \
        vppctl show cnat session 2>/dev/null \
        | grep -i "active elements" \
        | awk '{print $1}' \
        || echo 0
}
# Capture baseline before traffic so drain completion is relative, not absolute.
baseline_sessions=$(get_session_count)
baseline_sessions=${baseline_sessions:-0}
# Drain is considered complete when sessions return within 10% of baseline + 50
# (tolerates natural runtime fluctuation and unrelated sessions).
DRAIN_THRESHOLD=$(( baseline_sessions + baseline_sessions / 10 + 50 ))
green "  Baseline sessions: ${baseline_sessions}  (drain threshold: ≤${DRAIN_THRESHOLD})"

# ---------------------------------------------------------------------------
# Step 6: Start traffic
# ---------------------------------------------------------------------------
blue "[6/9] Starting traffic"
echo "start -f /trex-scripts/trex.py -p 0 -m 10mbps" | trex_console
green "  Traffic started"

# ---------------------------------------------------------------------------
# Step 7: Poll cnat sessions for TRAFFIC_DURATION seconds, track peak
# ---------------------------------------------------------------------------
blue "[7/9] Polling cnat sessions for ${TRAFFIC_DURATION}s (poll every ${POLL_INTERVAL}s)..."

max_sessions=0
elapsed=0
#PEAK_VERBOSE=""

while (( elapsed < TRAFFIC_DURATION )); do
    count=$(get_session_count)
    count=${count:-0}
    printf "  t=+%ds  cnat sessions: %d\n" "$elapsed" "$count"
    if (( count > max_sessions )); then
        max_sessions=$count
        #PEAK_VERBOSE=$(kubectl exec -n "$VPP_NAMESPACE" "$VPP_POD" -c vpp -- \
        #    vppctl show cnat session verbose 2>/dev/null || true)
    fi
    sleep "$POLL_INTERVAL"
    (( elapsed += POLL_INTERVAL ))
done

green "  Traffic phase done. Peak sessions observed: $max_sessions"

# ---------------------------------------------------------------------------
# Step 8: Stop traffic
# ---------------------------------------------------------------------------
blue "[8/9] Stopping traffic (stop -a)..."
echo "stop -a" | trex_console
green "  Traffic stopped"

DRAIN_START=$(date +%s)
DRAIN_START_HUMAN=$(date -Iseconds)

# ---------------------------------------------------------------------------
# Step 9: Poll drain until sessions return to near-baseline or timeout
# ---------------------------------------------------------------------------
blue "[9/9] Waiting for cnat scanner to drain sessions (timeout: ${SESSION_DRAIN_TIMEOUT}s)..."
blue "  Waiting 30s for UDP session lifetime before polling..."
sleep 30

drain_elapsed=30
prev_count=-1

while (( drain_elapsed < SESSION_DRAIN_TIMEOUT )); do
    count=$(get_session_count)
    count=${count:-0}
    if (( count != prev_count )); then
        printf "  drain t=+%ds  cnat sessions: %d  (threshold: %d)\n" \
            "$drain_elapsed" "$count" "$DRAIN_THRESHOLD"
        prev_count=$count
    fi
    if (( count <= DRAIN_THRESHOLD )); then
        break
    fi
    sleep "$POLL_INTERVAL"
    (( drain_elapsed += POLL_INTERVAL ))
done

DRAIN_END=$(date +%s)
DRAIN_DURATION=$(( DRAIN_END - DRAIN_START ))

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
echo ""
green "============================================================"
green "  CNAT DRAIN TEST RESULTS"
green "============================================================"
printf "  Destination              : %s:%s\n" "$DST_ADDRESS" "$DST_PORT"
printf "  Source range             : %s..%s  ports %s..%s\n" "$SRC_ADDRESS" "$SRC_ADDRESS2" "$SRC_PORT" "$SRC_PORT2"
printf "  Limit flows              : %d\n"    "$LIMIT_FLOWS"
printf "  Traffic duration         : %ds\n"   "$TRAFFIC_DURATION"
printf "  Poll interval            : %ds\n"   "$POLL_INTERVAL"
printf "  Baseline cnat sessions   : %d\n"    "$baseline_sessions"
printf "  Peak cnat sessions       : %d\n"    "$max_sessions"
printf "  Drain threshold          : ≤%d\n"   "$DRAIN_THRESHOLD"
printf "  Sessions at drain end    : %d\n"    "$count"
printf "  Drain started at         : %s\n"    "$DRAIN_START_HUMAN"
if (( drain_elapsed >= SESSION_DRAIN_TIMEOUT && count > DRAIN_THRESHOLD )); then
    red   "  Drain result             : TIMEOUT (${SESSION_DRAIN_TIMEOUT}s), ${count} sessions remain"
else
    printf "  Sessions drained in      : %ds\n"   "$DRAIN_DURATION"
    if (( DRAIN_DURATION > 30 && max_sessions > 0 )); then
        printf "  Drain rate               : ~%d sessions/s\n" "$(( max_sessions / (DRAIN_DURATION - 30) ))"
    fi
    green "  Drain result             : COMPLETE"
fi
green "============================================================"

#if [[ -n "$PEAK_VERBOSE" ]]; then
#    echo ""
#    blue "--- 'show cnat session verbose' snapshot at peak ---"
#    echo "$PEAK_VERBOSE"
#fi

# ---------------------------------------------------------------------------
# Cleanup (commented out — uncomment to tear down after test)
# ---------------------------------------------------------------------------
blue "Cleaning up..."
kubectl delete -f "$SCRIPTDIR/test.yaml" --ignore-not-found
kubectl delete namespace "$TREX_NAMESPACE" --ignore-not-found

