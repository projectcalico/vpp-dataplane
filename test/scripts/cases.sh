#!/bin/bash

# Copyright (c) 2020 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source $SCRIPTDIR/cases_util.sh

# This file contains integration test scenarios. They take the form
# of kubectl commands to be run on a running cluster with CNI and
# test framework installed

function test_vpp_restart_v4 ()
{
	load_parameters
	NS=iperf
	POD=iperf-client
	kill_local_vpp
	test "iperf ServiceName -P4" iperf -c iperf-service                              -t 1 -P4 -i1
	kill_local_agent
	test "iperf ServiceName -P4" iperf -c iperf-service                              -t 1 -P4 -i1
}

function test_vpp_restart_v6 ()
{
	load_parameters
	NS=iperf
	POD=iperf-client
	kill_local_vpp
	test "iperf ServiceName -P4" iperf -V -c iperf-service                           -t 1 -P4 -i1
	kill_local_agent
	test "iperf ServiceName -P4" iperf -V -c iperf-service                           -t 1 -P4 -i1
}

function test_snat_ip4 ()
{
	load_parameters
	NS=iperf
	POD=iperf-client-samehost
	configure_nodessh_ip4
	start_iperf4
	test "iperf 20.0.0.2 -P4" iperf -c 20.0.0.2                                      -t 1 -P1 -i1
	stop_iperf
	assert_test_output_contains "connected with 20.0.0.1"
}

function test_snat_ip6 ()
{
	load_parameters
	NS=iperf
	POD=iperf-client-samehost
	configure_nodessh_ip6
	start_iperf6
	test "iperf fd11::2 -P4" iperf -V -c fd11::2                                     -t 1 -P1 -i1
	stop_iperf
	assert_test_output_contains "connected with fd11::1"
}

function test_nodeport_ip4 ()
{
	load_parameters
	NS=iperf
	SVC=iperf-service-nodeport-v4
	PROTO=TCP
	configure_nodessh_ip4
	sshtest "Nodeport v4" iperf -c $(getNodeIP node1) -p $(getServiceNodePort) -t 1 -P1 -i1
	assert_test_output_contains_not "connect failed"
}

function test_nodeport_ip6 ()
{
	load_parameters
	NS=iperf
	SVC=iperf-service-nodeport-v6
	PROTO=TCP
	configure_nodessh_ip6
	sshtest "Nodeport v6" iperf -V -c $(getNodeIP node1) -p $(getServiceNodePort) -t 1 -P1 -i1
	assert_test_output_contains_not "connect failed"
}

function test_metallb ()
{
	if kubectl -n calico-vpp-dataplane exec -it $(kubectl -n calico-vpp-dataplane get pods -owide | awk '$0 ~  /node1/ {print $1}') gobgp global rib |grep 172.217.3.4/32; then
	  green "Assert OK (specific loadBalancerIP advertised)"
	else
	  red "Assert FAILED (specific loadBalancerIP not advertised)"
	fi
	if kubectl -n calico-vpp-dataplane exec -it $(kubectl -n calico-vpp-dataplane get pods -owide | awk '$0 ~  /node1/ {print $1}') gobgp global rib |grep 192.168.3.0/24; then
	  green "Assert OK (externalIPs advertised)"
	else
	  red "Assert FAILED (externalIPs not advertised)"
	fi
}

function test_ipv4 ()
{
	NS=iperf
	POD=iperf-client
	echo "--Cross node TCP tests--"
	test "DNS lookup" nslookup kubernetes.default
	test "iperf PodIP"           iperf -c $(NS=iperf POD=iperf-server onePodIP)      -t 1 -P1 -i1
	assert_test_output_contains_not "connect failed"
	test "iperf ServiceIP"       iperf -c $(NS=iperf SVC=iperf-service getClusterIP) -t 1 -P1 -i1
	assert_test_output_contains_not "connect failed"
	test "iperf ServiceName -P4" iperf -c iperf-service                              -t 1 -P4 -i1
	assert_test_output_contains_not "connect failed"

	echo "--Cross node UDP tests--"
	test "iperf PodIP"           iperf -c $(NS=iperf POD=iperf-server onePodIP)      -t 1 -P1 -i1 -u -l1000 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceIP"       iperf -c $(NS=iperf SVC=iperf-service getClusterIP) -t 1 -P1 -i1 -u -l1000 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceName -P4" iperf -c iperf-service                              -t 1 -P4 -i1 -u -l1000 -p5003
	assert_test_output_contains_not WARNING

	POD=iperf-client-samehost
	echo "--Same host TCP tests--"
	test "DNS lookup" nslookup kubernetes.default
	test "iperf PodIP"           iperf -c $(NS=iperf POD=iperf-server onePodIP)      -t 1 -P1 -i1
	assert_test_output_contains_not "connect failed"
	test "iperf ServiceIP"       iperf -c $(NS=iperf SVC=iperf-service getClusterIP) -t 1 -P1 -i1
	assert_test_output_contains_not "connect failed"
	test "iperf ServiceName -P4" iperf -c iperf-service                              -t 1 -P4 -i1
	assert_test_output_contains_not "connect failed"

	echo "--Same host UDP tests--"
	test "iperf PodIP"           iperf -c $(NS=iperf POD=iperf-server onePodIP)      -t 1 -P1 -i1 -u -l1000 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceIP"       iperf -c $(NS=iperf SVC=iperf-service getClusterIP) -t 1 -P1 -i1 -u -l1000 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceName -P4" iperf -c iperf-service                              -t 1 -P4 -i1 -u -l1000 -p5003
	assert_test_output_contains_not WARNING
}

function test_ipv6 ()
{
	NS=iperf
	POD=iperf-client
	echo "--Cross node TCP tests--"
	test "DNS lookup" nslookup kubernetes.default
	test "iperf PodIP"           iperf -V -c $(NS=iperf POD=iperf-server onePodIP_V6)      -t 1 -P1 -i1
	test "iperf ServiceIP"       iperf -V -c $(NS=iperf SVC=iperf-service-v6 getClusterIP) -t 1 -P1 -i1
	test "iperf ServiceName -P4" iperf -V -c iperf-service-v6                              -t 1 -P4 -i1

	echo "--Cross node UDP tests--"
	test "iperf PodIP"           iperf -V -c $(NS=iperf POD=iperf-server onePodIP_V6)      -t 1 -P1 -i1 -u -l1000 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceIP"       iperf -V -c $(NS=iperf SVC=iperf-service-v6 getClusterIP) -t 1 -P1 -i1 -u -l1000 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceName -P4" iperf -V -c iperf-service-v6                              -t 1 -P4 -i1 -u -l1000 -p5003
	assert_test_output_contains_not WARNING

	POD=iperf-client-samehost
	echo "--Same host tests--"
	test "DNS lookup" nslookup kubernetes.default
	test "iperf PodIP"           iperf -V -c $(NS=iperf POD=iperf-server onePodIP_V6)      -t 1 -P1 -i1
	test "iperf ServiceIP"       iperf -V -c $(NS=iperf SVC=iperf-service-v6 getClusterIP) -t 1 -P1 -i1
	test "iperf ServiceName -P4" iperf -V -c iperf-service-v6                              -t 1 -P4 -i1

	echo "--Same host UDP tests--"
	test "iperf PodIP"           iperf -V -c $(NS=iperf POD=iperf-server onePodIP_V6)      -t 1 -P1 -i1 -u -l1000 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceIP"       iperf -V -c $(NS=iperf SVC=iperf-service-v6 getClusterIP) -t 1 -P1 -i1 -u -l1000 -p5003
	assert_test_output_contains_not WARNING
	test "iperf ServiceName -P4" iperf -V -c iperf-service-v6                              -t 1 -P4 -i1 -u -l1000 -p5003
	assert_test_output_contains_not WARNING
}

function test_ipv4_vcl ()
{
	NS=iperf3-vcl
	POD=iperf3-client
	echo "--Cross node VCL TCP tests--"
	test "DNS lookup" nslookup kubernetes.default
	test "iperf PodIP"           iperf3-vcl -c $(NS=$NS POD=iperf3-server onePodIP)      -t 1 -P1 -i1
	assert_test_output_contains_not "connect failed"
	test "iperf ServiceIP"       iperf3-vcl -c $(NS=$NS SVC=iperf3-service getClusterIP) -t 1 -P1 -i1
	assert_test_output_contains_not "connect failed"
}

function test_policy_ipv4 ()
{
    NS=policy
    SVC=policy-service
    POLICY_SVC_IP=$(getClusterIP)

    # ---- Baseline: no policies, all traffic should be allowed ----
    echo "--Baseline: no policies--"
    POD=policy-client-samehost
    test "Baseline TCP same-node"    curl -s --max-time 3 http://${POLICY_SVC_IP}
    assert_test_output_contains "Welcome to nginx"

    POD=policy-client
    test "Baseline TCP cross-node"   curl -s --max-time 3 http://${POLICY_SVC_IP}
    assert_test_output_contains "Welcome to nginx"

    # ---- Calico: Ingress Deny All ----
    echo "--Calico ingress deny all--"
    cat <<EOF | apply_and_wait_policy
apiVersion: crd.projectcalico.org/v1
kind: NetworkPolicy
metadata:
  name: calico-ingress-deny-all
  namespace: policy
spec:
  selector: role == 'server'
  ingress: []
EOF

    POD=policy-client-samehost
    test_expect_fail "Calico ingress deny same-node"   curl -s --max-time 3 http://${POLICY_SVC_IP}

    POD=policy-client
    test_expect_fail "Calico ingress deny cross-node"  curl -s --max-time 3 http://${POLICY_SVC_IP}

    cat <<EOF | delete_and_wait_policy
apiVersion: crd.projectcalico.org/v1
kind: NetworkPolicy
metadata:
  name: calico-ingress-deny-all
  namespace: policy
EOF

    # ---- Calico: Ingress Allow TCP:80 from clients ----
    echo "--Calico ingress allow TCP:80--"
    cat <<EOF | apply_and_wait_policy
apiVersion: crd.projectcalico.org/v1
kind: NetworkPolicy
metadata:
  name: calico-ingress-allow-tcp80
  namespace: policy
spec:
  selector: role == 'server'
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: role == 'client'
    destination:
      ports:
        - 80
EOF

    POD=policy-client-samehost
    test "Calico ingress allow TCP:80 same-node"   curl -s --max-time 3 http://${POLICY_SVC_IP}
    assert_test_output_contains "Welcome to nginx"

    POD=policy-client
    test "Calico ingress allow TCP:80 cross-node"  curl -s --max-time 3 http://${POLICY_SVC_IP}
    assert_test_output_contains "Welcome to nginx"

    cat <<EOF | delete_and_wait_policy
apiVersion: crd.projectcalico.org/v1
kind: NetworkPolicy
metadata:
  name: calico-ingress-allow-tcp80
  namespace: policy
EOF

    # ---- Calico: Egress Deny All ----
    echo "--Calico egress deny all--"
    cat <<EOF | apply_and_wait_policy
apiVersion: crd.projectcalico.org/v1
kind: NetworkPolicy
metadata:
  name: calico-egress-deny-all
  namespace: policy
spec:
  selector: role == 'client'
  egress: []
EOF

    POD=policy-client-samehost
    test_expect_fail "Calico egress deny same-node"  curl -s --max-time 3 http://${POLICY_SVC_IP}

    cat <<EOF | delete_and_wait_policy
apiVersion: crd.projectcalico.org/v1
kind: NetworkPolicy
metadata:
  name: calico-egress-deny-all
  namespace: policy
EOF

    # ---- Kubernetes NetworkPolicy: Ingress Deny All ----
    echo "--K8s ingress deny all--"
    cat <<EOF | apply_and_wait_policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: k8s-ingress-deny-all
  namespace: policy
spec:
  podSelector:
    matchLabels:
      role: server
  policyTypes:
    - Ingress
EOF

    POD=policy-client-samehost
    test_expect_fail "K8s ingress deny same-node"   curl -s --max-time 3 http://${POLICY_SVC_IP}

    POD=policy-client
    test_expect_fail "K8s ingress deny cross-node"  curl -s --max-time 3 http://${POLICY_SVC_IP}

    cat <<EOF | delete_and_wait_policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: k8s-ingress-deny-all
  namespace: policy
EOF

    # ---- Kubernetes NetworkPolicy: Ingress Allow TCP:80 from clients ----
    echo "--K8s ingress allow TCP:80--"
    cat <<EOF | apply_and_wait_policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: k8s-ingress-allow-tcp80
  namespace: policy
spec:
  podSelector:
    matchLabels:
      role: server
  policyTypes:
    - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          role: client
    ports:
    - protocol: TCP
      port: 80
EOF

    POD=policy-client-samehost
    test "K8s ingress allow TCP:80 same-node"   curl -s --max-time 3 http://${POLICY_SVC_IP}
    assert_test_output_contains "Welcome to nginx"

    POD=policy-client
    test "K8s ingress allow TCP:80 cross-node"  curl -s --max-time 3 http://${POLICY_SVC_IP}
    assert_test_output_contains "Welcome to nginx"

    cat <<EOF | delete_and_wait_policy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: k8s-ingress-allow-tcp80
  namespace: policy
EOF

    # ---- Session tracking: established session survives a mid-flight deny policy ----
    # Start a rate-limited download before applying the deny policy so the TCP session
    # is active in VPP's session table when the policy lands. Existing sessions should
    # continue (stateful enforcement); only new connections should be dropped.
    echo "--Session tracking: established session survives new deny policy--"
    POD=policy-client-samehost

    # --limit-rate 100 means ~8s to transfer nginx's ~800-byte response, giving enough
    # time to apply the policy mid-flight.
    kubectl exec -n $NS $POD -- sh -c \
        "nohup curl -s --max-time 30 --limit-rate 100 http://${POLICY_SVC_IP}/ \
         -o /tmp/session_track.out 2>/tmp/session_track.err &"
    sleep 1  # Allow TCP handshake and session entry to be created in VPP

    # Apply ingress deny-all while the session is in flight
    cat <<EOF | apply_and_wait_policy
apiVersion: crd.projectcalico.org/v1
kind: NetworkPolicy
metadata:
  name: calico-session-deny
  namespace: policy
spec:
  selector: role == 'server'
  ingress: []
EOF

    # New connections must be blocked immediately
    test_expect_fail "New connection denied while session active"   curl -s --max-time 3 http://${POLICY_SVC_IP}

    # Wait for the in-flight download to finish (started ~5s ago, running for ~8s total)
    sleep 6

    # The established session should have completed and delivered the response
    echo "-----------TESTCASE Established session completed successfully-----------" > $LAST_TEST_LOGFILE
    kubectl exec -n $NS $POD -- cat /tmp/session_track.out >> $LAST_TEST_LOGFILE 2>&1
    cat $LAST_TEST_LOGFILE >> $LOGFILE
    assert_test_output_contains "Welcome to nginx"

    cat <<EOF | delete_and_wait_policy
apiVersion: crd.projectcalico.org/v1
kind: NetworkPolicy
metadata:
  name: calico-session-deny
  namespace: policy
EOF

    # ---- Cleanup & verify connectivity restored ----
    echo "--Cleanup: verify all policies removed--"
    kubectl -n policy delete networkpolicy --all --ignore-not-found
    kubectl -n policy delete networkpolicies.crd.projectcalico.org --all --ignore-not-found 2>/dev/null || true
    sleep ${POLICY_PROPAGATION_DELAY:-3}

    POD=policy-client
    test "Post-cleanup TCP cross-node" curl -s --max-time 3 http://${POLICY_SVC_IP}
    assert_test_output_contains "Welcome to nginx"
}

function test_nat_ipv4 ()
{
       NS=nat
       SVC=nat-service
       NAT_SVC_IP=$(getClusterIP)
       SVC=nat-udp-service
       NAT_UDP_SVC_IP=$(getClusterIP)

       echo "--DNAT same-node TCP: client -> ClusterIP -> nginx--"
       POD=nat-client-samehost
       test "DNAT same-node via ClusterIP (TCP)"    curl -s --max-time 3 http://${NAT_SVC_IP}
       assert_test_output_contains "Welcome to nginx"

       echo "--DNAT same-node DNS+TCP: client -> ServiceName -> nginx--"
       test "DNAT same-node via ServiceName (DNS)"  curl -s --max-time 3 http://nat-service
       assert_test_output_contains "Welcome to nginx"

       echo "--DNAT same-node UDP: client -> ClusterIP -> echo server--"
       test "DNAT same-node via ClusterIP (UDP)"    sh -c "echo hello | nc -u -w2 ${NAT_UDP_SVC_IP} 9999"
       assert_test_output_contains "hello"

       echo "--DNAT cross-node TCP: client -> ClusterIP -> nginx--"
       POD=nat-client
       test "DNAT cross-node via ClusterIP (TCP)"   curl -s --max-time 3 http://${NAT_SVC_IP}
       assert_test_output_contains "Welcome to nginx"

       echo "--DNAT cross-node DNS+TCP: client -> ServiceName -> nginx--"
       test "DNAT cross-node via ServiceName (DNS)" curl -s --max-time 3 http://nat-service
       assert_test_output_contains "Welcome to nginx"

       echo "--DNAT cross-node UDP: client -> ClusterIP -> echo server--"
       test "DNAT cross-node via ClusterIP (UDP)"   sh -c "echo hello | nc -u -w2 ${NAT_UDP_SVC_IP} 9999"
       assert_test_output_contains "hello"

       echo "--SNAT: pod -> outside cluster--"
       test "SNAT external connectivity"             curl -s --max-time 3 http://checkip.amazonaws.com
       assert_test_output_contains_not "curl: ("
}

if [ $# = 0 ]; then
	echo "Usage"
	for f in $(declare -F); do
		if [[ x$(echo $f | grep -e "^test_" ) != x ]]; then
			echo "cases $(echo $f | sed s/test_//g)"
		fi
	done
else
	mkdir -p $LOG_DIR
	"test_$1"
fi
