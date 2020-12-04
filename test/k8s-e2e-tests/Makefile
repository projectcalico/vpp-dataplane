#!/bin/bash

E2E_TEST_VERSION ?= 1.18.12
E2E_TEST_NODES ?= 2
E2E_TEST_FOCUS ?= \[sig-network\].*Conformance

kubernetes-$(E2E_TEST_VERSION)/_output/bin/e2e.test:
	wget https://github.com/kubernetes/kubernetes/archive/v$(E2E_TEST_VERSION).tar.gz
	tar -xvf v$(E2E_TEST_VERSION).tar.gz
	rm v$(E2E_TEST_VERSION).tar.gz
	make -C kubernetes-$(E2E_TEST_VERSION) WHAT=test/e2e/e2e.test

test: kubernetes-$(E2E_TEST_VERSION)/_output/bin/e2e.test
	KUBECONFIG=~/.kube/config kubernetes-$(E2E_TEST_VERSION)/_output/bin/e2e.test -ginkgo.focus="$(E2E_TEST_FOCUS)" -num-nodes $(E2E_TEST_NODES)

policy-tests:
	KUBECONFIG=~/.kube/config kubernetes-$(E2E_TEST_VERSION)/_output/bin/e2e.test -ginkgo.focus="\[sig-network\].*NetworkPolicy.*" -num-nodes $(E2E_TEST_NODES)

conformance-tests:
	KUBECONFIG=~/.kube/config kubernetes-$(E2E_TEST_VERSION)/_output/bin/e2e.test -ginkgo.focus="\[sig-network\].*Conformance" -num-nodes $(E2E_TEST_NODES)
