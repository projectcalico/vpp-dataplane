export KUBECONFIG ?= $(shell realpath ~/.kube/config)
E2E_TEST_VERSION ?= 1.18.12
E2E_TEST_NODES ?= 2
E2E_TEST_FOCUS ?= "\[sig-network\].*Conformance"
E2E_TEST_BINARY ?= kubernetes-$(E2E_TEST_VERSION)/_output/bin/e2e.test

.PHONY: test all-tests policy-tests conformance-tests
.PHONY: calico-tests calico-all-tests calico-net-tests calico-npol-tests

kubernetes-$(E2E_TEST_VERSION)/_output/bin/e2e.test:
	wget https://github.com/kubernetes/kubernetes/archive/v$(E2E_TEST_VERSION).tar.gz
	tar -xvf v$(E2E_TEST_VERSION).tar.gz
	rm v$(E2E_TEST_VERSION).tar.gz
	make -C kubernetes-$(E2E_TEST_VERSION) WHAT=test/e2e/e2e.test

test: $(E2E_TEST_BINARY)
	$(E2E_TEST_BINARY) -ginkgo.focus="$(E2E_TEST_FOCUS)" -num-nodes $(E2E_TEST_NODES)

all-tests:
	E2E_TEST_FOCUS="\[sig-network\].*(NetworkPolicy|Conformance).*" $(MAKE) test

policy-tests: $(E2E_TEST_BINARY)
	E2E_TEST_FOCUS="\[sig-network\].*NetworkPolicy.*" $(MAKE) test

conformance-tests: $(E2E_TEST_BINARY)
	E2E_TEST_FOCUS="\[sig-network\].*Conformance" $(MAKE) test

calico-tests: $(E2E_TEST_BINARY)
	$(E2E_TEST_BINARY) -ginkgo.focus="$(E2E_TEST_FOCUS)" -num-nodes $(E2E_TEST_NODES) --e2ecfg.product=calico --e2ecfg.release-stream=3.17 --e2ecfg.installer=manual

calico-all-tests:
	E2E_TEST_FOCUS="\[calico\]" $(MAKE) calico-tests

calico-net-tests: $(E2E_TEST_BINARY)
	E2E_TEST_FOCUS="\[calico\].*Network" $(MAKE) calico-tests

calico-npol-tests: $(E2E_TEST_BINARY)
	E2E_TEST_FOCUS="\[calico\].*should correctly implement NetworkPolicy" $(MAKE) calico-tests

