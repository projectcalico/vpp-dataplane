include common.mk

check-%:
	@: $(if $(value $*),,$(error $* is undefined))

.PHONY: build
build:
	$(MAKE) -C calico-vpp-agent $@
	$(MAKE) -C vpp-manager $@
	$(MAKE) -C multinet-monitor $@
	$(MAKE) -C cmd/calicovppctl $@

.PHONY: image images
images: image
image:
	$(MAKE) -C calico-vpp-agent $@
	$(MAKE) -C vpp-manager $@
	$(MAKE) -C multinet-monitor $@
	$(MAKE) -C cmd/calicovppctl $@

.PHONY: image-kind
image-kind: image
	@for image in vpp:$(TAG) vpp:dbg-$(TAG) vclsidecar:$(TAG) vclsidecar:dbg-$(TAG) agent:$(TAG) multinet-monitor:$(TAG); do \
		docker image tag calicovpp/$$image localhost:5000/calicovpp/$$image ; \
		docker push localhost:5000/calicovpp/$$image ; \
	done

.PHONY: kind-cluster-name
kind-cluster-name:
	@echo $(CLUSTER_NAME)

.PHONY: kind-rm-cluster
kind-rm-cluster:
	make -C test/kind rm-cluster

.PHONY: kind-new-cluster
kind-new-cluster:
	make -C test/kind new-cluster

.PHONY: kind-install-cni
kind-install-cni:
	make -C test/kind install-cni

.PHONY: kind
kind: kind-new-cluster image-kind kind-install-cni

.PHONY: push
push:
	$(MAKE) -C calico-vpp-agent $@
	$(MAKE) -C vpp-manager $@
	$(MAKE) -C multinet-monitor $@
	$(MAKE) -C cmd/calicovppctl $@

.PHONY: dev
dev:
	$(MAKE) -C calico-vpp-agent ALSO_LATEST=y $@
	$(MAKE) -C vpp-manager ALSO_LATEST=y $@
	$(MAKE) -C multinet-monitor ALSO_LATEST=y $@

.PHONY: clean-vpp
clean-vpp:
	$(MAKE) -C vpp-manager clean-vpp

.PHONY: proto
proto:
	$(MAKE) -C calico-vpp-agent $@

.PHONY: dev.k3s
dev.k3s: dev
	@for x in agent vpp ; do \
		docker save -o /tmp/$$x.tar calicovpp/$$x:latest ; \
		sudo k3s ctr images import /tmp/$$x.tar ; \
		rm -f /tmp/$$x.tar ; \
	done

.PHONY: dev-kind
dev-kind: dev
	make -C test/kind dev

.PHONY: load-kind
load-kind:
	make -C test/kind load

.PHONY: run-prometheus
run-prometheus:
	make -C test/prometheus run

.PHONY: stop-prometheus
stop-prometheus:
	make -C test/prometheus stop

.PHONY: install-test-deps
install-test-deps:
	sudo apt-get update
	sudo apt-get install -y jq nfs-kernel-server qemu-kvm libvirt-daemon-system \
		libvirt-clients bridge-utils qemu ebtables dnsmasq-base libxslt-dev \
		libxml2-dev libvirt-dev zlib1g-dev ruby-dev build-essential \
		libguestfs-tools
	sudo chmod a+r /boot/vmlinuz*	# Required for libguestfs
	sudo adduser `id -un` libvirt
	sudo adduser `id -un` kvm
	wget https://releases.hashicorp.com/vagrant/2.3.4/vagrant_2.3.4-1_amd64.deb
	sudo dpkg -i vagrant_2.3.4-1_amd64.deb
	rm vagrant_2.3.4-1_amd64.deb
	vagrant plugin install vagrant-libvirt
	newgrp libvirt

.PHONY: start-test-cluster
start-test-cluster:
	$(MAKE) -C test/vagrant up

.PHONY: load-images
load-images:
	$(MAKE) -C test/vagrant load-image -j99 IMG=calicovpp/agent:latest
	$(MAKE) -C test/vagrant load-image -j99 IMG=calicovpp/vpp:latest
	$(MAKE) -C test/vagrant load-image -j99 IMG=calicovpp/multinet-monitor:latest

CALICO_INSTALLATION ?= installation-default
.PHONY: test-install-calico
test-install-calico:
	kubectl replace --force -f https://raw.githubusercontent.com/projectcalico/calico/master/manifests/tigera-operator.yaml
	sleep 2
	kubectl apply -f yaml/calico/$(CALICO_INSTALLATION).yaml

# Allows to simply run calico-vpp from release images in a test cluster
.PHONY: test-install-calicovpp
test-install-calicovpp:
	$(MAKE) test-install-calico CALICO_INSTALLATION=installation-test-v4
	kubectl apply -k yaml/overlays/test-vagrant

.PHONY: test-install-calicovpp-v6
test-install-calicovpp-v6:
	$(MAKE) test-install-calico CALICO_INSTALLATION=installation-test-v6
	kubectl apply -k yaml/overlays/test-vagrant-v6

# Allows to simply run calico-vpp from release images in a test cluster with SRv6 configured
.PHONY: test-install-calicovpp-srv6
test-install-calicovpp-srv6:
	$(MAKE) test-install-calico CALICO_INSTALLATION=installation-test-v6
	kubectl kustomize yaml/overlays/test-vagrant-srv6 | kubectl apply -f -

# Allows to run calico-vpp in a test cluster with locally-built binaries for dev / debug
.PHONY: test-install-calicovpp-dev
test-install-calicovpp-dev:
	$(MAKE) test-install-calico CALICO_INSTALLATION=installation-test-v4
	kubectl apply -k yaml/overlays/test-vagrant-mounts

.PHONY: test-install-calicovpp-dev-vxlan
test-install-calicovpp-dev-vxlan:
	$(MAKE) test-install-calico CALICO_INSTALLATION=installation-vxlan
	kubectl apply -k yaml/overlays/test-vagrant-mounts

.PHONY: test-install-calicovpp-dev-v6
test-install-calicovpp-dev-v6:
	$(MAKE) test-install-calico CALICO_INSTALLATION=installation-test-v6
	kubectl apply -k yaml/overlays/test-vagrant-v6-mounts

.PHONY: test-install-calicovpp-dev-srv6
test-install-calicovpp-dev-srv6:
	$(MAKE) test-install-calico CALICO_INSTALLATION=installation-test-v6
	kubectl kustomize yaml/overlays/test-vagrant-srv6-mounts | kubectl apply -f -

.PHONY: run-tests
run-tests:
	test/scripts/test.sh up iperf v4
	kubectl -n iperf wait pod/iperf-client $$(kubectl -n iperf get pods -l 'app in (iperf-server,iperf-nodeport)' -o name) --for=condition=Ready --timeout=60s
	test/scripts/cases.sh ipv4
	test/scripts/test.sh down iperf v4

.PHONY: run-tests-v6
run-tests-v6:
	test/scripts/test.sh up iperf v6
	kubectl -n iperf wait pod/iperf-client $$(kubectl -n iperf get pods -l 'app in (iperf-server,iperf-nodeport)' -o name) --for=condition=Ready --timeout=60s
	test/scripts/cases.sh ipv4
	test/scripts/cases.sh ipv6
	test/scripts/test.sh down iperf v6

.PHONY: restart-calicovpp
restart-calicovpp:
	kubectl -n calico-vpp-dataplane rollout restart ds/calico-vpp-node
	kubectl -n calico-vpp-dataplane rollout status ds/calico-vpp-node

.PHONY: goapi
export VPP_DIR ?= $(shell pwd)/vpp-manager/vpp_build
goapi:
	@go generate -v ./vpplink/generated/

.PHONY: cherry-vpp
cherry-vpp:
	@if [ "$(FORCE)" = "y" ]; then \
		:; \
	else \
		echo "Cherry pick VPP ?"; \
		echo "This will reset current branch"; \
		echo "directory : ${VPP_DIR}"; \
		echo "branch    : $(shell cd ${VPP_DIR} && git branch --show-current)"; \
		echo "Are you sure? [y/N] " && read ans && [ $${ans:-N} = y ]; \
	fi
	@BASE=$(BASE) bash ./vpplink/generated/vpp_clone_current.sh ${VPP_DIR}
	@make goapi

.PHONY: cherry-wipe
cherry-wipe:
	rm -rf ./vpplink/binapi/.cherries-cache
	rm -rf ./vpplink/generated/.cherries-cache

.PHONY: yaml
yaml:
	$(MAKE) -C yaml

.PHONY: release
# TAG must be set to something like v3.24.0
# CALICO_TAG must be the latest calico release, like v3.24.1
release: check-TAG check-CALICO_TAG
	@[ -z "$(shell git status --porcelain)" ] || (echo "Repo is not clean! Aborting." && exit 1)
	git tag $(basename $(TAG)) # Tag the commit on master with major.minor
	git push origin $(basename $(TAG))
	# Generate yaml file for this release
	sed -i.bak "s|:latest|:$(TAG)|g" yaml/base/calico-vpp-daemonset.yaml
	sed -i.bak "s|:latest|:$(TAG)|g" yaml/components/multinet/multinet.yaml
	rm yaml/base/calico-vpp-daemonset.yaml.bak
	rm yaml/components/multinet/multinet.yaml.bak
	$(MAKE) -C yaml
	git checkout -b release/$(TAG)
	git add yaml
	git commit -sm "Release $(TAG)"
	# Tag release and push it
	git tag $(TAG)
	git push --set-upstream origin release/$(TAG)
	git push origin $(TAG)
	@echo
	@echo "***IMPORTANT***IMPORTANT***IMPORTANT***IMPORTANT***"
	@echo "In the tigera docs repo (https://github.com/tigera/docs), identify the directory for Calico version ${CALICO_TAG}"
	@echo "and update the \"vppbranch\" variable to ${TAG} in the \"variables.js\" file in that directory. For example, for"
	@echo "Calico version \"v3.27.0\", the directory would be \"calico_versioned_docs/version-3.27\". If this is not done,"
	@echo "the install docs get broken!!"

.PHONY: test-memif-multinet
test-memif-multinet:
	kubectl apply -f test/yaml/multinet/network.yaml
	kubectl apply -f test/yaml/multinet/netdefinitions.yaml
	kubectl apply -f test/yaml/multinet/pod-memif.yaml

.PHONY: delete-test-memif-multinet
delete-test-memif-multinet:
	kubectl delete -f test/yaml/multinet/pod-memif.yaml
	kubectl delete -f test/yaml/multinet/netdefinitions.yaml

.PHONY: install-multinet
install-multinet:
	@echo "--Installing network CRD..."
	@kubectl apply -f test/yaml/multinet/projectcalico.org_networks.yaml
	@kubectl apply -f test/yaml/multinet/whereabouts-daemonset-install.yaml
	@echo "--Installing multus daemonset..."
	@kubectl apply -f https://github.com/k8snetworkplumbingwg/multus-cni/raw/master/deployments/multus-daemonset-thick.yml
	@echo "--Installing whereabouts daemonset..."
	@kubectl apply -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_ippools.yaml
	@kubectl apply -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_overlappingrangeipreservations.yaml

.PHONY: delete-multinet
delete-multinet:
	@echo "--Deleting whereabouts daemonset..."
	@kubectl delete -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_ippools.yaml
	@kubectl delete -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_overlappingrangeipreservations.yaml
	@echo "--Deleting multus daemonset..."
	@kubectl delete -f https://github.com/k8snetworkplumbingwg/multus-cni/raw/master/deployments/multus-daemonset-thick.yml
	@echo "--Deleting network CRD..."
	@kubectl delete -f test/yaml/multinet/projectcalico.org_networks.yaml
	@kubectl delete -f test/yaml/multinet/whereabouts-daemonset-install.yaml
	@echo "--Removing pod & CNI installation..."
	@kubectl -n calico-vpp-dataplane delete deployment multinet-monitor-deployment
	@( \
	  for cid in `kubectl -n calico-vpp-dataplane get pods -o go-template --template='{{range .items}}{{printf "%s\n" .metadata.name}}{{end}}'` ;\
	  do \
		kubectl exec -it -n calico-vpp-dataplane $$cid -c vpp -- \
		  rm -rvf /host/etc/cni/net.d/multus.d \
				  /host/etc/cni/net.d/whereabouts.d \
				  /host/etc/cni/net.d/00-multus.conf ;\
	  done ;\
	)

.PHONY: lint
lint:
	gofmt -s -l . | grep -v binapi | grep -v vpp_build | diff -u /dev/null -
	test -d vpp-manager/vpp_build && touch vpp-manager/vpp_build/go.mod || true
	golangci-lint run --color=never

.PHONY: cov-html
cov-html:
	go tool covdata percent -i=.coverage/unit
	go tool covdata textfmt -i=.coverage/unit -o .coverage/profile
	go tool cover -html=.coverage/profile

.PHONY: cov
cov:
	go tool covdata percent -i=.coverage/unit
	@go tool covdata textfmt -i=.coverage/unit -o .coverage/profile
	@echo "TOTAL:"
	@go tool cover -func=.coverage/profile | tail -1 | awk '{print $$3}'

#
# Create a container image image used to build the go code.
#
# We're building a hash of that list of dependencies (Go,...). That should give us a deterministic
# version identifier for any particular list of dependencies -- if, with a future agent version,
# the dependencies change, then that hash will change. We can use that to minimize downloads
# from external sources, and maximise re-use of the "dependencies" image for as long as dependencies
# remain stable.
#

BASE_IMAGE_BUILDER = ubuntu:22.04

# Compute hash to detect any changes and rebuild/push the image
DEPEND_HASH = $(shell echo \
    "${BASE_IMAGE_BUILDER}-DOCKERFILE:$(shell md5sum \
    	$(CURDIR)/Dockerfile.depend \
    	$(CURDIR)/go.mod \
    	$(CURDIR)/go.sum \
    	| cut -f1 -d' ' \
	)" | md5sum | cut -f1 -d' ')
DEPEND_IMAGE = ${DEPEND_BASE}:${DEPEND_HASH}

ifdef CI_BUILD
PUSH_IMAGE = docker image push ${DEPEND_IMAGE}
else
PUSH_IMAGE = echo not pushing image
endif

.PHONY: builder-image
builder-image: ## Make dependencies image. (Not required normally; is implied in making any other container image).
	# Try to pull an existing dependencies image; it's OK if none exists yet.
	@echo Building depend image
	docker image pull ${DEPEND_IMAGE} || /bin/true
	docker image inspect ${DEPEND_IMAGE} >/dev/null 2>/dev/null \
		  || ( docker image build \
				-f ./Dockerfile.depend \
				--build-arg BASE_IMAGE=${BASE_IMAGE_BUILDER} \
				--tag ${DEPEND_IMAGE} \
				$(CURDIR) \
		   && ${PUSH_IMAGE} )
	docker tag ${DEPEND_IMAGE} ${DEPEND_BASE}:latest

# make test - runs the unit & VPP-integration tests
# requiring sudo, this is useful in dev as this caches go deps.
# Altought this requires go, sudo installed
.PHONY: test
test: builder-image
	@rm -rf $(shell pwd)/.coverage/unit
	@mkdir -p $(shell pwd)/.coverage/unit
	$(MAKE) -C vpp-manager image
	$(MAKE) -C vpp-manager mock-pod-image
	# we prevent parallel test execution as test infra does not currently support parallel VPPs
	sudo -E env "PATH=$$PATH" VPP_BINARY=/usr/bin/vpp \
		VPP_IMAGE=calicovpp/vpp:$(TAG) \
		go test ./... \
		-cover \
		-covermode=atomic \
		-p 1 \
		-test.v \
		-test.gocoverdir=$(shell pwd)/.coverage/unit

# make ci-test - runs the unit & VPP-integration tests
# within a container, with mounted /var/run/docker.sock
# this is portable, but lack go cache
.PHONY: ci-test
ci-test: builder-image
	@rm -rf $(shell pwd)/.coverage/unit
	@mkdir -p $(shell pwd)/.coverage/unit
	$(MAKE) -C vpp-manager image
	$(MAKE) -C vpp-manager mock-pod-image
	# we prevent parallel test execution as test infra does not currently support parallel VPPs
	docker run -t --rm \
		--privileged \
		--pid=host \
		-v /proc:/proc \
		-v $(CURDIR):/vpp-dataplane \
		-v /tmp/cni-node-tests-vpp:/tmp/cni-node-tests-vpp \
		-v /tmp/cni-pod-tests-vpp:/tmp/cni-pod-tests-vpp \
		-v /tmp/services-tests-vpp:/tmp/services-tests-vpp \
		-v /tmp/felix-tests-vpp:/tmp/felix-tests-vpp \
		-v /tmp/prometheus-tests-vpp:/tmp/prometheus-tests-vpp \
		-v /tmp/vpp-test-vpp-manager-test:/tmp/vpp-test-vpp-manager-test \
		-v /var/run/docker.sock:/var/run/docker.sock \
		--env VPP_BINARY=/usr/bin/vpp \
		--env VPP_IMAGE=calicovpp/vpp:$(TAG) \
		-w /vpp-dataplane \
		${DEPEND_IMAGE} \
		go test ./... \
			-cover \
			-covermode=atomic \
			-p 1 \
			-test.v \
			-test.gocoverdir=/vpp-dataplane/.coverage/unit

.PHONY: ci-%
ci-%: builder-image
	docker run -t --rm \
		-v $(CURDIR):/vpp-dataplane \
		${DEPEND_IMAGE} \
		make -C /vpp-dataplane $*

.PHONY: depend-image-hash
depend-image-hash:
	@echo $(DEPEND_IMAGE)

.PHONY: mdlint
mdlint:
ifdef CI_BUILD
	npm install -g markdownlint-cli
endif
	markdownlint --dot --ignore vpp-manager/vpp_build .
