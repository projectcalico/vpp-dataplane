include .ci/common.mk

check-%:
	@: $(if $(value $*),,$(error $* is undefined))

.PHONY: build
build:
	$(MAKE) -C calico-vpp-agent $@
	$(MAKE) -C vpp-manager $@
	$(MAKE) -C multinet-monitor $@

.PHONY: image images
images: image
image:
	$(MAKE) -C calico-vpp-agent $@
	$(MAKE) -C vpp-manager $@
	$(MAKE) -C multinet-monitor $@

.PHONY: push
push:
	$(MAKE) -C calico-vpp-agent $@
	$(MAKE) -C vpp-manager $@
	$(MAKE) -C multinet-monitor $@

.PHONY: dev
dev:
	$(MAKE) -C calico-vpp-agent ALSO_LATEST=y $@
	$(MAKE) -C vpp-manager ALSO_LATEST=y $@
	$(MAKE) -C multinet-monitor ALSO_LATEST=y $@

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

.PHONY: kind-new-cluster
kind-new-cluster:
	make -C test/kind new-cluster

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
	@echo "Cherry pick VPP ?"
	@echo "This will reset current branch"
	@echo "directory : ${VPP_DIR}"
	@echo "branch    : $(shell cd ${VPP_DIR} && git branch --show-current)"
	@echo "Are you sure? [y/N] " && read ans && [ $${ans:-N} = y ]
	@bash ./vpplink/generated/vpp_clone_current.sh ${VPP_DIR}
	@make goapi

.PHONY: cherry-wipe
cherry-wipe:
	rm -rf ./vpplink/binapi/.cherries-cache

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
	rm yaml/base/calico-vpp-daemonset.yaml.bak
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

.PHONY: run-integration-tests
run-integration-tests:
	$(MAKE) -C test/integration-tests $@

.PHONY: test
test: go-lint
	gofmt -s -l . | grep -v generated | grep -v vpp_build | diff -u /dev/null -
	go test ./...

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


.PHONY: go-check
go-check: go-lint
	gofmt -s -l . | grep -v binapi | grep -v vpp_build | diff -u /dev/null -
	go test ./...

.PHONY: go-lint
go-lint:
	golangci-lint run --color=never

.PHONY: go-lint-fix
go-lint-fix:
	golangci-lint run --fix
