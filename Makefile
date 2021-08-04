check-%:
	@: $(if $(value $*),,$(error $* is undefined))

.PHONY: build
build:
	$(MAKE) -C calico-vpp-agent $@
	$(MAKE) -C vpp-manager $@

.PHONY: image images
images: image
image:
	$(MAKE) -C calico-vpp-agent $@
	$(MAKE) -C vpp-manager $@

.PHONY: push
push:
	$(MAKE) -C calico-vpp-agent $@
	$(MAKE) -C vpp-manager $@

.PHONY: dev
dev:
	$(MAKE) -C calico-vpp-agent $@
	$(MAKE) -C vpp-manager $@

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
	wget https://releases.hashicorp.com/vagrant/2.2.14/vagrant_2.2.14_x86_64.deb
	sudo dpkg -i vagrant_2.2.14_x86_64.deb
	rm vagrant_2.2.14_x86_64.deb
	vagrant plugin install vagrant-libvirt
	newgrp libvirt

.PHONY: start-test-cluster
start-test-cluster:
	$(MAKE) -C test/vagrant up

.PHONY: load-images
load-images:
	$(MAKE) -C test/vagrant load-image -j99 IMG=calicovpp/agent:latest
	$(MAKE) -C test/vagrant load-image -j99 IMG=calicovpp/vpp:latest

# Allows to simply run calico-vpp from release images in a test cluster
.PHONY: test-install-calicovpp
test-install-calicovpp:
	kubectl apply -k yaml/overlays/test-vagrant

# Allows to simply run calico-vpp from release images in a test cluster with SRv6 configured
.PHONY: test-install-calicovpp-srv6
test-install-calicovpp-srv6:
	kubectl kustomize yaml/overlays/test-vagrant-srv6 | kubectl apply -f -

# Allows to run calico-vpp in a test cluster with locally-built binaries for dev / debug
.PHONY: test-install-calicovpp-dev
test-install-calicovpp-dev:
	kubectl apply -k yaml/overlays/test-vagrant-mounts

.PHONY: test-install-calicovpp-dev-v6
test-install-calicovpp-dev-v6:
	kubectl apply -k yaml/overlays/test-vagrant-v6-mounts

.PHONY: test-install-calicovpp-dev-srv6
test-install-calicovpp-dev-srv6:
	kubectl apply -k yaml/overlays/test-vagrant-srv6-mounts

.PHONY: run-tests
run-tests:
	test/scripts/test.sh up iperf
	kubectl -n iperf wait pod/iperf-client $$(kubectl -n iperf get pods -l 'app in (iperf-server,iperf-nodeport)' -o name) --for=condition=Ready --timeout=30s
	test/scripts/cases.sh ipv4
	test/scripts/test.sh down iperf

.PHONY: restart-calicovpp
restart-calicovpp:
	kubectl -n calico-vpp-dataplane rollout restart ds/calico-vpp-node
	kubectl -n calico-vpp-dataplane rollout status ds/calico-vpp-node

.PHONY: goapi
export VPP_DIR ?= $(shell pwd)/vpp-manager/vpp_build
goapi:
	@./vpplink/binapi/generate_binapi.sh

.PHONY: yaml
yaml:
	$(MAKE) -C yaml

.PHONY: release
# TAG must be set to something like v0.6.0-calicov3.9.1
release: check-TAG
	@[ -z "$(shell git status --porcelain)" ] || (echo "Repo is not clean! Aborting." && exit 1)
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
