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

.PHONY: install-test-deps
install-test-deps:
	sudo apt-get update
	sudo apt-get install -y jq nfs-kernel-server qemu-kvm libvirt-daemon-system \
		libvirt-clients bridge-utils qemu ebtables dnsmasq-base libxslt-dev \
		libxml2-dev libvirt-dev zlib1g-dev ruby-dev build-essential
	sudo adduser `id -un` libvirt
	sudo adduser `id -un` kvm
	newgrp libvirt
	wget https://releases.hashicorp.com/vagrant/2.2.9/vagrant_2.2.9_x86_64.deb
	sudo dpkg -i vagrant_2.2.9_x86_64.deb
	rm vagrant_2.2.9_x86_64.deb
	vagrant plugin install vagrant-libvirt

.PHONY: start-test-cluster
start-test-cluster:
	$(MAKE) -C test/vagrant up

.PHONY: load-images
load-images:
	$(MAKE) -C test/vagrant load-image -j3 IMG=calicovpp/node:latest
	$(MAKE) -C test/vagrant load-image -j3 IMG=calicovpp/vpp:latest

# Allows to simply run calico-vpp from release images in a test cluster
.PHONY: test-install-calicovpp
test-install-calicovpp:
	kubectl kustomize yaml/overlays/test-vagrant | kubectl apply -f -

# Allows to run calico-vpp in a test cluster with locally-built binaries for dev / debug
.PHONY: test-install-calicovpp-dev
test-install-calicovpp-dev:
	kubectl kustomize yaml/overlays/test-vagrant-mounts | kubectl apply -f -

.PHONY: run-tests
run-tests:
	test/scripts/test.sh up iperf
	kubectl -n iperf wait pod/iperf-client --for=condition=Ready --timeout=30s
	test/scripts/cases.sh ipv4
	test/scripts/test.sh down iperf

.PHONY: restart-calicovpp
restart-calicovpp:
	kubectl rollout restart ds/calico-vpp-node
	kubectl rollout status ds/calico-vpp-node
	kubectl rollout restart deployment/coredns
	kubectl rollout status deployment/coredns

.PHONY: goapi
goapi:
	@./vpplink/binapi/generate_binapi.sh

.PHONY: release
# TAG must be set to something like v0.6.0-calicov3.9.1
release: check-TAG push
	@[ -z "$(shell git status --porcelain)" ] || (echo "Repo is not clean! Aborting." && exit 1)
	# Generate yaml file for this release
	sed -i.bak "s|:latest|:$(TAG)|g" yaml/base/calico-vpp.yaml
	rm yaml/base/calico-vpp.yaml.bak
	kubectl kustomize yaml/base > yaml/generated/calico-base-latest.yaml
	git checkout -b release/$(TAG)
	git add yaml
	git commit -sm "Release $(TAG)"	
	# Tag release and push it
	git tag $(TAG)
	git push --set-upstream origin release/$(TAG)
	git push origin $(TAG)
