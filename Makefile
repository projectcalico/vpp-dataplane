.PHONY: all
all: image

.PHONY: build
build:
	$(MAKE) -C calico-vpp-agent $@
	$(MAKE) -C vpp-manager $@

.PHONY: image
image:
	$(MAKE) -C calico-vpp-agent $@
	$(MAKE) -C vpp-manager $@

.PHONY: install-test-deps
install-test-deps:
	sudo apt-get update
	sudo apt-get install -y jq nfs-kernel-server qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils qemu ebtables dnsmasq-base libxslt-dev libxml2-dev libvirt-dev zlib1g-dev ruby-dev build-essential
	sudo adduser `id -un` libvirt
	sudo adduser `id -un` kvm
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

.PHONY: test-install-calicovpp
test-install-calicovpp:
	kubectl apply -f test/yaml/calico-crd.yaml
	kubectl apply -f test/yaml/calico-vpp-test.yaml

.PHONY: run-tests
run-tests:
	test/scripts/test.sh up iperf
	kubectl -n iperf wait pod/iperf-client --for=condition=Ready --timeout=15s
	test/scripts/cases.sh run_ip4_iperf_tests
	test/scripts/test.sh down iperf
