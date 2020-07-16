.PHONY: all build image install-test-deps start-test-cluster load-images test-install-calicovpp

all: image

build:
	$(MAKE) -C calico-vpp-agent $@
	$(MAKE) -C vpp-manager $@

image:
	$(MAKE) -C calico-vpp-agent $@
	$(MAKE) -C vpp-manager $@

install-test-deps:
	sudo apt-get update
	sudo apt-get install -y nfs-kernel-server qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils qemu ebtables dnsmasq-base libxslt-dev libxml2-dev libvirt-dev zlib1g-dev ruby-dev build-essential
	sudo adduser `id -un` libvirt
	sudo adduser `id -un` kvm
	wget https://releases.hashicorp.com/vagrant/2.2.9/vagrant_2.2.9_x86_64.deb
	sudo dpkg -i vagrant_2.2.9_x86_64.deb
	rm vagrant_2.2.9_x86_64.deb
	vagrant plugin install vagrant-libvirt
	
start-test-cluster:
	$(MAKE) -C test/vagrant up

load-images:
	$(MAKE) -C test/vagrant load-image -j3 IMG=calicovpp/node:latest
	$(MAKE) -C test/vagrant load-image -j3 IMG=calicovpp/vpp:latest

test-install-calicovpp:
	kubectl apply -f test/yaml/calico-crd.yaml
	kubectl apply -f test/yaml/calico-vpp-test.yaml
