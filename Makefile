.PHONY: all build image

all: image

build:
	$(MAKE) -C calico-vpp-agent $@
	$(MAKE) -C vpp-manager $@

image:
	$(MAKE) -C calico-vpp-agent $@
	$(MAKE) -C vpp-manager $@
