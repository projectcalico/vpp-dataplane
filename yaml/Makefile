
.PHONY: build
build: clean
	@kubectl kustomize overlays/default-huge   > generated/calico-vpp.yaml
	@kubectl kustomize overlays/default-nohuge > generated/calico-vpp-nohuge.yaml
	@kubectl kustomize overlays/dpdk           > generated/calico-vpp-dpdk.yaml
	@kubectl kustomize overlays/ipsec          > generated/calico-vpp-ipsec.yaml

.PHONY: clean
clean:
	@rm -f generated/*.yaml
