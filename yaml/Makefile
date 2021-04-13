
.PHONY: build
build: clean
	@kubectl kustomize overlays/default-huge   > generated/calico-vpp.yaml
	@kubectl kustomize base                    > generated/calico-vpp-nohuge.yaml
	@kubectl kustomize overlays/dpdk           > generated/calico-vpp-dpdk.yaml
	@kubectl kustomize overlays/eks            > generated/calico-vpp-eks.yaml
	@kubectl kustomize overlays/eks-dpdk       > generated/calico-vpp-eks-dpdk.yaml
ifneq ($(strip $(TAG)),)
	@sed -i.bak "s|:latest|:$(TAG)|g" generated/*.yaml
	@rm -f generated/*.yaml.bak
endif

.PHONY: clean
clean:
	@rm -f generated/*.yaml
