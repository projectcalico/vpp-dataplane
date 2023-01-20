
TAG ?= prerelease
CALICO_TAG ?= master

.PHONY: build
build: clean
	@kubectl kustomize overlays/multinet       > generated/calico-vpp-multinet.yaml
	@kubectl kustomize overlays/default-huge   > generated/calico-vpp.yaml
	@kubectl kustomize base                    > generated/calico-vpp-nohuge.yaml
	@kubectl kustomize overlays/dpdk           > generated/calico-vpp-dpdk.yaml
	@kubectl kustomize overlays/eks            > generated/calico-vpp-eks.yaml
	@kubectl kustomize overlays/eks-dpdk       > generated/calico-vpp-eks-dpdk.yaml
	@kubectl kustomize overlays/kind           > generated/calico-vpp-kind.yaml
	@sed -i.bak "s|:latest|:$(TAG)|g" generated/*.yaml
	@rm -f generated/*.yaml.bak
	@sed -i.bak "s|:master|:$(CALICO_TAG)|g" generated/*.yaml
	@rm -f generated/*.yaml.bak

.PHONY: clean
clean:
	@rm -f generated/*.yaml
