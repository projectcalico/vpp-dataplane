
TAG ?= v3.26.0
CALICO_TAG ?= v3.26.0

.PHONY: build
build: clean
	kubectl kustomize base                                     > generated/calico-vpp-nohuge.yaml
	kubectl kustomize overlays/default-huge                    > generated/calico-vpp.yaml
	kubectl kustomize overlays/default-multinet                > generated/calico-vpp-multinet.yaml
	kubectl kustomize overlays/dpdk                            > generated/calico-vpp-dpdk.yaml
	kubectl kustomize overlays/eks                             > generated/calico-vpp-eks.yaml
	kubectl kustomize overlays/eks-dpdk                        > generated/calico-vpp-eks-dpdk.yaml
	kubectl kustomize overlays/kind                            > generated/calico-vpp-kind.yaml
	kubectl kustomize overlays/kind-multinet                   > generated/calico-vpp-kind-multinet.yaml
	# Do not export the test-* overlays, but still check they compile
	kubectl kustomize overlays/test-vagrant                    > /dev/null
	kubectl kustomize overlays/test-vagrant-mounts             > /dev/null
	kubectl kustomize overlays/test-vagrant-mounts-flat        > /dev/null
	kubectl kustomize overlays/test-vagrant-multinet-mounts    > /dev/null
	kubectl kustomize overlays/test-vagrant-srv6               > /dev/null
	kubectl kustomize overlays/test-vagrant-srv6-mounts        > /dev/null
	kubectl kustomize overlays/test-vagrant-v6                 > /dev/null
	kubectl kustomize overlays/test-vagrant-v6-mounts          > /dev/null
	@sed -i.bak "s|:latest|:$(TAG)|g" generated/*.yaml
	@rm -f generated/*.yaml.bak
	@sed -i.bak "s|:master|:$(CALICO_TAG)|g" generated/*.yaml
	@rm -f generated/*.yaml.bak

.PHONY: clean
clean:
	@rm -f generated/*.yaml
