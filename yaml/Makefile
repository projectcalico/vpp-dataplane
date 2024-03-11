
#
# The generated yaml files are consumed by CI, dev and users.
# - on the master branch of this repository TAG should be
# 'latest' as this will be used by CI/dev which consume the latest
#  master branch HEAD.
#
# - on release branches of this repository, used by the tigera docs
# TAG should the latest release tag for calicovpp images
#
TAG ?= latest

.PHONY: build
build: clean
	kubectl kustomize base                                     > generated/calico-vpp-nohuge.yaml
	kubectl kustomize overlays/default-huge                    > generated/calico-vpp.yaml
	kubectl kustomize overlays/default-multinet                > generated/calico-vpp-multinet.yaml
	kubectl kustomize overlays/dpdk                            > generated/calico-vpp-dpdk.yaml
	kubectl kustomize overlays/eks                             > generated/calico-vpp-eks.yaml
	kubectl kustomize overlays/eks-dpdk                        > generated/calico-vpp-eks-dpdk.yaml
	kubectl kustomize overlays/eks-multinet                    > generated/calico-vpp-eks-multinet.yaml
	kubectl kustomize overlays/eks-dpdk-multinet               > generated/calico-vpp-eks-dpdk-multinet.yaml
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
	@sed -i "s|:latest|:$(TAG)|g" generated/*.yaml

.PHONY: clean
clean:
	@rm -f generated/*.yaml
