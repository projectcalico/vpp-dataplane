include ../../common.mk

TAG ?= latest # Tag images with :$(TAG)
N_KIND_WORKERS ?= 2
N_KIND_CONTROL_PLANES ?= 1
CPU_PINNING ?= false
KIND_CALICO_VERSION ?= master
DEBUG ?= false
TIGERA_OPERATOR_VERSION ?= v3.29.0

.PHONY: new-cluster
new-cluster:
	@N_KIND_WORKERS=$(N_KIND_WORKERS) \
		N_KIND_CONTROL_PLANES=$(N_KIND_CONTROL_PLANES) \
		CPU_PINNING=$(CPU_PINNING) \
		CLUSTER_NAME=$(CLUSTER_NAME) \
		./new_cluster.sh
	mkdir -p $(HOME)/.kube
	kind get kubeconfig --name $(CLUSTER_NAME) > $(HOME)/.kube/config

.PHONY: install-cni
install-cni:
	@TAG=${TAG} DEBUG=${DEBUG} TIGERA_OPERATOR_VERSION=${TIGERA_OPERATOR_VERSION} ./install_calico_vpp.sh

.PHONY: rm-cluster
rm-cluster:
	kind delete cluster --name $(CLUSTER_NAME)

.PHONY: dev
dev:
	docker image tag calicovpp/vpp:$(TAG) localhost:5000/calicovpp/vpp:master
	docker push localhost:5000/calicovpp/vpp:master
	docker image tag calicovpp/agent:$(TAG) localhost:5000/calicovpp/agent:master
	docker push localhost:5000/calicovpp/agent:master
	docker image tag calicovpp/multinet-monitor:$(TAG) localhost:5000/calicovpp/multinet-monitor:master
	docker push localhost:5000/calicovpp/multinet-monitor:master

# this is for a cluster using a mirror docker.io -> localhost:5000 to avoid pull rate limit
.PHONY: load-mirror
load-mirror:
	@for x in node cni csi node-driver-registrar pod2daemon-flexvol ; do \
		docker pull docker.io/calico/$$x:$(KIND_CALICO_VERSION) ; \
		docker image tag calico/$$x:$(KIND_CALICO_VERSION) localhost:5000/calico/$$x:$(KIND_CALICO_VERSION) ; \
		docker push localhost:5000/calico/$$x:$(KIND_CALICO_VERSION) ; \
	done

# this is for saving manually images after one pull to avoid pull rate limit
.PHONY: load
load:
	mkdir -p $(shell pwd)/.imagecache/images
	@for x in node cni csi node-driver-registrar pod2daemon-flexvol ; do \
		docker pull docker.io/calico/$$x:$(KIND_CALICO_VERSION) ; \
		docker save docker.io/calico/$$x:$(KIND_CALICO_VERSION) -o $(shell pwd)/.imagecache/images/$$x ; \
		for nodename in $$(kubectl get node | grep kind | awk '{print $$1 }') ; do \
			docker cp $(shell pwd)/.imagecache/images/$$x $$nodename:/ ; \
			docker exec -it $$nodename ctr -n=k8s.io image import $$x ; \
		done ; \
	done


# this is for using localhost images and tagging them as docker.io images to avoid pull rate limit
.PHONY: load-tag
load-tag:
	@for x in node cni csi node-driver-registrar pod2daemon-flexvol ; do \
		for nodename in $$(kubectl get node | grep kind | awk '{print $$1 }') ; do \
			docker exec -it $$nodename ctr -n k8s.io images delete docker.io/calico/$$x:$(KIND_CALICO_VERSION) ; \
			docker exec -it $$nodename crictl pull localhost:5000/calico/$$x:$(KIND_CALICO_VERSION) ; \
			docker exec -it $$nodename ctr -n k8s.io images tag localhost:5000/calico/$$x:$(KIND_CALICO_VERSION) docker.io/calico/$$x:$(KIND_CALICO_VERSION) ; \
		done ; \
	done
