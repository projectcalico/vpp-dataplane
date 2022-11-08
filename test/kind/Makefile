TAG ?= latest # Tag images with :$(TAG)

.PHONY: new-cluster
new-cluster:
	@./new_cluster.sh $(nodes)

.PHONY: delete-cluster
delete-cluster:
	kind delete cluster

.PHONY: dev
dev:
	docker image tag calicovpp/vpp:$(TAG) localhost:5000/calicovpp/vpp:$(TAG)
	docker push localhost:5000/calicovpp/vpp:$(TAG)
	docker image tag calicovpp/agent:$(TAG) localhost:5000/calicovpp/agent:$(TAG)
	docker push localhost:5000/calicovpp/agent:$(TAG)
	docker image tag calicovpp/multinet-monitor:$(TAG) localhost:5000/calicovpp/multinet-monitor:$(TAG)
	docker push localhost:5000/calicovpp/multinet-monitor:$(TAG)


.PHONY: load
load:
	mkdir -p $(shell pwd)/.imagecache/images
	docker pull docker.io/calico/node:master
	docker save docker.io/calico/node:master -o $(shell pwd)/.imagecache/images/node

	docker pull docker.io/calico/cni:master
	docker save docker.io/calico/cni:master -o $(shell pwd)/.imagecache/images/cni

	docker pull docker.io/calico/csi:master
	docker save docker.io/calico/csi:master -o $(shell pwd)/.imagecache/images/csi

	docker pull docker.io/calico/node-driver-registrar:master
	docker save docker.io/calico/node-driver-registrar:master -o $(shell pwd)/.imagecache/images/node-driver-registrar

	docker pull docker.io/calico/pod2daemon-flexvol:master
	docker save docker.io/calico/pod2daemon-flexvol:master -o $(shell pwd)/.imagecache/images/pod2daemon-flexvol

	for nodename in $$(kubectl get node | grep kind | awk '{print $$1 }') ; do \
		docker cp $(shell pwd)/.imagecache/images/node $$nodename:/ ; \
		docker cp $(shell pwd)/.imagecache/images/cni $$nodename:/ ; \
		docker cp $(shell pwd)/.imagecache/images/csi $$nodename:/ ; \
		docker cp $(shell pwd)/.imagecache/images/node-driver-registrar $$nodename:/ ; \
		docker cp $(shell pwd)/.imagecache/images/pod2daemon-flexvol $$nodename:/ ; \
	done

	for nodename in $$(kubectl get node | grep kind | awk '{print $$1 }') ; do \
		docker exec -it $$nodename ctr -n=k8s.io image import node ; \
		docker exec -it $$nodename ctr -n=k8s.io image import cni ; \
		docker exec -it $$nodename ctr -n=k8s.io image import csi ; \
		docker exec -it $$nodename ctr -n=k8s.io image import node-driver-registrar ; \
		docker exec -it $$nodename ctr -n=k8s.io image import pod2daemon-flexvol ; \
	done