TAG ?= latest # Tag images with :$(TAG)

.PHONY: new-cluster
new-cluster:
	@./new_cluster.sh

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
