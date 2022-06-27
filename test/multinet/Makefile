.PHONY: test-memif-multinet
test-memif-multinet:
	kubectl apply -f network.yaml
	kubectl apply -f netdefinitions.yaml
	kubectl apply -f pod-memif.yaml

.PHONY: delete-test-memif-multinet
delete-test-memif-multinet:
	kubectl delete -f pod-memif.yaml
	kubectl delete -f netdefinitions.yaml

.PHONY: install
install:
	@echo "--Installing network CRD..."
	@kubectl apply -f ../../yaml/features/multinet/projectcalico.org_networks.yaml
	@kubectl apply -f ../../yaml/features/multinet/whereabouts-daemonset-install.yaml
	@echo "--Installing multus daemonset..."
	@kubectl apply -f https://github.com/k8snetworkplumbingwg/multus-cni/raw/master/deployments/multus-daemonset-thick-plugin.yml
	@echo "--Installing whereabouts daemonset..."
	@kubectl apply -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_ippools.yaml
	@kubectl apply -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_overlappingrangeipreservations.yaml
	@kubectl apply -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/ip-reconciler-job.yaml

.PHONY: delete
delete:
	@echo "--Deleting whereabouts daemonset..."
	@kubectl apply -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_ippools.yaml
	@kubectl apply -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_overlappingrangeipreservations.yaml
	@kubectl apply -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/ip-reconciler-job.yaml
	@echo "--Deleting multus daemonset..."
	@kubectl apply -f https://github.com/k8snetworkplumbingwg/multus-cni/raw/master/deployments/multus-daemonset-thick-plugin.yml
	@echo "--Deleting network CRD..."
	@kubectl apply -f ../../yaml/features/multinet/projectcalico.org_networks.yaml
	@kubectl apply -f ../../yaml/features/multinet/whereabouts-daemonset-install.yaml

