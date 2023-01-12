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
	@kubectl apply -f ../../../yaml/features/multinet/projectcalico.org_networks.yaml
	@kubectl apply -f ../../../yaml/features/multinet/whereabouts-daemonset-install.yaml
	@echo "--Installing multus daemonset..."
	@kubectl apply -f https://github.com/k8snetworkplumbingwg/multus-cni/raw/master/deployments/multus-daemonset-thick.yml
	@echo "--Installing whereabouts daemonset..."
	@kubectl apply -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_ippools.yaml
	@kubectl apply -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_overlappingrangeipreservations.yaml

.PHONY: delete
delete:
	@echo "--Deleting whereabouts daemonset..."
	@kubectl delete -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_ippools.yaml
	@kubectl delete -f https://github.com/k8snetworkplumbingwg/whereabouts/raw/master/doc/crds/whereabouts.cni.cncf.io_overlappingrangeipreservations.yaml
	@echo "--Deleting multus daemonset..."
	@kubectl delete -f https://github.com/k8snetworkplumbingwg/multus-cni/raw/master/deployments/multus-daemonset-thick-plugin.yml
	@echo "--Deleting network CRD..."
	@kubectl delete -f ../../../yaml/features/multinet/projectcalico.org_networks.yaml
	@kubectl delete -f ../../../yaml/features/multinet/whereabouts-daemonset-install.yaml
	@echo "--Removing pod & CNI installation..."
	@kubectl -n calico-vpp-dataplane delete deployment multinet-monitor-deployment
	@( \
	  for cid in `kubectl -n calico-vpp-dataplane get pods -o go-template --template='{{range .items}}{{printf "%s\n" .metadata.name}}{{end}}'` ;\
	  do \
		kubectl exec -it -n calico-vpp-dataplane $$cid -c vpp -- \
		  rm -rvf /host/etc/cni/net.d/multus.d \
		          /host/etc/cni/net.d/whereabouts.d \
		          /host/etc/cni/net.d/00-multus.conf ;\
	  done ;\
	)
