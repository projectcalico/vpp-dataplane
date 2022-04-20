.PHONY: install-multus
install-multus:
	kubectl apply -f https://github.com/k8snetworkplumbingwg/multus-cni/raw/master/deployments/multus-daemonset.yml

test-memif-multinet:
	kubectl apply -f network.yaml
	kubectl apply -f netdefinitions.yaml
	kubectl apply -f pod-memif.yaml

delete-test-memif-multinet:
	kubectl delete -f pod-memif.yaml
	kubectl delete -f netdefinitions.yaml