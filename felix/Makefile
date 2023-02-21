
.PHONY: fv
fv:
	cd calico/felix && make fv-no-prereqs

.PHONY: fv-prereqs
fv-prereqs:
	sudo mkdir -p /var/run/calico
	git clone https://github.com/calico-vpp/calico 2> /dev/null || echo
	(cd calico/ ; git checkout origin/feature/wip-fv-tests-vpp)
	cd calico/felix &&  make fv-prereqs
