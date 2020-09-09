#!/bin/bash
VPP_COMMIT=f30e07e3b

if [ ! -d $1 ]; then
	git clone "https://gerrit.fd.io/r/vpp" $1
	cd $1
	git reset --hard ${VPP_COMMIT}
else
	cd $1
	git fetch "https://gerrit.fd.io/r/vpp" && git reset --hard ${VPP_COMMIT}
fi

git fetch "https://gerrit.fd.io/r/vpp" refs/changes/06/29206/2 && git cherry-pick FETCH_HEAD # 29206: ip: Fix unformat_ip_prefix
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/11/28711/3 && git cherry-pick FETCH_HEAD # vlib: force input node interrupts to be unique
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/87/28587/18 && git cherry-pick FETCH_HEAD # calico plugin
# Policies
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/83/28083/9 && git cherry-pick FETCH_HEAD # ACL custom policies
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/13/28513/7 && git cherry-pick FETCH_HEAD # Calico policies

