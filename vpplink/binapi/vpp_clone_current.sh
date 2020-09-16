#!/bin/bash
VPP_COMMIT=8fb4d10dc

if [ ! -d $1 ]; then
	git clone "https://gerrit.fd.io/r/vpp" $1
	cd $1
	git reset --hard ${VPP_COMMIT}
else
	cd $1
	git fetch "https://gerrit.fd.io/r/vpp" && git reset --hard ${VPP_COMMIT}
fi

git fetch "https://gerrit.fd.io/r/vpp" refs/changes/43/28743/2 && git cherry-pick FETCH_HEAD # icmp errors
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/88/28788/2 && git cherry-pick FETCH_HEAD # icmp echo
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/92/28792/1 && git cherry-pick FETCH_HEAD # source policy
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/87/28587/16 && git cherry-pick FETCH_HEAD # calico plugin
