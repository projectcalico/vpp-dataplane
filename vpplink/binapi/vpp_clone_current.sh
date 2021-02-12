#!/bin/bash
VPP_COMMIT=fb0afab7f

if [ ! -d $1/.git ]; then
	rm -rf $1
	git clone "https://gerrit.fd.io/r/vpp" $1
	cd $1
	git reset --hard ${VPP_COMMIT}
else
	cd $1
	git fetch "https://gerrit.fd.io/r/vpp" && git reset --hard ${VPP_COMMIT}
fi

git fetch "https://gerrit.fd.io/r/vpp" refs/changes/86/29386/9 && git cherry-pick FETCH_HEAD # 29386: virtio: DRAFT: multi tx support | https://gerrit.fd.io/r/c/vpp/+/29386
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/18/31118/1 && git cherry-pick FETCH_HEAD # 31118: interface: Add promisc on/off in api | https://gerrit.fd.io/r/c/vpp/+/31118

# --------------- Cnat patches ---------------
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/75/30275/11 && git cherry-pick FETCH_HEAD # 30275: cnat: add input feature node | https://gerrit.fd.io/r/c/vpp/+/30275
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/87/28587/32 && git cherry-pick FETCH_HEAD # 28587: cnat: k8s extensions
# --------------- Cnat patches ---------------

# ------------- Policies patches -------------
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/83/28083/15 && git cherry-pick FETCH_HEAD # 28083: acl: acl-plugin custom policies |  https://gerrit.fd.io/r/c/vpp/+/28083
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/13/28513/18 && git cherry-pick FETCH_HEAD # 25813: capo: Calico Policies plugin | https://gerrit.fd.io/r/c/vpp/+/28513
# ------------- Policies patches -------------