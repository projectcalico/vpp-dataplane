#!/bin/bash
VPP_COMMIT=8b4d0dd5ba8ea42063b0700f39c2165486b8c9a0

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
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/21/31321/7 && git cherry-pick FETCH_HEAD # 31321: devices: add support for pseudo header checksum | https://gerrit.fd.io/r/c/vpp/+/31321
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/88/31288/2 && git cherry-pick FETCH_HEAD # 31288: interface: Fix rxq deletion | https://gerrit.fd.io/r/c/vpp/+/31288
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/87/31287/1 && git cherry-pick FETCH_HEAD # 31287: interface: fix sh int rx | https://gerrit.fd.io/r/c/vpp/+/31287
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/49/31249/4 && git cherry-pick FETCH_HEAD # 31249: dpdk: implement interrupt mode | https://gerrit.fd.io/r/c/vpp/+/31249

# --------------- Cnat patches ---------------
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/46/31446/2 && git cherry-pick FETCH_HEAD # 31446: cnat: fixes & prepare maglev | https://gerrit.fd.io/r/c/vpp/+/31446
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/25/30925/4 && git cherry-pick FETCH_HEAD # 30925: cnat: Add maglev support | https://gerrit.fd.io/r/c/vpp/+/30925
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/75/30275/15 && git cherry-pick FETCH_HEAD # 30275: cnat: add input feature node | https://gerrit.fd.io/r/c/vpp/+/30275
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/47/31447/3 && git cherry-pick FETCH_HEAD # 31447: cnat: Prepare extended snat policies | https://gerrit.fd.io/r/c/vpp/+/31447
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/87/28587/34 && git cherry-pick FETCH_HEAD # 28587: cnat: Add calico/k8s src policy | https://gerrit.fd.io/r/c/vpp/+/28587
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/49/31449/1 && git cherry-pick FETCH_HEAD # 31449: cnat: fix cnat feature partial cksum | https://gerrit.fd.io/r/c/vpp/+/31449
# --------------- Cnat patches ---------------

# ------------- Policies patches -------------
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/83/28083/16 && git cherry-pick FETCH_HEAD # 28083: acl: acl-plugin custom policies |  https://gerrit.fd.io/r/c/vpp/+/28083
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/13/28513/19 && git cherry-pick FETCH_HEAD # 25813: capo: Calico Policies plugin | https://gerrit.fd.io/r/c/vpp/+/28513
# ------------- Policies patches -------------
