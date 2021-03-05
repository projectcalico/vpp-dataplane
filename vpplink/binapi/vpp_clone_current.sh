#!/bin/bash
VPP_COMMIT=9cc765559c39a299bdb55f3f7279abbcbe00a556

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
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/49/31249/4 && git cherry-pick FETCH_HEAD # 31249: dpdk: implement interrupt mode | https://gerrit.fd.io/r/c/vpp/+/31249

# --------------- Cnat patches ---------------
# git fetch "https://gerrit.fd.io/r/vpp" refs/changes/67/31467/2 && git cherry-pick FETCH_HEAD # 31467: cnat: Fix snat with dhcp | https://gerrit.fd.io/r/c/vpp/+/31467
# git fetch "https://gerrit.fd.io/r/vpp" refs/changes/47/31447/8 && git cherry-pick FETCH_HEAD # 31447: cnat: Prepare extended snat policies | https://gerrit.fd.io/r/c/vpp/+/31447
# git fetch "https://gerrit.fd.io/r/vpp" refs/changes/87/28587/38 && git cherry-pick FETCH_HEAD # 28587: cnat: Add calico/k8s src policy | https://gerrit.fd.io/r/c/vpp/+/28587
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/51/31551/1 && git cherry-pick FETCH_HEAD # 31551: cnat: maglev fixes | https://gerrit.fd.io/r/c/vpp/+/31551
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/49/31449/4 && git cherry-pick FETCH_HEAD # 31449: cnat: fix cnat feature partial cksum | https://gerrit.fd.io/r/c/vpp/+/31449
# --------------- Cnat patches ---------------

# ------------- Policies patches -------------
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/83/28083/16 && git cherry-pick FETCH_HEAD # 28083: acl: acl-plugin custom policies |  https://gerrit.fd.io/r/c/vpp/+/28083
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/13/28513/19 && git cherry-pick FETCH_HEAD # 25813: capo: Calico Policies plugin | https://gerrit.fd.io/r/c/vpp/+/28513
# ------------- Policies patches -------------
