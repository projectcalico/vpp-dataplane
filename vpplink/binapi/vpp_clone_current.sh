#!/bin/bash
set -e

VPP_COMMIT=cf0e257dcf3d23a3b38129e1a3375f1c38c10973

if [ ! -d $1/.git ]; then
	rm -rf $1
	git clone "https://gerrit.fd.io/r/vpp" $1
	cd $1
	git reset --hard ${VPP_COMMIT}
else
	cd $1
	git fetch "https://gerrit.fd.io/r/vpp" && git reset --hard ${VPP_COMMIT}
fi

git fetch "https://gerrit.fd.io/r/vpp" refs/changes/02/32002/1 && git cherry-pick FETCH_HEAD # 32002: ip: fix offload flags handling | https://gerrit.fd.io/r/c/vpp/+/32002
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/86/29386/9 && git cherry-pick FETCH_HEAD # 29386: virtio: DRAFT: multi tx support | https://gerrit.fd.io/r/c/vpp/+/29386
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/21/31321/7 && git cherry-pick FETCH_HEAD # 31321: devices: add support for pseudo header checksum | https://gerrit.fd.io/r/c/vpp/+/31321
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/69/31869/8 && git cherry-pick FETCH_HEAD # 31869: gso: do not try gro on small packets | https://gerrit.fd.io/r/c/vpp/+/31869
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/05/31905/1 && git cherry-pick FETCH_HEAD # 31905: vpp: Fix session flag initialization | https://gerrit.fd.io/r/c/vpp/+/31905
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/69/31969/4 && git cherry-pick FETCH_HEAD # 31969: punt: ensure ttl doesn't decrease to 0 when punting | https://gerrit.fd.io/r/c/vpp/+/31969

# IPv6 ND patch (temporary)
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/68/31868/1 && git cherry-pick FETCH_HEAD # 31868: ip6-nd: silent the source and target checks on given interface | https://gerrit.fd.io/r/c/vpp/+/31868

# --------------- Cnat patches ---------------
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/88/31588/1 && git cherry-pick FETCH_HEAD # 31588: cnat: [WIP] no k8s maglev from pods | https://gerrit.fd.io/r/c/vpp/+/31588
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/49/31449/4 && git cherry-pick FETCH_HEAD # 31449: cnat: fix cnat feature partial cksum | https://gerrit.fd.io/r/c/vpp/+/31449
# --------------- Cnat patches ---------------

# ------------- Policies patches -------------
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/83/28083/16 && git cherry-pick FETCH_HEAD # 28083: acl: acl-plugin custom policies |  https://gerrit.fd.io/r/c/vpp/+/28083
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/13/28513/20 && git cherry-pick FETCH_HEAD # 25813: capo: Calico Policies plugin | https://gerrit.fd.io/r/c/vpp/+/28513
# ------------- Policies patches -------------
