#!/bin/bash
set -e

VPP_COMMIT=af073546e1bf130089a58d9cdb8ca1da3492c933

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
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/21/31321/10 && git cherry-pick FETCH_HEAD # 31321: devices: add support for pseudo header checksum | https://gerrit.fd.io/r/c/vpp/+/31321
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/69/31869/12 && git cherry-pick FETCH_HEAD # 31869: gso: do not try gro on small packets | https://gerrit.fd.io/r/c/vpp/+/31869
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/76/32476/2 && git cherry-pick FETCH_HEAD # 32476: gso: handle push flag in gro | https://gerrit.fd.io/r/c/vpp/+/32476

git fetch "https://gerrit.fd.io/r/vpp" refs/changes/82/32482/1 && git cherry-pick FETCH_HEAD # 32482: virtio: compute cksums in output no offload | https://gerrit.fd.io/r/c/vpp/+/32482
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/83/32483/1 && git cherry-pick FETCH_HEAD # 32483: virtio: Still init unused txq | https://gerrit.fd.io/r/c/vpp/+/32483

# IPv6 ND patch (temporary)
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/68/31868/1 && git cherry-pick FETCH_HEAD # 31868: ip6-nd: silent the source and target checks on given interface | https://gerrit.fd.io/r/c/vpp/+/31868

# --------------- Cnat patches ---------------
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/88/31588/1 && git cherry-pick FETCH_HEAD # 31588: cnat: [WIP] no k8s maglev from pods | https://gerrit.fd.io/r/c/vpp/+/31588
# --------------- Cnat patches ---------------

# ------------- Policies patches -------------
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/83/28083/16 && git cherry-pick FETCH_HEAD # 28083: acl: acl-plugin custom policies |  https://gerrit.fd.io/r/c/vpp/+/28083
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/13/28513/20 && git cherry-pick FETCH_HEAD # 25813: capo: Calico Policies plugin | https://gerrit.fd.io/r/c/vpp/+/28513
# ------------- Policies patches -------------

