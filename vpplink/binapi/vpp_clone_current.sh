#!/bin/bash
set -e

function git_cherry_pick ()
{
	refs=$1
	git fetch "https://gerrit.fd.io/r/vpp" ${refs}
	git cherry-pick FETCH_HEAD
	git commit --amend -m "gerrit:${refs#refs/changes/*/} $(git log -1 --pretty=%B)"
}


VPP_COMMIT=e631ece4aa32b33651ed458200ab551ffb8fbb47

if [ ! -d $1/.git ]; then
	rm -rf $1
	git clone "https://gerrit.fd.io/r/vpp" $1
	cd $1
	git reset --hard ${VPP_COMMIT}
else
	cd $1
	git fetch "https://gerrit.fd.io/r/vpp" && git reset --hard ${VPP_COMMIT}
fi

git_cherry_pick refs/changes/86/29386/9 # 29386: virtio: DRAFT: multi tx support | https://gerrit.fd.io/r/c/vpp/+/29386
git_cherry_pick refs/changes/21/31321/10 # 31321: devices: add support for pseudo header checksum | https://gerrit.fd.io/r/c/vpp/+/31321
git_cherry_pick refs/changes/69/31869/12 # 31869: gso: do not try gro on small packets | https://gerrit.fd.io/r/c/vpp/+/31869
git_cherry_pick refs/changes/76/32476/2 # 32476: gso: handle push flag in gro | https://gerrit.fd.io/r/c/vpp/+/32476

git_cherry_pick refs/changes/82/32482/1 # 32482: virtio: compute cksums in output no offload | https://gerrit.fd.io/r/c/vpp/+/32482
git_cherry_pick refs/changes/83/32483/1 # 32483: virtio: Still init unused txq | https://gerrit.fd.io/r/c/vpp/+/32483

# IPv6 ND patch (temporary)
git_cherry_pick refs/changes/68/31868/1 # 31868: ip6-nd: silent the source and target checks on given interface | https://gerrit.fd.io/r/c/vpp/+/31868

# --------------- Cnat patches ---------------
git_cherry_pick refs/changes/88/31588/1 # 31588: cnat: [WIP] no k8s maglev from pods | https://gerrit.fd.io/r/c/vpp/+/31588
git_cherry_pick refs/changes/71/32571/1 # 32571: cnat: fix spinlock | https://gerrit.fd.io/r/c/vpp/+/32571
# --------------- Cnat patches ---------------

# ------------- Policies patches -------------
git_cherry_pick refs/changes/83/28083/16 # 28083: acl: acl-plugin custom policies |  https://gerrit.fd.io/r/c/vpp/+/28083
git_cherry_pick refs/changes/13/28513/20 # 25813: capo: Calico Policies plugin | https://gerrit.fd.io/r/c/vpp/+/28513
# ------------- Policies patches -------------

