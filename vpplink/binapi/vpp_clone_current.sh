#!/bin/bash
set -e

function git_cherry_pick ()
{
	refs=$1
	git fetch "https://gerrit.fd.io/r/vpp" ${refs}
	git cherry-pick FETCH_HEAD
	git commit --amend -m "gerrit:${refs#refs/changes/*/} $(git log -1 --pretty=%B)"
}

if [ -z "$1" ]; then
	echo "Missing VPP path"
	exit 1
fi

VPP_COMMIT=078d258034cef5b4ca74d9deb37b2684cc77d060
VPP_DIR="$1"

if [ ! -d $1/.git ]; then
	rm -rf $1
	git clone "https://gerrit.fd.io/r/vpp" $1
	cd $1
	git reset --hard ${VPP_COMMIT}
else
	cd $1
	git fetch "https://gerrit.fd.io/r/vpp" && git reset --hard ${VPP_COMMIT}
fi

git_cherry_pick refs/changes/68/32468/3 # 32468: buffers: fix buffer linearization | https://gerrit.fd.io/r/c/vpp/+/32468
git_cherry_pick refs/changes/33/32833/1 # 32833: ipsec: disable linearization | https://gerrit.fd.io/r/c/vpp/+/32833
git_cherry_pick refs/changes/86/29386/9 # 29386: virtio: DRAFT: multi tx support | https://gerrit.fd.io/r/c/vpp/+/29386
git_cherry_pick refs/changes/21/31321/11 # 31321: devices: add support for pseudo header checksum | https://gerrit.fd.io/r/c/vpp/+/31321

# Revert for now
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/68/32568/6 && git revert --no-edit FETCH_HEAD
git_cherry_pick refs/changes/69/31869/13 # 31869: gso: do not try gro on small packets | https://gerrit.fd.io/r/c/vpp/+/31869
git_cherry_pick refs/changes/76/32476/3 # 32476: gso: handle push flag in gro | https://gerrit.fd.io/r/c/vpp/+/32476
git_cherry_pick refs/changes/82/32482/1 # 32482: virtio: compute cksums in output no offload | https://gerrit.fd.io/r/c/vpp/+/32482
git_cherry_pick refs/changes/83/32483/1 # 32483: virtio: Still init unused txq | https://gerrit.fd.io/r/c/vpp/+/32483
git_cherry_pick refs/changes/71/32871/1 # 32871: devices: Add queues params in create_if | https://gerrit.fd.io/r/c/vpp/+/32871
git_cherry_pick refs/changes/71/32271/6 # 32271: memif: add support for ns abstract sockets | https://gerrit.fd.io/r/c/vpp/+/32271
git_cherry_pick refs/changes/21/31921/8 # 31921: ip6-nd: add ip6-nd proxy | https://gerrit.fd.io/r/c/vpp/+/31921
git_cherry_pick refs/changes/64/33164/3  # 33164: dpdk: enable ena interrupt support in dpdk version 21.05 | https://gerrit.fd.io/r/c/vpp/+/33164

git_cherry_pick refs/changes/01/33301/2 # 33301: session: make netns abtract name static | https://gerrit.fd.io/r/c/vpp/+/33301
git_cherry_pick refs/changes/51/33451/3 # 33451: ip: punt redirect add nh in api | https://gerrit.fd.io/r/c/vpp/+/33451
git_cherry_pick refs/changes/01/33501/4 # 33501: interface: fix init fib_index_by_sw_if_index | https://gerrit.fd.io/r/c/vpp/+/33501
git_cherry_pick refs/changes/04/33504/2 # 33504: ip: show ip table CLI | https://gerrit.fd.io/r/c/vpp/+/33504
git_cherry_pick refs/changes/57/33557/1 # 33557: ip: unlock_fib on if delete | https://gerrit.fd.io/r/c/vpp/+/33557

# --------------- Dedicated plugins ---------------
git_cherry_pick refs/changes/64/33264/3 # 33264: pbl: Port based balancer | https://gerrit.fd.io/r/c/vpp/+/33264
git_cherry_pick refs/changes/88/31588/1 # 31588: cnat: [WIP] no k8s maglev from pods | https://gerrit.fd.io/r/c/vpp/+/31588
git_cherry_pick refs/changes/83/28083/20 # 28083: acl: acl-plugin custom policies |  https://gerrit.fd.io/r/c/vpp/+/28083
git_cherry_pick refs/changes/13/28513/24 # 25813: capo: Calico Policies plugin | https://gerrit.fd.io/r/c/vpp/+/28513
# --------------- Dedicated plugins ---------------

