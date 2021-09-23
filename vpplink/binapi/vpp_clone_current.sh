#!/bin/bash
set -e

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
CACHE_DIR=$SCRIPTDIR/.cherries-cache

function green () { printf "\e[0;32m$1\e[0m\n" >&2 ; }
function blue () { printf "\e[0;34m$1\e[0m\n" >&2 ; }
function grey () { printf "\e[0;37m$1\e[0m\n" >&2 ; }
function red () { printf "\e[0;31m$1\e[0m\n" >&2 ; }
function commit_exists () { git show $1 > /dev/null 2>&1 && echo "true" || echo "false" ; }
function commit_exists_f () { [ -f $1 ] && commit_exists $(cat $1) || echo "false" ; }

function exit_and_print_help ()
{
	msg=$1
	refs=$2
	red "${msg} failed ! Patch can be found at :"
	red "https://gerrit.fd.io/r/c/vpp/+/${refs#refs/changes/*/}"
	echo
	red "you can use 'cherry-wipe' if you fear this is a caching issue"
	exit 1
}

function git_get_commit_from_refs ()
{
	refs=$1
	mkdir -p $CACHE_DIR
	CACHE_F=$CACHE_DIR/$(echo $refs |sed s@refs/changes/@@g |sed s@/@_@g)
	if $(commit_exists_f $CACHE_F); then
		COMMIT_HASH=$(cat $CACHE_F)
		green "Using cached $COMMIT_HASH"
	else
		green "Fetching $refs"
		git fetch "https://gerrit.fd.io/r/vpp" ${refs}
		COMMIT_HASH=$(git log FETCH_HEAD -1 --pretty=%H)
	fi
	echo $COMMIT_HASH > $CACHE_F
	echo $COMMIT_HASH
}

function git_cherry_pick ()
{
	refs=$1
    blue "Cherry picking $refs..."
	COMMIT_HASH=$(git_get_commit_from_refs $refs)
	git cherry-pick $COMMIT_HASH || exit_and_print_help "Cherry pick" $refs
	git commit --amend -m "gerrit:${refs#refs/changes/*/} $(git log -1 --pretty=%B)"
}

function git_revert ()
{
	refs=$1
    blue "Reverting $refs..."
	COMMIT_HASH=$(git_get_commit_from_refs $refs)
	git revert --no-edit $COMMIT_HASH || exit_and_print_help "Revert" $refs
	git commit --amend -m "gerrit:revert:${refs#refs/changes/*/} $(git log -1 --pretty=%B)"
}

if [ -z "$1" ]; then
	echo "Missing VPP path"
	exit 1
fi

VPP_COMMIT=ef356f57b54b948d990b293514f062aebf86da72
VPP_DIR="$1"

if [ ! -d $1/.git ]; then
	rm -rf $1
	green "Cloning VPP..."
	git clone "https://gerrit.fd.io/r/vpp" $1
	cd $1
	git reset --hard ${VPP_COMMIT}
else
	cd $1
	green "Fetching most recent VPP..."
	git fetch "https://gerrit.fd.io/r/vpp"
	git reset --hard ${VPP_COMMIT}
fi

git_cherry_pick refs/changes/12/33312/4 # 33312: sr: fix srv6 definition of behavior associated to a LocalSID | https://gerrit.fd.io/r/c/vpp/+/33312
git_cherry_pick refs/changes/86/29386/9 # 29386: virtio: DRAFT: multi tx support | https://gerrit.fd.io/r/c/vpp/+/29386
git_cherry_pick refs/changes/21/31321/11 # 31321: devices: add support for pseudo header checksum | https://gerrit.fd.io/r/c/vpp/+/31321
git_cherry_pick refs/changes/69/31869/18 # 31869: gso: do not try gro on small packets | https://gerrit.fd.io/r/c/vpp/+/31869
git_cherry_pick refs/changes/82/32482/1 # 32482: virtio: compute cksums in output no offload | https://gerrit.fd.io/r/c/vpp/+/32482
git_cherry_pick refs/changes/83/32483/1 # 32483: virtio: Still init unused txq | https://gerrit.fd.io/r/c/vpp/+/32483
git_cherry_pick refs/changes/71/32871/1 # 32871: devices: Add queues params in create_if | https://gerrit.fd.io/r/c/vpp/+/32871
git_cherry_pick refs/changes/71/32271/6 # 32271: memif: add support for ns abstract sockets | https://gerrit.fd.io/r/c/vpp/+/32271
git_cherry_pick refs/changes/57/33557/1 # 33557: ip: unlock_fib on if delete | https://gerrit.fd.io/r/c/vpp/+/33557
git_cherry_pick refs/changes/94/33794/1 # 33794: tap: Fix tap create with ns | https://gerrit.fd.io/r/c/vpp/+/33794
git_cherry_pick refs/changes/93/33793/1 # 33793: wireguard: fix wg-output-tun feature configuration | https://gerrit.fd.io/r/c/vpp/+/33793

# --------------- Dedicated plugins ---------------
git_cherry_pick refs/changes/64/33264/3 # 33264: pbl: Port based balancer | https://gerrit.fd.io/r/c/vpp/+/33264
git_cherry_pick refs/changes/88/31588/1 # 31588: cnat: [WIP] no k8s maglev from pods | https://gerrit.fd.io/r/c/vpp/+/31588
git_cherry_pick refs/changes/83/28083/20 # 28083: acl: acl-plugin custom policies |  https://gerrit.fd.io/r/c/vpp/+/28083
git_cherry_pick refs/changes/13/28513/24 # 25813: capo: Calico Policies plugin | https://gerrit.fd.io/r/c/vpp/+/28513
# --------------- Dedicated plugins ---------------

