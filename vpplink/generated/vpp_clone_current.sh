#!/bin/bash
set -e

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
CACHE_DIR=$SCRIPTDIR/.cherries-cache
STASH_SAVED=0

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
		blue "Using cached $COMMIT_HASH"
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
	CHANGE_ID=$(git log -1 --format=%b ${COMMIT_HASH} | grep -E 'Change-Id:' | head -1 | cut -d' ' -f2)
    blue "commmit-hash:$COMMIT_HASH"
    blue "change-id:   $CHANGE_ID"

	EXISTING_COMMIT=$(git --no-pager log --format=format:%H -1 --grep "Change-Id: $CHANGE_ID")
	if [ -z "$EXISTING_COMMIT" ]; then
		git cherry-pick $COMMIT_HASH || exit_and_print_help "Cherry pick" $refs
		git commit --amend -m "gerrit:${refs#refs/changes/*/} $(git log -1 --pretty=%B)"
		green "Did cherry pick ${refs} as $(git log -1 --pretty=%H)"
	else
		green "Not cherry pick ${refs} change-id in tree as ${EXISTING_COMMIT}"
	fi
}

function git_apply_private ()
{
	refs=$1
    blue "Applying $refs..."
    git am < $SCRIPTDIR/patches/$refs
}


function git_revert ()
{
	refs=$1
    blue "Reverting $refs..."
	COMMIT_HASH=$(git_get_commit_from_refs $refs)
	git revert --no-edit $COMMIT_HASH || exit_and_print_help "Revert" $refs
	git commit --amend -m "gerrit:revert:${refs#refs/changes/*/} $(git log -1 --pretty=%B)"
}

function git_clone_cd_and_reset ()
{
	VPP_DIR=$1
	VPP_COMMIT=$2
	if [ -z "$VPP_DIR" ]; then
		red "Please provide the VPP repository path"
		exit 1
	fi
	if [ ! -d $VPP_DIR/.git ]; then
		if [ x$VPP_DIR == x/ ]; then
			red "Beware, trying to remove '$VPP_DIR'"
			exit 1
		fi
		rm -rf $VPP_DIR
		green "Cloning VPP..."
		git clone "https://gerrit.fd.io/r/vpp" $VPP_DIR
	fi
	cd $VPP_DIR
	if ! git diff-index --quiet HEAD --; then
		echo "Saving stash"
		git stash save "HST: temp stash"
		STASH_SAVED=1
	fi
	if ! $(commit_exists $VPP_COMMIT); then
		green "Fetching most recent VPP..."
		git fetch "https://gerrit.fd.io/r/vpp"
	fi
	git reset --hard ${VPP_COMMIT}
	if [ $STASH_SAVED -eq 1 ]; then
		git stash pop
	fi
}

# --------------- Things to cherry pick ---------------

# VPP 25.06 released on 25/June/2025
BASE="${BASE:-"1573e751c5478d3914d26cdde153390967932d6b"}" # misc: VPP 25.06 Release Notes
if [ "$VPP_DIR" = "" ]; then
       VPP_DIR="$1"
fi
git_clone_cd_and_reset "$VPP_DIR" ${BASE}

git_cherry_pick refs/changes/26/34726/3 # 34726: interface: add buffer stats api | https://gerrit.fd.io/r/c/vpp/+/34726
git_cherry_pick refs/changes/43/42343/2 # 42343: vcl: LDP default to regular option | https://gerrit.fd.io/r/c/vpp/+/42343

# This is the commit which broke IPv6 from v3.28.0 onwards.
git_revert refs/changes/75/39675/5  # ip-neighbor: do not use sas to determine NS source address

# Mohsin's set of patches addressing the gso/cksum offload issue
git_cherry_pick refs/changes/84/42184/6  # interface: add a new cap for virtual interfaces
git_cherry_pick refs/changes/85/42185/6  # vnet: add assert for offload flags in debug mode
git_cherry_pick refs/changes/86/42186/6  # tap: enable IPv4 checksum offload on interface
git_cherry_pick refs/changes/19/42419/5  # dpdk: fix the outer flags
git_cherry_pick refs/changes/81/43081/2  # interface: clear flags after checksum computation
git_cherry_pick refs/changes/91/42891/5  # ip: compute checksums before fragmentation if offloaded
git_cherry_pick refs/changes/82/43082/6  # ipip: fix the offload flags
git_cherry_pick refs/changes/84/43084/3  # af_packet: conditionally set checksum offload based on TCP/UDP offload flags
git_cherry_pick refs/changes/83/43083/3  # virtio: conditionally set checksum offload based on TCP/UDP offload flags
git_cherry_pick refs/changes/25/42425/8  # interface: add support for proper checksum handling
git_cherry_pick refs/changes/36/43336/3  # gso: fix ip fragment support for gso packet

git_cherry_pick refs/changes/98/42598/12  # pg: add support for checksum offload
git_cherry_pick refs/changes/76/42876/10  # gso: add support for ipip tso for phyiscal interfaces
git_cherry_pick refs/changes/90/43690/2 # session: track app session index for cl sessions

git_cherry_pick refs/changes/07/43107/4 # 43107: vcl: fix fifo private vpp sh on migration | https://gerrit.fd.io/r/c/vpp/+/43107
git_cherry_pick refs/changes/14/43714/5 # 43714: session: fix handling of closed during migration | https://gerrit.fd.io/r/c/vpp/+/43714
git_cherry_pick refs/changes/39/43139/5 # 43139: udp: regrab connected session after transport clone | https://gerrit.fd.io/r/c/vpp/+/43139
git_cherry_pick refs/changes/23/43723/3 # 43723: session svm: fix session migrate attach data corruption | https://gerrit.fd.io/r/c/vpp/+/43723
git_cherry_pick refs/changes/50/44350/2 # 44350: vnet: fix unicast NA handling in ND proxy | https://gerrit.fd.io/r/c/vpp/+/44350
git_cherry_pick refs/changes/55/44855/6 # 44855: tap: backport VHOST_SET_FORK_FROM_OWNER support | https://gerrit.fd.io/r/c/vpp/+/44855
git_cherry_pick refs/changes/00/44900/1 # 44900: tap: backport fix promiscuous mode | https://gerrit.fd.io/r/c/vpp/+/44900

git_cherry_pick refs/changes/03/44903/1 # 44903: vxlan: reset next_dpo on delete | https://gerrit.fd.io/r/c/vpp/+/44903

# --------------- private plugins ---------------
# Generated with 'git format-patch --zero-commit -o ./patches/ HEAD^^^'
git_apply_private 0001-pbl-Port-based-balancer.patch
git_apply_private 0002-cnat-WIP-no-k8s-maglev-from-pods.patch
git_apply_private 0003-acl-acl-plugin-custom-policies.patch
git_apply_private 0004-capo-Calico-Policies-plugin.patch
