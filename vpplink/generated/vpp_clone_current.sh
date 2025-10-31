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
		git fetch --tags "https://gerrit.fd.io/r/vpp"
	fi
	git reset --hard ${VPP_COMMIT}
	if [ $STASH_SAVED -eq 1 ]; then
		git stash pop
	fi
}

# --------------- Things to cherry pick ---------------

# VPP 25.10 released on 29/October/2025
BASE="${BASE:-"cbba0451bb0af02a3ab8e163f6f99062782258e6"}" # misc: VPP 25.10 Release Notes
if [ "$VPP_DIR" = "" ]; then
       VPP_DIR="$1"
fi
git_clone_cd_and_reset "$VPP_DIR" ${BASE}

git_cherry_pick refs/changes/26/34726/3 # 34726: interface: add buffer stats api | https://gerrit.fd.io/r/c/vpp/+/34726
git_cherry_pick refs/changes/43/42343/2 # 42343: vcl: LDP default to regular option | https://gerrit.fd.io/r/c/vpp/+/42343

# This is the commit which broke IPv6 from v3.28.0 onwards.
git_revert refs/changes/75/39675/5  # ip-neighbor: do not use sas to determine NS source address

# npol: Network Policies plugin
git_cherry_pick refs/changes/10/43710/12 # 43710: npol: Network Policies plugin | https://gerrit.fd.io/r/c/vpp/+/43710
git_cherry_pick refs/changes/52/43952/2 # 43952: npol: fix test-debug | https://gerrit.fd.io/r/c/vpp/+/43952
# testing new cnat stuff
git_cherry_pick refs/changes/89/41089/21 # https://gerrit.fd.io/r/c/vpp/+/41089 cnat: combine multiple changes
git_cherry_pick refs/changes/69/43369/9 # https://gerrit.fd.io/r/c/vpp/+/43369 cnat: converge new cnat implementation to support encaps (calico)


# --------------- private plugins ---------------
# Generated with 'git format-patch --zero-commit -o ./patches/ HEAD^^^'
git_apply_private 0001-pbl-Port-based-balancer.patch
git_apply_private 0002-cnat-WIP-no-k8s-maglev-from-pods.patch
git_apply_private 0003-acl-acl-plugin-custom-policies.patch

