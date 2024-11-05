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
	if ! $(commit_exists $VPP_COMMIT); then
		green "Fetching most recent VPP..."
		git fetch "https://gerrit.fd.io/r/vpp"
	fi
	git reset --hard ${VPP_COMMIT}
}

# --------------- Things to cherry pick ---------------

# VPP 24.10 released on 30/Oct/2024
git_clone_cd_and_reset "$1" cfa0953251cbab435307baf3dcd249fd95afaf1f # misc: VPP 24.10 Release Notes

git_cherry_pick refs/changes/26/34726/3 # 34726: interface: add buffer stats api | https://gerrit.fd.io/r/c/vpp/+/34726

# This is the commit which broke IPv6 from v3.28.0 onwards.
git_revert refs/changes/75/39675/5  # ip-neighbor: do not use sas to determine NS source address


# --------------- private plugins ---------------
# Generated with 'git format-patch --zero-commit -o ./patches/ HEAD^^^'
git_apply_private 0001-pbl-Port-based-balancer.patch
git_apply_private 0002-cnat-WIP-no-k8s-maglev-from-pods.patch
git_apply_private 0003-acl-acl-plugin-custom-policies.patch
git_apply_private 0004-capo-Calico-Policies-plugin.patch
git_apply_private 0005-partial-revert-arthur-gso.patch
