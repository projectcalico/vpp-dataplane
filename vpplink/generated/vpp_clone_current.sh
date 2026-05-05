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

function copy_private_plugin ()
{
	name=$1
	blue "Copying private plugin $name..."
	rm -rf "src/plugins/$name"
	cp -r "$SCRIPTDIR/private_plugins/$name" "src/plugins/$name"
	git add "src/plugins/$name"
	git commit -m "calicovpp plugin:$name"
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
		git fetch --tags "https://gerrit.fd.io/r/vpp"
	fi
	git reset --hard ${VPP_COMMIT}
	# Remove plugins copied with copy_private_plugin
	git clean -fd src/plugins/
}

# --------------- Things to cherry pick ---------------

#
BASE="${BASE:-"2ddeeeacbd43de97ff304689ea6de7b9f7cc8ecd"}"
if [ "$VPP_DIR" = "" ]; then
       VPP_DIR="$1"
fi
git_clone_cd_and_reset "$VPP_DIR" ${BASE}

git_cherry_pick refs/changes/43/42343/2 # 42343: vcl: LDP default to regular option | https://gerrit.fd.io/r/c/vpp/+/42343

# IPv6 related fixes:
git_cherry_pick refs/changes/50/44350/3 # 44350: vnet: fix unicast NA handling in ND proxy | https://gerrit.fd.io/r/c/vpp/+/44350
git_cherry_pick refs/changes/03/44903/1 # 44903: vxlan: reset next_dpo on delete | https://gerrit.fd.io/r/c/vpp/+/44903
git_cherry_pick refs/changes/99/45099/2 # 45099: ip6-nd: add nd-proxy all dst | https://gerrit.fd.io/r/c/vpp/+/45099
git_cherry_pick refs/changes/46/45046/4 # 45046: ip6-nd: add punt reason for neigh advs | https://gerrit.fd.io/r/c/vpp/+/45046

# --------------- private patches/plugins ---------------
# Patch files generated with 'git format-patch --zero-commit -o ./patches/ HEAD^^^^'
git_apply_private 0001-cnat-WIP-no-k8s-maglev-from-pods.patch
git_apply_private 0002-ip-neighbor-preserve-interface-LL-receive-DPO-for-se.patch
# VPP Private plugins:
copy_private_plugin ip_ttl_fixup
copy_private_plugin pbl
