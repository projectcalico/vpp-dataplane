#!/bin/bash
set -e

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

git fetch "https://gerrit.fd.io/r/vpp" refs/changes/18/31818/1 && git cherry-pick FETCH_HEAD # 31818: af_packet: use netlink to get/set mtu | https://gerrit.fd.io/r/c/vpp/+/31818
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/86/29386/9 && git cherry-pick FETCH_HEAD # 29386: virtio: DRAFT: multi tx support | https://gerrit.fd.io/r/c/vpp/+/29386
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/21/31321/7 && git cherry-pick FETCH_HEAD # 31321: devices: add support for pseudo header checksum | https://gerrit.fd.io/r/c/vpp/+/31321
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/49/31249/4 && git cherry-pick FETCH_HEAD # 31249: dpdk: implement interrupt mode | https://gerrit.fd.io/r/c/vpp/+/31249
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/69/31869/7 && git cherry-pick FETCH_HEAD # 31869: gso: fix packet length when padding is present | https://gerrit.fd.io/r/c/vpp/+/31869

# IPv6 ND patch (temporary)
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/68/31868/1 && git cherry-pick FETCH_HEAD # 31868: ip6-nd: silent the source and target checks on given interface | https://gerrit.fd.io/r/c/vpp/+/31868

# --------------- Cnat patches ---------------
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/51/31551/1 && git cherry-pick FETCH_HEAD # 31551: cnat: maglev fixes | https://gerrit.fd.io/r/c/vpp/+/31551
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/88/31588/1 && git cherry-pick FETCH_HEAD # 31588: cnat: [WIP] no k8s maglev from pods | https://gerrit.fd.io/r/c/vpp/+/31588
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/49/31449/4 && git cherry-pick FETCH_HEAD # 31449: cnat: fix cnat feature partial cksum | https://gerrit.fd.io/r/c/vpp/+/31449
# --------------- Cnat patches ---------------

# ------------- Policies patches -------------
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/83/28083/16 && git cherry-pick FETCH_HEAD # 28083: acl: acl-plugin custom policies |  https://gerrit.fd.io/r/c/vpp/+/28083
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/13/28513/19 && git cherry-pick FETCH_HEAD # 25813: capo: Calico Policies plugin | https://gerrit.fd.io/r/c/vpp/+/28513
# ------------- Policies patches -------------
