#!/bin/bash
VPP_COMMIT=5f4f2081c

if [ ! -d $1 ]; then
	git clone "https://gerrit.fd.io/r/vpp" $1
	cd $1
	git reset --hard ${VPP_COMMIT}
else
	cd $1
	git fetch "https://gerrit.fd.io/r/vpp" && git reset --hard ${VPP_COMMIT}
fi

git fetch "https://gerrit.fd.io/r/vpp" refs/changes/11/28711/4 && git cherry-pick FETCH_HEAD # 28711: vlib: force input node interrupts to be unique | https://gerrit.fd.io/r/c/vpp/+/28711

git fetch "https://gerrit.fd.io/r/vpp" refs/changes/35/29735/2 && git cherry-pick FETCH_HEAD # 29735: cnat: Fix invalid adj_index | https://gerrit.fd.io/r/c/vpp/+/29735
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/24/29724/3 && git cherry-pick FETCH_HEAD # 29724: cnat: reduce compile time | https://gerrit.fd.io/r/c/vpp/+/29724
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/04/29804/1 && git cherry-pick FETCH_HEAD # 29804: cnat: export src_policy fns | https://gerrit.fd.io/r/c/vpp/+/29804

git fetch "https://gerrit.fd.io/r/vpp" refs/changes/87/28587/23 && git cherry-pick FETCH_HEAD # 28587: calico: Add SNAT simultaneously to VIP DNAT | https://gerrit.fd.io/r/c/vpp/+/28587
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/49/29649/3 && git cherry-pick FETCH_HEAD # 29649: tap: fix the segv | https://gerrit.fd.io/r/c/vpp/+/29649
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/86/29386/7 && git cherry-pick FETCH_HEAD # 29386: virtio: DRAFT: multi tx support | https://gerrit.fd.io/r/c/vpp/+/29386

# Policies
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/83/28083/13 && git cherry-pick FETCH_HEAD # 28083: acl: acl-plugin custom policies |  https://gerrit.fd.io/r/c/vpp/+/28083
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/13/28513/13 && git cherry-pick FETCH_HEAD # 25813: capo: Calico Policies plugin | https://gerrit.fd.io/r/c/vpp/+/28513

echo "diff --git a/src/vlib/unix/input.c b/src/vlib/unix/input.c
index 7531dd197..94a2bfb12 100644
--- a/src/vlib/unix/input.c
+++ b/src/vlib/unix/input.c
@@ -245,7 +245,7 @@ linux_epoll_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
 	      {
 		/* Sleep for 100us at a time */
 		ts.tv_sec = 0;
-		ts.tv_nsec = 1000 * 100;
+		ts.tv_nsec = 1000 * 10;
 
 		while (nanosleep (&ts, &tsrem) < 0)
 		  ts = tsrem;
" | git apply -- && git add -A &&  git commit --author "Calico-vpp builder <>" -m "Use 10us interrupt sleep"
