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

git fetch "https://gerrit.fd.io/r/vpp" refs/changes/11/28711/4 && git cherry-pick FETCH_HEAD # vlib: force input node interrupts to be unique
git fetch "https://gerrit.fd.io/r/vpp" refs/changes/87/28587/22 && git cherry-pick FETCH_HEAD # calico plugin

git fetch "https://gerrit.fd.io/r/vpp" refs/changes/86/29386/7 && git cherry-pick FETCH_HEAD # multi TX
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
" | git apply -- && git add -A &&  git commit --author "Anonymous <>" -m "Use 10us interrupt sleep"

