#!/bin/bash

# Copyright (c) 2022 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

VPP_DATAPLANE_DIRECTORY=/tmp/vpp-dataplane/
REPO_URL=https://github.com/projectcalico/vpp-dataplane.git
TAG=latest
EXTRA_TAGS=prerelease

function push ()
{
	SSH_NAME=$1
	if [ x$SSH_NAME = x ]; then
		echo "missing ssh host"
		echo "please use mngmt.sh push <some ssh host to build on>"
		exit 1
	fi

	ssh $SSH_NAME /bin/bash << EOF
if [ -d $VPP_DATAPLANE_DIRECTORY ]; then
	echo "Fetching latest"
	cd $VPP_DATAPLANE_DIRECTORY
	git fetch origin -p
	git reset origin/master --hard
	git clean -fd
else
	git clone $REPO_URL $VPP_DATAPLANE_DIRECTORY
fi

make -C $VPP_DATAPLANE_DIRECTORY image TAG=$TAG

echo "built calicovpp/vpp:${TAG}"
echo "built calicovpp/agent:${TAG}"
for tagname in $(echo $EXTRA_TAGS | sed 's/,/ /g'); do
	echo "Tagging calicovpp/vpp:\${tagname}..."
	docker tag calicovpp/vpp:${TAG} calicovpp/vpp:\${tagname}
	echo "Tagging calicovpp/agent:\${tagname}..."
	docker tag calicovpp/agent:${TAG} calicovpp/agent:\${tagname}
done

trap 'docker logout' EXIT
docker login --username $DOCKER_USERNAME $DOCKER_TOKEN

docker push calicovpp/vpp:${TAG}
docker push calicovpp/agent:${TAG}
for tagname in $(echo $EXTRA_TAGS | sed 's/,/ /g'); do
	echo "Pushing calicovpp/vpp:\${tagname}...."
	docker push calicovpp/vpp:\${tagname}
	echo "Pushing calicovpp/vpp:\${tagname}...."
	docker push calicovpp/agent:\${tagname}
done

EOF

}


if [ x$1 = xpush ]; then
  shift ; push $@
else
  echo "Usage"
  echo "mngmt.sh push <some ssh host to build on>"
  echo "  params: DOCKER_USERNAME= DOCKER_TOKEN="
fi

