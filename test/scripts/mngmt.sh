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

SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
BUILD_LOG_DIR=$SCRIPTDIR/.buildlogs
BUILD_NAME=$(date +"build.%Y-%m-%dT%H.%M.%s")

if [ -e $BUILD_LOG_DIR/conf ]; then
    source $BUILD_LOG_DIR/conf
fi

VPP_DATAPLANE_DIRECTORY=${VPP_DATAPLANE_DIRECTORY:=/tmp/vpp-dataplane/}
REPO_URL=${REPO_URL:=https://github.com/projectcalico/vpp-dataplane.git}
BRANCH_NAME=${BRANCH_NAME:=origin/master}
TAG=${TAG:=latest}
EXTRA_TAGS=${EXTRA_TAGS:=prerelease}
PUSH=${PUSH:=y}

function push ()
{

SSH_NAME=${SSH_NAME:=$1}
if [ x$SSH_NAME = x ]; then
	echo "missing ssh host"
	echo "please use mngmt.sh push <some ssh host to build on>"
	exit 1
fi

mkdir -p $BUILD_LOG_DIR/${BUILD_NAME}
echo "Starting build..."
echo "Output redirected to ${BUILD_LOG_DIR}/${BUILD_NAME}/build.log"

ssh $SSH_NAME /bin/bash > ${BUILD_LOG_DIR}/${BUILD_NAME}/build.log 2>&1 << EOF
if [ -d $VPP_DATAPLANE_DIRECTORY ]; then
	echo "Fetching latest"
	cd $VPP_DATAPLANE_DIRECTORY
	git fetch origin -p
else
	git clone $REPO_URL $VPP_DATAPLANE_DIRECTORY
fi
git reset $BRANCH_NAME --hard
git clean -fd

make -C $VPP_DATAPLANE_DIRECTORY image TAG=$TAG WITH_GDB=$WITH_GDB

echo "built calicovpp/vpp:${TAG}"
echo "built calicovpp/agent:${TAG}"
for tagname in $(echo $EXTRA_TAGS | sed 's/,/ /g'); do
	echo "Tagging calicovpp/vpp:\${tagname}..."
	docker tag calicovpp/vpp:${TAG} calicovpp/vpp:\${tagname}
	echo "Tagging calicovpp/agent:\${tagname}..."
	docker tag calicovpp/agent:${TAG} calicovpp/agent:\${tagname}
done

if [ $PUSH != "y" ]; then
	echo "not pushing"
	exit 0
fi

trap 'docker logout' EXIT
docker login --username $DOCKER_USERNAME  --password $DOCKER_TOKEN

echo ">> Pushing calicovpp/vpp:${TAG}...."
docker push calicovpp/vpp:${TAG}
echo ">> Pushing calicovpp/agent:${TAG}...."
docker push calicovpp/agent:${TAG}
for tagname in $(echo $EXTRA_TAGS | sed 's/,/ /g'); do
	echo ">> Pushing calicovpp/vpp:\${tagname}...."
	docker push calicovpp/vpp:\${tagname}
	echo ">> Pushing calicovpp/vpp:\${tagname}...."
	docker push calicovpp/agent:\${tagname}
done

EOF

echo "Printing summary to ${BUILD_LOG_DIR}/${BUILD_NAME}/summary"
echo "--------------------------------------------------"   >> ${BUILD_LOG_DIR}/${BUILD_NAME}/summary
echo "Date                     : $(date +"%Y-%m-%d %H:%M")" >> ${BUILD_LOG_DIR}/${BUILD_NAME}/summary
echo "REPO_URL                 : $REPO_URL"                 >> ${BUILD_LOG_DIR}/${BUILD_NAME}/summary
echo "BRANCH_NAME              : $BRANCH_NAME"              >> ${BUILD_LOG_DIR}/${BUILD_NAME}/summary
echo "VPP_DATAPLANE_DIRECTORY  : $VPP_DATAPLANE_DIRECTORY"  >> ${BUILD_LOG_DIR}/${BUILD_NAME}/summary
echo "WITH_GDB                 : $WITH_GDB"                 >> ${BUILD_LOG_DIR}/${BUILD_NAME}/summary
echo "SSH_NAME                 : $SSH_NAME"                 >> ${BUILD_LOG_DIR}/${BUILD_NAME}/summary
echo "PUSH                     : $PUSH"                     >> ${BUILD_LOG_DIR}/${BUILD_NAME}/summary
echo "Tags built               : ${TAG},${EXTRA_TAGS}"      >> ${BUILD_LOG_DIR}/${BUILD_NAME}/summary
ssh $SSH_NAME /bin/bash                                     >> ${BUILD_LOG_DIR}/${BUILD_NAME}/summary << EOF
cd $VPP_DATAPLANE_DIRECTORY
echo "Commit                   : \$(git log -1 --pretty=%H)"
EOF
echo "SHAs                     :"                           >> ${BUILD_LOG_DIR}/${BUILD_NAME}/summary
echo "--------------------------------------------------"   >> ${BUILD_LOG_DIR}/${BUILD_NAME}/summary
ssh $SSH_NAME /bin/bash                                     >> ${BUILD_LOG_DIR}/${BUILD_NAME}/summary << EOF
for imgname in calicovpp/vpp calicovpp/agent; do
for tagname in $(echo "${TAG},${EXTRA_TAGS}" | sed 's/,/ /g'); do
	echo "\${imgname}:\${tagname} \$(docker inspect \${imgname}:\${tagname} --format '{{ .RepoDigests }}')"
done
done
EOF
echo "--------------------------------------------------"   >> ${BUILD_LOG_DIR}/${BUILD_NAME}/summary

cat ${BUILD_LOG_DIR}/${BUILD_NAME}/summary
}

get_message ()
{
	printf "Just built & pushed new images\\n"
    printf "\`\`\`\`\\n"
	cat ${BUILD_LOG_DIR}/${BUILD_NAME}/summary
    printf "\`\`\`\`\\n"
    printf "\\n"
}

send_report_to_webex ()
{
	if [ x$PUSH != "xy" ]; then
		echo "not pushing"
		exit 0
	fi
	if [ x$ACCESS_TOKEN == x"" ] || [ x$ROOM_ID == x"" ]; then
		echo "Not sending to webex, missing ACCESS_TOKEN/ROOM_ID"
		exit 0
	fi
    MESSAGE="$(get_message)"
    curl --request POST \
      --header "Authorization: Bearer $ACCESS_TOKEN" \
      --form "roomId=${ROOM_ID}" \
      --form "markdown=${MESSAGE}" \
      "https://webexapis.com/v1/messages"
}

if [ x$1 = xpush ]; then
  shift ; push $@
  send_report_to_webex
else
  echo "Usage"
  echo "mngmt.sh push <some ssh host to build on>"
  echo "  params: DOCKER_USERNAME= DOCKER_TOKEN= BRANCH_NAME="
fi

