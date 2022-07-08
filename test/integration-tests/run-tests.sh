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

VPP_IMAGE="calicovpp/vpp:latest"
POD_MOCK_IMAGE="calicovpp/vpp-test-pod-mock:latest"

function prepageImageWithVPPBinary() {
  if ! docker image inspect $VPP_IMAGE >/dev/null 2>&1; then
    echo "Can't find docker image "$VPP_IMAGE". Rebuilding it..."
    pushd ../../vpp-manager
    if ! make image; then
      echo "Can't build "$VPP_IMAGE", exiting..."
      exit 1
    fi
    popd
  fi
}

function preparePodMockImage() {
  if ! docker build -t $POD_MOCK_IMAGE images/pod-mock; then
      echo "Can't build "$POD_MOCK_IMAGE", exiting..."
      exit 1
  fi
}

result=0

echo "Running Integration tests..."
echo "Running Calico VPP Agent - CNI tests..."
prepageImageWithVPPBinary
preparePodMockImage
# Note: some pod tests expect elevated user privileges -> using sudo
INTEGRATION_TEST="." VPP_IMAGE=$VPP_IMAGE VPP_BINARY="/usr/bin/vpp" \
sudo -E env "PATH=$PATH" go test -v -run Integration ../../calico-vpp-agent/cni -ginkgo.v || result=$?



if [ $result -ne 0 ]; then
    echo -e "[FAIL] Some integration tests failed";
else
    echo -e "[OK] All integration tests passed";
fi

exit $result