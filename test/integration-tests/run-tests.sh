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

-e # stop at first failed test

result=0

echo "Running Integration tests..."
echo "Running Calico VPP Agent - CNI tests..."
# creating image with VPP binary that is needed for test
# TODO check for needed image (tagged latest) to exists - minimal prevention of unnecessary vpp rebuild
pushd ../../vpp-manager
make image
popd

# running the cni tests
INTEGRATION_TEST="." VPP_IMAGE="calicovpp/vpp" VPP_BINARY="/usr/bin/vpp" \
go test -v -run Integration ../../calico-vpp-agent/cni || result=$?



if [ $result -ne 0 ]; then
    echo -e "[FAIL] Some integration tests failed";
else
    echo -e "[OK] All integration tests passed";
fi

exit $result