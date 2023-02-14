#!/usr/bin/env bash

# Copyright 2023 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License"";
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

: "${GIT_HASH:?Environment variable empty or not defined.}"
: "${GITHUB_RUN_ID:?Environment variable empty or not defined.}"
: "${GITHUB_RUN_ATTEMPT:?Environment variable empty or not defined.}"
: "${TEST_IMAGE:?Environment variable empty or not defined.}"

export COSIGN_EXPERIMENTAL=1
K8S_SIGSTORE_CLI=./kubectl-sigstore

timestamp=$(date +%s)

cat << EOS > sample-configmap.yaml
kind: ConfigMap 
apiVersion: v1 
metadata:
  name: example-configmap 
data:
  key: val
  timestamp: $timestamp
EOS

echo "Signing a sample yaml using Keyless..."
$K8S_SIGSTORE_CLI sign --tarball=no -f sample-configmap.yaml


echo "Verifying the signed yaml..."
$K8S_SIGSTORE_CLI verify -f sample-configmap.yaml.signed