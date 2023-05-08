#!/bin/bash
# 
# Copyright 2021 The Sigstore Authors.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -e

if [[ ! -z $KUBEBUILDER_ASSETS ]]; then
    echo $KUBEBUILDER_ASSETS
    exit 0
fi

if ! [ -x "$(command -v setup-envtest)" ]; then
    echo "Installing setup-envtest..."  >&2
    go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest  >&2
    echo "done."  >&2
fi

path=`setup-envtest use -p path 1.24.1`
echo $path

# For more details: https://github.com/kubernetes-sigs/controller-runtime/tree/master/tools/setup-envtest