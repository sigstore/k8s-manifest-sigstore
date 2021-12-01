//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package util

import (
	_ "embed"
	"fmt"
	"testing"
)

//go:embed testdata/concatenated-manifest.yaml
var concatYAMLBytes []byte

//go:embed testdata/target-manifest.yaml
var targetYAMLBytes []byte

func TestYAML(t *testing.T) {
	yamls := SplitConcatYAMLs(concatYAMLBytes)
	yamlsNumExpected := 4
	if len(yamls) != yamlsNumExpected {
		t.Errorf("len(yamls) expect: %v, actual: %v", yamlsNumExpected, len(yamls))
		return
	}

	for _, yamlBytes := range yamls {
		if !isK8sResourceYAML(yamlBytes) {
			t.Errorf("failed to load this YAML as a K8s resource: %s", string(yamlBytes))
			return
		}
	}

	found, candidates := FindManifestYAML(concatYAMLBytes, targetYAMLBytes, nil, nil)
	if !found || len(candidates) == 0 {
		t.Error("failed to find a target YAML in a concatenated YAML")
		return
	}

	for i, cand := range candidates {
		t.Logf("found YAML %v: %s", i+1, string(cand))
	}
}

func sampleFunc(in string) {
	fmt.Printf("this is input: %s", in)
}
