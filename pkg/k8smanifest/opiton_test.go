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
package k8smanifest

import (
	_ "embed"
	"testing"

	"github.com/ghodss/yaml"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestLoadDefaultConfig(t *testing.T) {

	testObjBytes := []byte(`
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm
data:
  key1: val1
  key2: val2
`)
	var obj unstructured.Unstructured
	err := yaml.Unmarshal(testObjBytes, &obj)
	if err != nil {
		t.Errorf("failed to unmarshal: %s", err.Error())
		return
	}

	vo := LoadDefaultConfig()
	matched, ignoreFields := vo.IgnoreFields.Match(obj)
	if !matched || len(ignoreFields) == 0 {
		t.Errorf("failed to get ignore fields from default config; matched: %v, len(ignoreFields): %v", matched, len(ignoreFields))
		return
	}

	resourceBundleRefAnnotationKey := vo.AnnotationConfig.ResourceBundleRefAnnotationKey()
	if resourceBundleRefAnnotationKey == "" {
		t.Error("failed to get resBundleRefAnnotationKey; this config must not be empty and must return `cosign.sigstore.dev/resourceBundleRef` if empty")
		return
	}
}
