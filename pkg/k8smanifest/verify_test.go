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
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghodss/yaml"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// files for test cases

//go:embed testdata/testpub
var b64EncodedTestPubkey []byte

func TestVerifyResource(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "k8smanifest-verify-resource-test")
	if err != nil {
		t.Errorf("failed to create temp dir: %s", err.Error())
		return
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "testpub")
	err = initSingleTestFile(b64EncodedTestPubkey, keyPath)
	if err != nil {
		t.Errorf("failed to init a public key file for test: %s", err.Error())
		return
	}

	fpath := "testdata/sample-configmap-signed.yaml"
	objBytes, err := ioutil.ReadFile(fpath)
	if err != nil {
		t.Errorf("failed to load a test resource file: %s", err.Error())
		return
	}
	t.Logf("verify-resource resource: %s", string(objBytes))
	var obj unstructured.Unstructured
	err = yaml.Unmarshal(objBytes, &obj)
	if err != nil {
		t.Errorf("failed to unmarshal: %s", err.Error())
		return
	}
	vo := &VerifyResourceOption{
		verifyOption: verifyOption{
			KeyPath: keyPath,
		},
	}

	result, err := VerifyResource(obj, vo)
	if err != nil {
		t.Errorf("failed to verify a resource: %s", err.Error())
		return
	}
	resultBytes, _ := json.Marshal(result)
	t.Logf("verify-resource result: %s", string(resultBytes))
}
