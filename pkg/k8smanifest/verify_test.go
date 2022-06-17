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
	"encoding/base64"
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

const b64KeylesSignerConfig = "aGlyb2t1bmkua2l0YWhhcmExQGlibS5jb20K"

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

func TestVerifyResourceWithMultipleSignatures(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "k8smanifest-verify-resource-multisig-test")
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

	fpath := "testdata/sample-configmap-multi-signed.yaml"
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
	t.Logf("verify-resource with multiple signatures result: %s", string(resultBytes))
}

func TestVerifyResourceWithKeylessMultipleSignatures(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "k8smanifest-verify-resource-keyless-multisig-test")
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

	fpath := "testdata/sample-configmap-keyless-multi-signed.yaml"
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
	signerConfig, err := base64.StdEncoding.DecodeString(b64KeylesSignerConfig)
	if err != nil {
		t.Errorf("failed to base64 decode the signer config: %s", err.Error())
		return
	}
	vo := &VerifyResourceOption{
		verifyOption: verifyOption{
			KeyPath: keyPath,
			Signers: SignerList{
				string(signerConfig), // this should match with the second signature
			},
		},
	}

	result, err := VerifyResource(obj, vo)
	if err != nil {
		t.Errorf("failed to verify a resource: %s", err.Error())
		return
	}
	resultBytes, _ := json.Marshal(result)
	t.Logf("verify-resource with keyless multiple signatures result: %s", string(resultBytes))
}

func TestVerifyResourceWithoutDryRun(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "k8smanifest-verify-resource-without-dryrun-test")
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

	fpath := "testdata/sample-deployment-signed-deployed.yaml"
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
		DisableDryRun: true,
	}
	vo = AddDefaultConfig(vo)

	result, err := VerifyResource(obj, vo)
	if err != nil {
		t.Errorf("failed to verify a resource: %s", err.Error())
		return
	}

	resultBytes, _ := json.Marshal(result)
	t.Logf("verify-resource without dry run result: %s", string(resultBytes))
	if result.Verified {
		t.Errorf("it should fail without dryrun in this test case, but not failed")
		return
	}
}

func TestInclusionMatch(t *testing.T) {
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

	f1path := "testdata/sample-deployment-signed.yaml"
	mnfBytes, err := ioutil.ReadFile(f1path)
	if err != nil {
		t.Errorf("failed to load a test resource file for manifest: %s", err.Error())
		return
	}

	f2path := "testdata/sample-deployment-signed-mutating-1.yaml"
	objYAMLBytes, err := ioutil.ReadFile(f2path)
	if err != nil {
		t.Errorf("failed to load a test resource file for obejct: %s", err.Error())
		return
	}
	objBytes, err := yaml.YAMLToJSON(objYAMLBytes)
	if err != nil {
		t.Errorf("failed to convert YAML to JSON for object: %s", err.Error())
		return
	}

	f3path := "testdata/sample-deployment-signed-mutating-2.yaml"
	dyrRunBytes, err := ioutil.ReadFile(f3path)
	if err != nil {
		t.Errorf("failed to load a test resource file for DryRun result: %s", err.Error())
		return
	}

	verified, diff, err := inclusionMatch(mnfBytes, objBytes, dyrRunBytes, false, false)
	if err != nil {
		t.Errorf("failed to check inclusionMatch: %s", err.Error())
		return
	}
	if !verified && diff != nil {
		t.Errorf("diff found in inclusionMatch: %s", diff.String())
		return
	}
	t.Log("inclusionMatch successfully finished.")
}
