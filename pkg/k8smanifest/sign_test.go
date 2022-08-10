// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package k8smanifest

import (
	_ "embed"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghodss/yaml"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// files for test cases

//go:embed testdata/testkey
var b64EncodedTestKey []byte

func TestSign(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "k8smanifest-sign-test")
	if err != nil {
		t.Errorf("failed to create temp dir: %s", err.Error())
		return
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "testkey")
	_ = os.Setenv("COSIGN_PASSWORD", "")
	err = initSingleTestFile(b64EncodedTestKey, keyPath)
	if err != nil {
		t.Errorf("failed to init a signing key file for test: %s", err.Error())
		return
	}

	fpath := "testdata/sample-configmap.yaml"
	outPath := filepath.Join(tmpDir, "sample-configmap.yaml.signed")

	so := &SignOption{
		KeyPath:          keyPath,
		Output:           outPath,
		UpdateAnnotation: true,
	}

	signedBytes, err := Sign(fpath, so)
	if err != nil {
		t.Errorf("failed to sign the test file: %s", err.Error())
		return
	}
	t.Logf("signed YAML file: %s", string(signedBytes))

	var obj1, obj2, obj3 unstructured.Unstructured
	err = yaml.Unmarshal(signedBytes, &obj1)
	if err != nil {
		t.Errorf("failed to unmarshal the signed yaml: %s", err.Error())
		return
	}
	annotationMap := obj1.GetAnnotations()
	msgKey := DefaultAnnotationKeyDomain + "/message"
	msg1 := annotationMap[msgKey]

	// 2nd time to check message consistency
	secondSignedBytes, err := Sign(fpath, so)
	if err != nil {
		t.Errorf("failed to sign the test file (2nd time): %s", err.Error())
		return
	}
	err = yaml.Unmarshal(secondSignedBytes, &obj2)
	if err != nil {
		t.Errorf("failed to unmarshal the signed yaml (2nd time): %s", err.Error())
		return
	}
	annotationMap2 := obj2.GetAnnotations()
	msg2 := annotationMap2[msgKey]
	if msg1 != msg2 {
		t.Errorf("the message is different from the first time even though the input is identical")
		return
	}

	// then, try signing with "AppendSignature" option on the signed manifest
	so.AppendSignature = true
	thirdSignedBytes, err := Sign(outPath, so)
	if err != nil {
		t.Errorf("failed to sign the test file (3rd time): %s", err.Error())
		return
	}
	err = yaml.Unmarshal(thirdSignedBytes, &obj3)
	if err != nil {
		t.Errorf("failed to unmarshal the signed yaml (3rd time): %s", err.Error())
		return
	}
	annotationMap3 := obj3.GetAnnotations()
	sigKey := DefaultAnnotationKeyDomain + "/signature_1"
	_, ok := annotationMap3[sigKey]
	if !ok {
		t.Errorf("`%s` is not found in the signed yaml manifest after signing with AppendSignature option", sigKey)
		return
	}
}

func TestNonTarballSign(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "k8smanifest-sign-test")
	if err != nil {
		t.Errorf("failed to create temp dir: %s", err.Error())
		return
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "testkey")
	_ = os.Setenv("COSIGN_PASSWORD", "")
	err = initSingleTestFile(b64EncodedTestKey, keyPath)
	if err != nil {
		t.Errorf("failed to init a signing key file for test: %s", err.Error())
		return
	}

	fpath := "testdata/sample-configmap.yaml"
	outPath := filepath.Join(tmpDir, "sample-configmap-raw.yaml.signed")

	falseVar := false
	so := &SignOption{
		KeyPath:          keyPath,
		Output:           outPath,
		Tarball:          &falseVar,
		UpdateAnnotation: true,
	}

	signedBytes, err := Sign(fpath, so)
	if err != nil {
		t.Errorf("failed to sign the test file by non-tarball sign: %s", err.Error())
		return
	}
	t.Logf("signed YAML file by non-tarball sign: %s", string(signedBytes))
}

func initSingleTestFile(b64EncodedData []byte, fpath string) error {
	testblob, err := base64.StdEncoding.DecodeString(string(b64EncodedData))
	if err != nil {
		return err
	}
	err = os.WriteFile(fpath, testblob, 0644)
	if err != nil {
		return err
	}
	return nil
}
