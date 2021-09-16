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
package cli

import (
	_ "embed"
	"encoding/base64"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

// files for test cases

//go:embed testdata/testkey
var b64EncodedTestKey []byte

func TestSign(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "sign-test")
	if err != nil {
		t.Errorf("failed to create temp dir: %s", err.Error())
		return
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "testkey")
	_ = os.Setenv("COSIGN_PASSWORD", "")
	err = initSingleTestFile(b64EncodedTestKey, keyPath)
	if err != nil {
		t.Errorf("failed to load a signing key file for test: %s", err.Error())
		return
	}

	fpath := "testdata/sample-configmap.yaml"
	outPath := filepath.Join(tmpDir, "sample-configmap.yaml.signed")
	err = sign(fpath, "", keyPath, outPath, false, true, nil)
	if err != nil {
		t.Errorf("failed to sign the test file: %s", err.Error())
		return
	}
	outBytes, err := ioutil.ReadFile(outPath)
	if err != nil {
		t.Errorf("failed to read the signed file: %s", err.Error())
		return
	}
	t.Logf("signed YAML file: %s", string(outBytes))
}

func initSingleTestFile(b64EncodedData []byte, fpath string) error {
	testblob, err := base64.StdEncoding.DecodeString(string(b64EncodedData))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(fpath, testblob, 0644)
	if err != nil {
		return err
	}
	return nil
}
