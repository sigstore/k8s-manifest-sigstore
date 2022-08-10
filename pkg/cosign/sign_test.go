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
package cosign

import (
	_ "embed"
	"encoding/base64"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

// files for test cases

//go:embed testdata/testblob
var b64EncodedTestBlob []byte

//go:embed testdata/testkey
var b64EncodedTestKey []byte

//go:embed testdata/testpub
var b64EncodedTestPubKey []byte

//go:embed testdata/testsig
var b64EncodedTestSig []byte

type testFile struct {
	fpath   string
	b64data []byte
}

func TestSignBlob(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "sign_test")
	if err != nil {
		t.Errorf("failed to create temp dir: %s", err.Error())
		return
	}
	defer os.RemoveAll(tmpDir)

	files := map[string]testFile{
		"blob": {b64data: b64EncodedTestBlob, fpath: filepath.Join(tmpDir, "blobfile")},
		"key":  {b64data: b64EncodedTestKey, fpath: filepath.Join(tmpDir, "cosign.key")},
	}
	err = loadTestFiles(files)
	if err != nil {
		t.Errorf("failed to load test files: %s", err.Error())
		return
	}
	blobPath := files["blob"].fpath
	keyPath := files["key"].fpath

	sigMap, err := SignBlob(blobPath, &keyPath, nil, "", passFuncForTest)
	if err != nil {
		t.Errorf("failed to load test files: %s", err.Error())
		return
	}
	if _, ok := sigMap["signature"]; !ok {
		t.Error("signature is not found in return values from SignBlob()")
		return
	}
	if _, ok := sigMap["message"]; !ok {
		t.Error("message is not found in return values from SignBlob()")
		return
	}

	// b64SigBytes := sigMap["signature"]
	// sigFileName := filepath.Join("testdata", "testsig")
	// _ = ioutil.WriteFile(sigFileName, []byte(b64SigBytes), 0644)
}

func passFuncForTest(b bool) ([]byte, error) {
	return []byte(""), nil
}

func loadTestFiles(files map[string]testFile) error {
	for _, tf := range files {
		err := initSingleTestFile(tf.b64data, tf.fpath)
		if err != nil {
			return err
		}
	}
	return nil
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
