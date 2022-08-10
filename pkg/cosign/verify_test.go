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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyBlob(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "verify_test")
	if err != nil {
		t.Errorf("failed to create temp dir: %s", err.Error())
		return
	}
	defer os.RemoveAll(tmpDir)

	pubkeyPath := filepath.Join(tmpDir, "cosign.pub")
	err = loadTestFiles(map[string]testFile{"key": {b64data: b64EncodedTestPubKey, fpath: pubkeyPath}})
	if err != nil {
		t.Errorf("failed to load pub key: %s", err.Error())
		return
	}
	verified, _, _, err := VerifyBlob(b64EncodedTestBlob, b64EncodedTestSig, nil, nil, &pubkeyPath, "", "", "", "")
	if err != nil {
		t.Errorf("failed to verify signature with error: %s", err.Error())
		return
	}
	if !verified {
		t.Error("failed to verify signature")
		return
	}
}
