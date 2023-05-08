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
package cli

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// files for test cases

//go:embed testdata/testkey
var b64EncodedTestKey []byte

func TestSign(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "sign-test")
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
	err = sign(fpath, "", keyPath, "", outPath, false, false, true, true, false, false, true, nil)
	if err != nil {
		t.Errorf("failed to sign the test file: %s", err.Error())
		return
	}
	outBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Errorf("failed to read the signed file: %s", err.Error())
		return
	}
	t.Logf("signed YAML file: %s", string(outBytes))

	fpath2 := "testdata/sample-configmap-concat.yaml"
	outPath2 := filepath.Join(tmpDir, "sample-configmap-concat.yaml.signed")
	err = sign(fpath2, "", keyPath, "", outPath2, false, false, true, true, false, false, true, nil)
	if err != nil {
		t.Errorf("failed to sign the test file: %s", err.Error())
		return
	}
	outBytes2, err := os.ReadFile(outPath2)
	if err != nil {
		t.Errorf("failed to read the signed file: %s", err.Error())
		return
	}
	yamls := k8smnfutil.SplitConcatYAMLs(outBytes2)
	if len(yamls) != 2 {
		t.Errorf("signed YAML must be a concatenated YAML if the original is a concatenated one")
		return
	}
	var obj *unstructured.Unstructured
	err = yaml.Unmarshal(yamls[0], &obj)
	if err != nil {
		t.Errorf("failed to unmarshal the signed YAML manifest: %s", err.Error())
		return
	}
	annt := obj.GetAnnotations()
	defaultMessageAnnotationKey := "cosign.sigstore.dev/message"
	msgInAnnotations, ok := annt[defaultMessageAnnotationKey]
	if !ok {
		t.Errorf("`%s` not found in annotations in the singed YAML manifest", defaultMessageAnnotationKey)
		return
	}

	t.Logf("signed YAML file2: %s", string(outBytes2))

	manifestInAnnotations, err := getManifestInTarballMessage([]byte(msgInAnnotations))
	if err != nil {
		t.Errorf("failed to get YAML manifest in message annotations: %s", err.Error())
		return
	}
	yamlsInMsgAnnotations := k8smnfutil.SplitConcatYAMLs(manifestInAnnotations)
	if len(yamlsInMsgAnnotations) != 2 {
		t.Errorf("a manifest in message annotation must be a concatenated YAML if the original is a concatenated one")
		return
	}

	t.Logf("manifest in message annotations: %s", string(manifestInAnnotations))
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

func getManifestInTarballMessage(msgBytes []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "kubectl-sigstore-sign-test-temp-dir")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create temp directory")
	}
	defer os.RemoveAll(dir)

	gzipMsg, _ := base64.StdEncoding.DecodeString(string(msgBytes))
	rawMsg := k8smnfutil.GzipDecompress(gzipMsg)
	rawMsgReader := bytes.NewReader(rawMsg)

	err = k8smnfutil.TarGzDecompress(rawMsgReader, dir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decompress an input file/dir")
	}

	yamls, err := k8smnfutil.FindYAMLsInDir(dir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to find yamls in decompressed message tar gz file")
	}

	manifest := k8smnfutil.ConcatenateYAMLs(yamls)
	return manifest, nil
}
