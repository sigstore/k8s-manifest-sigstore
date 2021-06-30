//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package k8smanifest

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/google/go-containerregistry/pkg/name"
	k8scosign "github.com/sigstore/k8s-manifest-sigstore/pkg/cosign"
	k8ssigutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"

	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
)

const (
	ImageRefAnnotationKey    = "cosign.sigstore.dev/imageRef"
	SignatureAnnotationKey   = "cosign.sigstore.dev/signature"
	CertificateAnnotationKey = "cosign.sigstore.dev/certificate"
	MessageAnnotationKey     = "cosign.sigstore.dev/message"
	BundleAnnotationKey      = "cosign.sigstore.dev/bundle" // bundle is not supported in cosign.SignBlob() so far
)

func Sign(inputDir string, so *SignOption) ([]byte, error) {

	output := ""
	if so.UpdateAnnotation {
		output = so.Output
	}

	signedBytes, err := NewSigner(so.ImageRef, so.KeyPath).Sign(inputDir, output)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign the specified content")
	}

	return signedBytes, nil
}

type Signer interface {
	Sign(inputDir, output string) ([]byte, error)
}

func NewSigner(imageRef, keyPath string) Signer {
	var prikeyPath *string
	if keyPath != "" {
		prikeyPath = &keyPath
	}
	if imageRef == "" {
		// TODO: support annotation signature
		return nil
	} else {
		return &ImageSigner{imageRef: imageRef, prikeyPath: prikeyPath}
	}
}

type ImageSigner struct {
	imageRef   string
	prikeyPath *string
}

func (s *ImageSigner) Sign(inputDir, output string) ([]byte, error) {
	var inputDataBuffer bytes.Buffer
	err := k8ssigutil.TarGzCompress(inputDir, &inputDataBuffer)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compress an input file/dir")
	}
	var signedBytes []byte
	// upload files as image
	err = uploadFileToRegistry(inputDataBuffer.Bytes(), s.imageRef)
	if err != nil {
		return nil, errors.Wrap(err, "failed to upload image with manifest")
	}
	// sign the image
	err = k8scosign.SignImage(s.imageRef, s.prikeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign image")
	}
	if output != "" {
		// generate a signed YAML file
		signedBytes, err = generateSignedYAMLManifest(inputDir, s.imageRef, nil)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate a signed YAML")
		}
		err = ioutil.WriteFile(output, signedBytes, 0644)
		if err != nil {
			return nil, errors.Wrap(err, "failed to write a signed YAML into")
		}
	}
	return signedBytes, nil
}

func uploadFileToRegistry(inputData []byte, imageRef string) error {
	dir, err := ioutil.TempDir("", "kubectl-sigstore-temp-dir")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	fpath := filepath.Join(dir, "manifest.yaml")
	err = ioutil.WriteFile(fpath, inputData, 0644)
	if err != nil {
		return err
	}

	files := []cremote.File{
		{Path: fpath},
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	_, err = cremote.UploadFiles(ref, files)
	if err != nil {
		return err
	}
	return nil
}

func generateSignedYAMLManifest(inputDir, imageRef string, sigMaps map[string][]byte) ([]byte, error) {
	if imageRef == "" && len(sigMaps) == 0 {
		return nil, errors.New("either image ref or signature infos are required for generating a signed YAML")
	}

	yamls, err := k8ssigutil.FindYAMLsInDir(inputDir)
	if err != nil {
		return nil, err
	}

	annotationMap := map[string]interface{}{}
	if imageRef != "" {
		annotationMap[ImageRefAnnotationKey] = imageRef
	}

	signedYAMLs := [][]byte{}
	sumErr := []string{}
	for _, yaml := range yamls {
		signedYAML, err := embedAnnotation(yaml, annotationMap)
		if err != nil {
			sumErr = append(sumErr, err.Error())
			continue
		}
		signedYAMLs = append(signedYAMLs, signedYAML)
	}
	if len(signedYAMLs) == 0 && len(sumErr) > 0 {
		return nil, errors.New(fmt.Sprintf("failed to embed annotation to YAMLs; %s", strings.Join(sumErr, "; ")))
	}
	signedConcatYAML := k8ssigutil.ConcatenateYAMLs(signedYAMLs)
	return signedConcatYAML, nil
}

func embedAnnotation(yamlBytes []byte, annotationMap map[string]interface{}) ([]byte, error) {
	orgNode, err := mapnode.NewFromYamlBytes(yamlBytes)
	if err != nil {
		return nil, err
	}
	metadataMap := map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": annotationMap,
		},
	}
	annotationNode, err := mapnode.NewFromMap(metadataMap)
	if err != nil {
		return nil, err
	}
	embedNode, err := orgNode.Merge(annotationNode)
	if err != nil {
		return nil, err
	}
	embedYamlBytes := embedNode.ToYaml()
	return []byte(embedYamlBytes), nil
}
