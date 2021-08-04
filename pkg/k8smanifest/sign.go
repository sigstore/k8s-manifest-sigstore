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
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/sigstore/cosign/pkg/cosign"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	k8scosign "github.com/sigstore/k8s-manifest-sigstore/pkg/cosign"
	k8ssigutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
)

const (
	ImageRefAnnotationKey    = "cosign.sigstore.dev/imageRef"
	SignatureAnnotationKey   = "cosign.sigstore.dev/signature"
	CertificateAnnotationKey = "cosign.sigstore.dev/certificate"
	MessageAnnotationKey     = "cosign.sigstore.dev/message"
	BundleAnnotationKey      = "cosign.sigstore.dev/bundle" // bundle is not supported in cosign.SignBlob() yet
)

var annotationKeyMap = map[string]string{
	"signature":   SignatureAnnotationKey,
	"certificate": CertificateAnnotationKey,
	"message":     MessageAnnotationKey,
	"bundle":      BundleAnnotationKey,
	"imageRef":    ImageRefAnnotationKey,
}

func Sign(inputDir string, so *SignOption) ([]byte, error) {

	output := ""
	if so.UpdateAnnotation {
		output = so.Output
	}

	signedBytes, err := NewSigner(so.ImageRef, so.KeyPath, so.CertPath, so.PassFunc).Sign(inputDir, output, so.ImageAnnotations)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign the specified content")
	}

	return signedBytes, nil
}

type Signer interface {
	Sign(inputDir, output string, imageAnnotations map[string]interface{}) ([]byte, error)
}

func NewSigner(imageRef, keyPath, certPath string, pf cosign.PassFunc) Signer {
	var prikeyPath *string
	if keyPath != "" {
		prikeyPath = &keyPath
	}
	var certPathP *string
	if certPath != "" {
		certPathP = &certPath
	}
	if imageRef == "" {
		return &AnnotationSigner{prikeyPath: prikeyPath, certPath: certPathP, passFunc: pf}
	} else {
		return &ImageSigner{imageRef: imageRef, prikeyPath: prikeyPath, certPath: certPathP, passFunc: pf}
	}
}

type ImageSigner struct {
	imageRef   string
	prikeyPath *string
	certPath   *string
	passFunc   cosign.PassFunc
}

func (s *ImageSigner) Sign(inputDir, output string, imageAnnotations map[string]interface{}) ([]byte, error) {
	var inputDataBuffer bytes.Buffer
	var mo *k8ssigutil.MutateOptions
	if len(imageAnnotations) > 0 {
		mo = &k8ssigutil.MutateOptions{AW: embedAnnotation, Annotations: imageAnnotations}
	}
	err := k8ssigutil.TarGzCompress(inputDir, &inputDataBuffer, mo)
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
	err = k8scosign.SignImage(s.imageRef, s.prikeyPath, s.certPath, s.passFunc, imageAnnotations)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign image")
	}
	if output != "" {
		// generate a signed YAML file
		signedBytes, err = generateSignedYAMLManifest(inputDir, s.imageRef, nil, imageAnnotations)
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

type AnnotationSigner struct {
	prikeyPath *string
	certPath   *string
	passFunc   cosign.PassFunc
}

func (s *AnnotationSigner) Sign(inputDir, output string, imageAnnotations map[string]interface{}) ([]byte, error) {
	var inputDataBuffer bytes.Buffer
	dir, err := ioutil.TempDir("", "kubectl-sigstore-temp-dir")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a temporary directory for signing")
	}
	defer os.RemoveAll(dir)
	tmpBlobFile := filepath.Join(dir, "tmp-blob-file")

	var mo *k8ssigutil.MutateOptions
	if imageAnnotations != nil {
		mo = &k8ssigutil.MutateOptions{AW: embedAnnotation, Annotations: imageAnnotations}
	}

	err = k8ssigutil.TarGzCompress(inputDir, &inputDataBuffer, mo)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compress an input file/dir")
	}
	var signedBytes []byte
	var sigMaps map[string][]byte
	err = ioutil.WriteFile(tmpBlobFile, inputDataBuffer.Bytes(), 0777)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a temporary blob file")
	}
	sigMaps, err = k8scosign.SignBlob(tmpBlobFile, s.prikeyPath, s.certPath, s.passFunc)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign a blob file")
	}
	if output != "" {
		// generate a signed YAML file
		signedBytes, err = generateSignedYAMLManifest(inputDir, "", sigMaps, imageAnnotations)
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

	mediaTypeGetter := cremote.DefaultMediaTypeGetter
	remoteAuthOption := remote.WithAuthFromKeychain(authn.DefaultKeychain)
	remoteContextOption := remote.WithContext(context.Background())
	_, err = cremote.UploadFiles(ref, files, mediaTypeGetter, remoteAuthOption, remoteContextOption)
	if err != nil {
		return err
	}
	return nil
}

func generateSignedYAMLManifest(inputDir, imageRef string, sigMaps map[string][]byte, imageAnnotations map[string]interface{}) ([]byte, error) {
	if imageRef == "" && len(sigMaps) == 0 {
		return nil, errors.New("either image ref or signature infos are required for generating a signed YAML")
	}

	yamls, err := k8ssigutil.FindYAMLsInDir(inputDir)
	if err != nil {
		return nil, err
	}
	// convert any type of YAMLs into a list of single resource YAMLs
	tmpYAMLs := [][]byte{}
	for _, singleYAML := range yamls {
		if k8ssigutil.IsConcatYAMLs(singleYAML) {
			yamlsInSingle := k8ssigutil.SplitConcatYAMLs(singleYAML)
			tmpYAMLs = append(tmpYAMLs, yamlsInSingle...)
		} else {
			tmpYAMLs = append(tmpYAMLs, singleYAML)
		}
	}
	yamls = tmpYAMLs

	annotationMap := map[string]interface{}{}
	if imageRef != "" {
		annotationMap[ImageRefAnnotationKey] = imageRef
	} else if len(sigMaps) > 0 {
		for key, val := range sigMaps {
			annoKey, ok := annotationKeyMap[key]
			if ok {
				annotationMap[annoKey] = string(val)
			}
		}
	}

	for k, v := range imageAnnotations {
		annotationMap[k] = v
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
