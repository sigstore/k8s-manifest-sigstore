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
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"

	k8smnfcosign "github.com/sigstore/k8s-manifest-sigstore/pkg/cosign"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	mapnode "github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
)

var EmbeddedAnnotationMaskKeys = []string{
	fmt.Sprintf("metadata.annotations.\"%s\"", ImageRefAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", SignatureAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", CertificateAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", MessageAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", BundleAnnotationKey),
}

type SignatureVerifier interface {
	Verify() (bool, string, error)
}

func NewSignatureVerifier(objYAMLBytes []byte, imageRef string, pubkeyPath *string) SignatureVerifier {
	var annotations map[string]string
	if imageRef == "" {
		annotations = k8smnfutil.GetAnnotationsInYAML(objYAMLBytes)
		if annoImageRef, ok := annotations[ImageRefAnnotationKey]; ok {
			imageRef = annoImageRef
		}
	}
	if imageRef == "" {
		// TODO: support annotation signature
		return nil
	} else {
		return &ImageSignatureVerifier{imageRef: imageRef}
	}
}

type ImageSignatureVerifier struct {
	imageRef   string
	pubkeyPath *string
}

func (v *ImageSignatureVerifier) Verify() (bool, string, error) {
	imageRef := v.imageRef
	if imageRef == "" {
		return false, "", errors.New("no image reference is found")
	}

	// do normal image verification
	return k8smnfcosign.VerifyImage(imageRef, v.pubkeyPath)
}

// This is an interface for fetching YAML manifest
// a function Fetch() fetches a YAML manifest which matches the input object's kind, name and so on
type ManifestFetcher interface {
	Fetch(objYAMLBytes []byte) ([]byte, error)
}

func NewManifestFetcher(imageRef string) ManifestFetcher {
	if imageRef == "" {
		// TODO: support annotation signature
		return nil
	} else {
		return &ImageManifestFetcher{imageRef: imageRef}
	}
}

// ImageManifestFetcher is a fetcher implementation for image reference
type ImageManifestFetcher struct {
	imageRef string
}

func (f *ImageManifestFetcher) Fetch(objYAMLBytes []byte) ([]byte, error) {
	imageRef := f.imageRef
	if imageRef == "" {
		annotations := k8smnfutil.GetAnnotationsInYAML(objYAMLBytes)
		if annoImageRef, ok := annotations[ImageRefAnnotationKey]; ok {
			imageRef = annoImageRef
		}
	}
	if imageRef == "" {
		return nil, errors.New("no image reference is found")
	}

	var concatYAMLbytes []byte
	var err error
	// fetch YAML manifests from actual image
	concatYAMLbytes, err = f.getConcatYAMLFromImageRef(imageRef)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get YAMLs in the image")
	}

	found, foundManifest := k8smnfutil.FindManifestYAML(concatYAMLbytes, objYAMLBytes)
	if !found {
		return nil, errors.New("failed to find a YAML manifest in the image")
	}
	return foundManifest, nil
}

func (f *ImageManifestFetcher) getConcatYAMLFromImageRef(imageRef string) ([]byte, error) {
	image, err := k8smnfutil.PullImage(imageRef)
	if err != nil {
		return nil, err
	}
	concatYAMLbytes, err := k8smnfutil.GenerateConcatYAMLsFromImage(image)
	if err != nil {
		return nil, err
	}
	return concatYAMLbytes, nil
}

type VerifyResult struct {
	Verified bool                `json:"verified"`
	Signer   string              `json:"signer"`
	Diff     *mapnode.DiffResult `json:"diff"`
}

func (r *VerifyResult) String() string {
	rB, _ := json.Marshal(r)
	return string(rB)
}
