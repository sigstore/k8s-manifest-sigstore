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
	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	mapnode "github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
)

func VerifyManifest(manifest []byte, vo *VerifyManifestOption) (*VerifyResult, error) {
	if manifest == nil {
		return nil, errors.New("input YAML manifest must be non-empty")
	}

	var obj unstructured.Unstructured
	_ = yaml.Unmarshal(manifest, &obj)

	verified := false
	signerName := ""
	var err error

	// if imageRef is not specified in args and it is found in object annotations, use the found image ref
	if vo.ImageRef == "" {
		annotations := obj.GetAnnotations()
		annoImageRef, found := annotations[ImageRefAnnotationKey]
		if found {
			vo.ImageRef = annoImageRef
		}
	}

	// get ignore fields configuration for this resource if found
	ignoreFields := []string{}
	if vo != nil {
		if ok, fields := vo.IgnoreFields.Match(obj); ok {
			ignoreFields = fields
		}
	}

	var foundManifestBytes []byte
	foundManifestBytes, _, err = NewManifestFetcher(vo.ImageRef).Fetch(manifest)
	if err != nil {
		return nil, errors.Wrap(err, "reference YAML manifest not found for this manifest")
	}

	mnfMatched, diff, err := matchManifest(manifest, foundManifestBytes, ignoreFields)
	if err != nil {
		return nil, errors.Wrap(err, "error occurred during matching manifest")
	}

	var keyPath *string
	if vo.KeyPath != "" {
		keyPath = &(vo.KeyPath)
	}

	sigVerified, signerName, _, err := NewSignatureVerifier(manifest, vo.ImageRef, keyPath).Verify()
	if err != nil {
		return nil, errors.Wrap(err, "error occured during signature verification")
	}

	verified = mnfMatched && sigVerified && vo.Signers.Match(signerName)

	return &VerifyResult{
		Verified: verified,
		Signer:   signerName,
		Diff:     diff,
	}, nil
}

func matchManifest(inputManifestBytes, foundManifestBytes []byte, ignoreFields []string) (bool, *mapnode.DiffResult, error) {
	log.Debug("manifest:", string(inputManifestBytes))
	log.Debug("manifest in reference:", string(foundManifestBytes))
	inputFileNode, err := mapnode.NewFromYamlBytes(inputManifestBytes)
	if err != nil {
		return false, nil, err
	}
	maskedInputNode := inputFileNode.Mask(EmbeddedAnnotationMaskKeys)

	var obj unstructured.Unstructured
	err = yaml.Unmarshal(inputManifestBytes, &obj)
	if err != nil {
		return false, nil, err
	}

	manifestNode, err := mapnode.NewFromYamlBytes(foundManifestBytes)
	if err != nil {
		return false, nil, err
	}
	maskedManifestNode := manifestNode.Mask(EmbeddedAnnotationMaskKeys)
	var matched bool
	diff := maskedInputNode.Diff(maskedManifestNode)

	// filter out ignoreFields
	if diff != nil && len(ignoreFields) > 0 {
		_, diff, _ = diff.Filter(ignoreFields)
	}
	if diff == nil || diff.Size() == 0 {
		matched = true
		diff = nil
	}
	return matched, diff, nil
}
