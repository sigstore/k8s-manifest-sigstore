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

func VerifyManifest(objManifest []byte, vo *VerifyManifestOption) (*VerifyResult, error) {
	if objManifest == nil {
		return nil, errors.New("input YAML manifest must be non-empty")
	}
	if vo == nil {
		vo = &VerifyManifestOption{}
	}

	var obj unstructured.Unstructured
	_ = yaml.Unmarshal(objManifest, &obj)

	verified := false
	signerName := ""
	var err error

	// use resourceBundleRef if specified in the annotation; otherwise follow the verify option
	resBundleRefAnnotationKey := vo.AnnotationConfig.ResourceBundleRefAnnotationKey()
	annotations := obj.GetAnnotations()
	if annoImageRef, found := annotations[resBundleRefAnnotationKey]; found {
		vo.ImageRef = annoImageRef
	}

	// add signature/message/others annotations to ignore fields
	if vo != nil {
		vo.SetAnnotationIgnoreFields()
	}
	// get ignore fields configuration for this resource if found
	ignoreFields := []string{}
	if vo != nil {
		if ok, fields := vo.IgnoreFields.Match(obj); ok {
			ignoreFields = fields
		}
	}

	var resourceManifests [][]byte
	var sigRef string
	resourceManifests, sigRef, err = NewManifestFetcher(vo.ImageRef, vo.SignatureResourceRef, vo.AnnotationConfig, ignoreFields, vo.MaxResourceManifestNum).Fetch(objManifest)
	if err != nil {
		return nil, errors.Wrap(err, "reference YAML manifest not found for this manifest")
	}

	var mnfMatched bool
	var diff *mapnode.DiffResult
	var diffsForAllCandidates []*mapnode.DiffResult
	for i, candidate := range resourceManifests {
		log.Debugf("try matching with the candidate %v out of %v", i+1, len(resourceManifests))
		cndMatched, tmpDiff, err := matchManifest(objManifest, candidate, ignoreFields, vo.AnnotationConfig)
		if err != nil {
			return nil, errors.Wrap(err, "error occurred during matching manifest")
		}
		diffsForAllCandidates = append(diffsForAllCandidates, tmpDiff)
		if cndMatched {
			mnfMatched = true
			break
		}
	}
	if !mnfMatched && len(diffsForAllCandidates) > 0 {
		diff = diffsForAllCandidates[0]
	}

	var keyPath *string
	if vo.KeyPath != "" {
		keyPath = &(vo.KeyPath)
	}

	sigVerified, signerName, _, err := NewSignatureVerifier(objManifest, sigRef, keyPath, vo.AnnotationConfig).Verify()
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

func matchManifest(inputManifestBytes, foundManifestBytes []byte, ignoreFields []string, AnnotationConfig AnnotationConfig) (bool, *mapnode.DiffResult, error) {
	log.Debug("manifest:", string(inputManifestBytes))
	log.Debug("manifest in reference:", string(foundManifestBytes))
	inputFileNode, err := mapnode.NewFromYamlBytes(inputManifestBytes)
	if err != nil {
		return false, nil, err
	}
	annotationMask := AnnotationConfig.AnnotationKeyMask()
	maskedInputNode := inputFileNode.Mask(annotationMask)

	var obj unstructured.Unstructured
	err = yaml.Unmarshal(inputManifestBytes, &obj)
	if err != nil {
		return false, nil, err
	}

	manifestNode, err := mapnode.NewFromYamlBytes(foundManifestBytes)
	if err != nil {
		return false, nil, err
	}
	maskedManifestNode := manifestNode.Mask(annotationMask)
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
