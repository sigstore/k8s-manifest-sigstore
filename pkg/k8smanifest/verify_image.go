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
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/pkg/errors"
	kubeutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
)

type VerifyImageResult struct {
	Images []SingleImageResult `json:"images"`

	numInScopeImages  int `json:"-"`
	numVerifiedImages int `json:"-"`
}

type SingleImageResult struct {
	kubeutil.ImageObject `json:""`
	Verified             bool       `json:"verified"`
	InScope              bool       `json:"inScope"`
	Signer               string     `json:"signer"`
	SignedTime           *time.Time `json:"signedTime"`
	FailedReason         string     `json:"failedReason"`
}

// verify all images inside a specified resource object
// e.g.) if obj is a Pod, list all the container images in the Pod and try verifying signatures of them
func VerifyImage(obj unstructured.Unstructured, vo *VerifyImageOption) (*VerifyImageResult, error) {
	images, err := kubeutil.GetAllImagesFromObject(&obj)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get images in object")
	}
	if vo == nil {
		return nil, errors.New("VerifyImageOption must be non-nil value")
	}
	results := []SingleImageResult{}
	numInScope := 0
	numVerified := 0
	for _, img := range images {
		inScope := vo.InScopeImages.Match(img.ImageRef)
		if !inScope {
			r := SingleImageResult{
				ImageObject: img,
				InScope:     false,
			}
			results = append(results, r)
			continue
		}
		var keyPath *string
		if vo.KeyPath != "" {
			keyPath = &(vo.KeyPath)
		}
		verifier := NewSignatureVerifier(nil, img.ImageRef, keyPath, AnnotationConfig{})
		imageVerifier, ok := verifier.(*ImageSignatureVerifier)
		if !ok {
			return nil, fmt.Errorf("failed to initialize image verifier for %s", img.ImageRef)
		}
		sigVerified, signerName, _, err := imageVerifier.Verify()
		failedReason := ""
		if !sigVerified && err != nil {
			failedReason = err.Error()
		}
		signerOk := true
		if sigVerified {
			signerOk = vo.Signers.Match(signerName)
		}
		verified := sigVerified && signerOk

		if inScope {
			numInScope += 1
		}
		if verified {
			numVerified += 1
		}
		r := SingleImageResult{
			ImageObject:  img,
			Verified:     verified,
			InScope:      true,
			Signer:       signerName,
			FailedReason: failedReason,
		}
		results = append(results, r)
	}

	verifyResult := &VerifyImageResult{
		Images:            results,
		numInScopeImages:  numInScope,
		numVerifiedImages: numVerified,
	}
	return verifyResult, nil
}

func (r *VerifyImageResult) Verified() bool {
	return r.numInScopeImages == r.numVerifiedImages
}

func (r *VerifyImageResult) ImageFound() bool {
	return len(r.Images) > 0
}
