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
	"time"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	k8ssigutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	kubeutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	mapnode "github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
)

const defaultDryRunNamespace = "default"

type VerifyResourceResult struct {
	Verified   bool                `json:"verified"`
	InScope    bool                `json:"inScope"`
	Signer     string              `json:"signer"`
	SignedTime *time.Time          `json:"signedTime"`
	SigRef     string              `json:"sigRef"`
	Diff       *mapnode.DiffResult `json:"diff"`
}

func (r *VerifyResourceResult) String() string {
	rB, _ := json.Marshal(r)
	return string(rB)
}

func VerifyResource(obj unstructured.Unstructured, vo *VerifyResourceOption) (*VerifyResourceResult, error) {

	objBytes, _ := yaml.Marshal(obj.Object)

	verified := false
	inScope := true // assume that input resource is in scope in verify-resource
	signerName := ""
	var signedTimestamp *int64
	sigRef := ""
	var err error

	imageRefString := ""
	if vo != nil {
		imageRefString = vo.ImageRef
	}

	// if imageRef is not specified in args and it is found in object annotations, use the found image ref
	if imageRefString == "" {
		annotations := obj.GetAnnotations()
		annoImageRef, found := annotations[ImageRefAnnotationKey]
		if found {
			imageRefString = annoImageRef
		}
	}

	// check if the resource should be skipped or not
	if vo != nil && len(vo.SkipObjects) > 0 {
		if vo.SkipObjects.Match(obj) {
			inScope = false
			return &VerifyResourceResult{InScope: false}, nil
		}
	}

	// get ignore fields configuration for this resource if found
	ignoreFields := []string{}
	if vo != nil {
		if ok, fields := vo.IgnoreFields.Match(obj); ok {
			ignoreFields = fields
		}
	}

	var manifestInRef []byte
	log.Debug("fetching manifest...")
	manifestInRef, sigRef, err = NewManifestFetcher(imageRefString).Fetch(objBytes)
	if err != nil {
		return nil, errors.Wrap(err, "YAML manifest not found for this resource")
	}

	log.Debug("matching object with manifest...")
	mnfMatched, diff, err := matchResourceWithManifest(obj, manifestInRef, ignoreFields, vo.CheckDryRunForApply)
	if err != nil {
		return nil, errors.Wrap(err, "error occurred during matching manifest")
	}

	if vo.SkipSignatureVerification {
		verified = mnfMatched
	} else {
		var keyPath *string
		if vo.KeyPath != "" {
			keyPath = &(vo.KeyPath)
		}

		var sigVerified bool
		log.Debug("verifying signature...")
		sigVerified, signerName, signedTimestamp, err = NewSignatureVerifier(objBytes, sigRef, keyPath).Verify()
		if err != nil {
			return nil, errors.Wrap(err, "failed to verify signature")
		}

	var sigVerified bool
	log.Debug("verifying signature...")
	sigVerified, signerName, signedTimestamp, err = NewSignatureVerifier(objBytes, sigRef, keyPath).Verify()
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify signature")
	}

	verified = mnfMatched && sigVerified && vo.Signers.Match(signerName)

	return &VerifyResourceResult{
		Verified:   verified,
		InScope:    inScope,
		Signer:     signerName,
		SignedTime: getTime(signedTimestamp),
		SigRef:     sigRef,
		Diff:       diff,
	}, nil
}

func matchResourceWithManifest(obj unstructured.Unstructured, manifestInImage []byte, ignoreFields []string, checkDryRunForApply bool) (bool, *mapnode.DiffResult, error) {

	apiVersion := obj.GetAPIVersion()
	kind := obj.GetKind()
	name := obj.GetName()
	namespace := obj.GetNamespace()
	clusterScope := false
	if namespace == "" {
		clusterScope = true
	}
	isCRD := kind == "CustomResourceDefinition"

	log.Debug("obj: apiVersion", apiVersion, "kind", kind, "name", name)
	log.Debug("manifest in image:", string(manifestInImage))

	found, foundBytes := k8ssigutil.FindSingleYaml(manifestInImage, apiVersion, kind, name, namespace)
	if !found {
		return false, nil, errors.New("failed to find the corresponding manifest YAML file in image")
	}

	var err error
	var matched bool
	var diff *mapnode.DiffResult
	objBytes, _ := json.Marshal(obj.Object)

	// CASE1: direct match
	log.Debug("try direct matching")
	matched, diff, err = directMatch(objBytes, foundBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "error occured during diract match")
	}
	if diff != nil && len(ignoreFields) > 0 {
		_, diff, _ = diff.Filter(ignoreFields)
	}
	if diff == nil || diff.Size() == 0 {
		matched = true
		diff = nil
	}
	if matched {
		return true, nil, nil
	}

	// CASE2: dryrun create match
	log.Debug("try dryrun create matching")
	matched, diff, err = dryrunCreateMatch(objBytes, foundBytes, clusterScope, isCRD)
	if err != nil {
		return false, nil, errors.Wrap(err, "error occured during dryrun create match")
	}
	if diff != nil && len(ignoreFields) > 0 {
		_, diff, _ = diff.Filter(ignoreFields)
	}
	if diff == nil || diff.Size() == 0 {
		matched = true
		diff = nil
	}
	if matched {
		return true, nil, nil
	}

	// CASE3: dryrun apply match
	if checkDryRunForApply {
		log.Debug("try dryrun apply matching")
		matched, diff, err = dryrunApplyMatch(objBytes, foundBytes, clusterScope, isCRD)
		if err != nil {
			return false, nil, errors.Wrap(err, "error occured during dryrun apply match")
		}
		if diff != nil && len(ignoreFields) > 0 {
			_, diff, _ = diff.Filter(ignoreFields)
		}
		if diff == nil || diff.Size() == 0 {
			matched = true
			diff = nil
		}
		if matched {
			return true, nil, nil
		}
	}

	// TODO: handle patch case
	// // CASE4: dryrun patch match
	// matched, diff, err = dryrunPatchMatch(objBytes, foundBytes)
	// if err != nil {
	// 	return false, errors.Wrap(err, "error occured during dryrun patch match")
	// }
	// if matched {
	// 	return true, nil
	// }

	return false, diff, nil
}

func directMatch(objBytes, manifestBytes []byte) (bool, *mapnode.DiffResult, error) {
	objNode, err := mapnode.NewFromBytes(objBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to initialize object node")
	}
	mnfNode, err := mapnode.NewFromYamlBytes(manifestBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to initialize manifest node")
	}
	diff := objNode.Diff(mnfNode)
	if diff == nil || diff.Size() == 0 {
		return true, nil, nil
	}
	return false, diff, nil
}

func dryrunCreateMatch(objBytes, manifestBytes []byte, clusterScope, isCRD bool) (bool, *mapnode.DiffResult, error) {
	objNode, err := mapnode.NewFromBytes(objBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to initialize object node")
	}
	mnfNode, err := mapnode.NewFromYamlBytes(manifestBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to initialize manifest node")
	}
	nsMaskedManifestBytes := mnfNode.Mask([]string{"metadata.namespace"}).ToYaml()
	var simBytes []byte
	if clusterScope {
		simBytes, err = kubeutil.DryRunCreate([]byte(nsMaskedManifestBytes), "")
	} else {
		simBytes, err = kubeutil.DryRunCreate([]byte(nsMaskedManifestBytes), defaultDryRunNamespace)
	}
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to dryrun with the found YAML in image")
	}
	simNode, err := mapnode.NewFromYamlBytes(simBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to initialize dry-run-generated object node")
	}
	mask := []string{}
	mask = append(mask, "metadata.name") // name is overwritten for dryrun like `sample-configmap-dryrun`
	if !clusterScope {
		mask = append(mask, "metadata.namespace") // namespace is overwritten for dryrun
	}
	if isCRD {
		mask = append(mask, "spec.names.kind")
		mask = append(mask, "spec.names.listKind")
		mask = append(mask, "spec.names.singular")
		mask = append(mask, "spec.names.plural")
	}
	maskedObjNode := objNode.Mask(mask)
	maskedSimNode := simNode.Mask(mask)
	diff := maskedObjNode.Diff(maskedSimNode)
	if diff == nil || diff.Size() == 0 {
		return true, nil, nil
	}
	return false, diff, nil
}

func dryrunApplyMatch(objBytes, manifestBytes []byte, clusterScope, isCRD bool) (bool, *mapnode.DiffResult, error) {
	objNode, err := mapnode.NewFromBytes(objBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to initialize object node")
	}
	objNamespace := objNode.GetString("metadata.namespace")
	_, patchedBytes, err := kubeutil.GetApplyPatchBytes(manifestBytes, objNamespace)
	if err != nil {
		return false, nil, errors.Wrap(err, "error during getting applied bytes")
	}
	patchedNode, _ := mapnode.NewFromBytes(patchedBytes)
	nsMaskedPatchedNode := patchedNode.Mask([]string{"metadata.namespace"})
	var simPatchedObj []byte
	if clusterScope {
		simPatchedObj, err = kubeutil.DryRunCreate([]byte(nsMaskedPatchedNode.ToYaml()), "")
	} else {
		simPatchedObj, err = kubeutil.DryRunCreate([]byte(nsMaskedPatchedNode.ToYaml()), defaultDryRunNamespace)
	}
	if err != nil {
		return false, nil, errors.Wrap(err, "error during DryRunCreate for apply")
	}
	simNode, _ := mapnode.NewFromYamlBytes(simPatchedObj)
	mask := []string{}
	mask = append(mask, "metadata.name") // name is overwritten for dryrun like `sample-configmap-dryrun`
	if !clusterScope {
		mask = append(mask, "metadata.namespace") // namespace is overwritten for dryrun
	}
	if isCRD {
		mask = append(mask, "spec.names.kind")
		mask = append(mask, "spec.names.listKind")
		mask = append(mask, "spec.names.singular")
		mask = append(mask, "spec.names.plural")
	}
	maskedObjNode := objNode.Mask(mask)
	maskedSimNode := simNode.Mask(mask)
	diff := maskedObjNode.Diff(maskedSimNode)
	if diff == nil || diff.Size() == 0 {
		return true, nil, nil
	}
	return false, diff, nil

}

func getTime(tstamp *int64) *time.Time {
	if tstamp == nil {
		return nil
	}
	t := time.Unix(*tstamp, 0)
	return &t
}
