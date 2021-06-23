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
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	k8ssigutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
	kubeutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util/kubeutil"
	mapnode "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util/mapnode"
)

const defaultDryRunNamespace = "default"

var CommonResourceMaskKeys = []string{
	fmt.Sprintf("metadata.annotations.\"%s\"", ImageRefAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", SignatureAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", CertificateAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", MessageAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", BundleAnnotationKey),
	"metadata.annotations.namespace",
	"metadata.annotations.kubectl.\"kubernetes.io/last-applied-configuration\"",
	"metadata.managedFields",
	"metadata.creationTimestamp",
	"metadata.generation",
	"metadata.annotations.deprecated.daemonset.template.generation",
	"metadata.namespace",
	"metadata.resourceVersion",
	"metadata.selfLink",
	"metadata.uid",
	"status",
}

type VerifyResourceResult struct {
	Object   unstructured.Unstructured `json:"-"`
	Verified bool                      `json:"verified"`
	InScope  bool                      `json:"inScope"`
	Signer   string                    `json:"signer"`
	Diff     *mapnode.DiffResult       `json:"diff"`
}

func (r *VerifyResourceResult) String() string {
	rB, _ := json.Marshal(r)
	return string(rB)
}

func VerifyResource(obj unstructured.Unstructured, imageRef, keyPath string, vo *VerifyOption) (*VerifyResourceResult, error) {

	verified := false
	inScope := true // assume that input resource is in scope in verify-resource
	signerName := ""

	// if imageRef is not specified in args and it is found in object annotations, use the found image ref
	if imageRef == "" {
		annotations := obj.GetAnnotations()
		annoImageRef, found := annotations[ImageRefAnnotationKey]
		if found {
			imageRef = annoImageRef
		}
	}

	// check if the resource should be skipped or not
	if vo != nil && len(vo.SkipObjects) > 0 {
		if vo.SkipObjects.Match(obj) {
			inScope = false
		}
	}

	// get ignore fields configuration for this resource if found
	ignoreFields := []string{}
	if vo != nil {
		if ok, fields := vo.IgnoreFields.Match(obj); ok {
			ignoreFields = fields
		}
	}

	// do manifest matching and signature verification
	// TODO: support directly attached annotation sigantures
	if imageRef != "" {
		image, err := k8ssigutil.PullImage(imageRef)
		if err != nil {
			return nil, errors.Wrap(err, "failed to pull image")
		}
		ok, tmpDiff, err := matchResourceWithManifest(obj, image, ignoreFields)
		if err != nil {
			return nil, errors.Wrap(err, "failed to match resource with manifest")
		}
		if !ok {
			return &VerifyResourceResult{
				Object:   obj,
				Verified: false,
				InScope:  inScope,
				Signer:   "",
				Diff:     tmpDiff,
			}, nil
		}
		verified, signerName, err = imageVerify(imageRef, &keyPath)
		if err != nil {
			return nil, errors.Wrap(err, "failed to verify image")
		}
		if verified {
			if !vo.Signers.Match(signerName) {
				verified = false
			}
		}
	}

	return &VerifyResourceResult{
		Object:   obj,
		Verified: verified,
		InScope:  inScope,
		Signer:   signerName,
	}, nil

}

func matchResourceWithManifest(obj unstructured.Unstructured, image v1.Image, ignoreFields []string) (bool, *mapnode.DiffResult, error) {

	apiVersion := obj.GetAPIVersion()
	kind := obj.GetKind()
	name := obj.GetName()
	namespace := obj.GetNamespace()

	concatYAMLFromImage, err := k8ssigutil.GenerateConcatYAMLsFromImage(image)
	if err != nil {
		return false, nil, err
	}
	log.Debug("obj: apiVersion", apiVersion, "kind", kind, "name", name)
	log.Debug("manifest in image:", string(concatYAMLFromImage))

	found, foundBytes := k8ssigutil.FindSingleYaml(concatYAMLFromImage, apiVersion, kind, name, namespace)
	if !found {
		return false, nil, errors.New("failed to find the corresponding manifest YAML file in image")
	}

	var matched bool
	var diff *mapnode.DiffResult
	objBytes, _ := json.Marshal(obj.Object)

	// CASE1: direct match
	matched, diff, err = directMatch(objBytes, foundBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "error occured during diract match")
	}
	if matched {
		return true, nil, nil
	}

	// CASE2: dryrun create match
	matched, diff, err = dryrunCreateMatch(objBytes, foundBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "error occured during dryrun create match")
	}
	if matched {
		return true, nil, nil
	}

	// CASE3: dryrun apply match
	matched, diff, err = dryrunApplyMatch(objBytes, foundBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "error occured during dryrun apply match")
	}
	if matched {
		return true, nil, nil
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

func directMatch(objBytes, manifestBytes []byte) (bool, *mapnode.DiffResult, error) {
	objNode, err := mapnode.NewFromBytes(objBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to initialize object node")
	}
	mnfNode, err := mapnode.NewFromYamlBytes(manifestBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to initialize manifest node")
	}
	maskedObjNode := objNode.Mask(CommonResourceMaskKeys)
	maskedMnfNode := mnfNode.Mask(CommonResourceMaskKeys)
	diff := maskedObjNode.Diff(maskedMnfNode)
	if diff == nil || diff.Size() == 0 {
		return true, nil, nil
	}
	return false, diff, nil
}

func dryrunCreateMatch(objBytes, manifestBytes []byte) (bool, *mapnode.DiffResult, error) {
	objNode, err := mapnode.NewFromBytes(objBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to initialize object node")
	}
	mnfNode, err := mapnode.NewFromYamlBytes(manifestBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to initialize manifest node")
	}
	nsMaskedManifestBytes := mnfNode.Mask([]string{"metadata.namespace"}).ToYaml()
	simBytes, err := kubeutil.DryRunCreate([]byte(nsMaskedManifestBytes), defaultDryRunNamespace)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to dryrun with the found YAML in image")
	}
	simNode, err := mapnode.NewFromYamlBytes(simBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to initialize dry-run-generated object node")
	}
	mask := CommonResourceMaskKeys
	mask = append(mask, "metadata.name") // name is overwritten for dryrun like `sample-configmap-dryrun`
	maskedObjNode := objNode.Mask(mask)
	maskedSimNode := simNode.Mask(mask)
	diff := maskedObjNode.Diff(maskedSimNode)
	if diff == nil || diff.Size() == 0 {
		return true, nil, nil
	}
	return false, diff, nil
}

func dryrunApplyMatch(objBytes, manifestBytes []byte) (bool, *mapnode.DiffResult, error) {
	objNode, err := mapnode.NewFromBytes(objBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to initialize object node")
	}
	objNamespace := objNode.GetString("metadata.namespace")
	_, patchedBytes, err := kubeutil.GetApplyPatchBytes(manifestBytes, objNamespace)
	if err != nil {
		return false, nil, errors.Wrap(err, "error during getting patched bytes")
	}
	patchedNode, _ := mapnode.NewFromBytes(patchedBytes)
	nsMaskedPatchedNode := patchedNode.Mask([]string{"metadata.namespace"})
	simPatchedObj, err := kubeutil.DryRunCreate([]byte(nsMaskedPatchedNode.ToYaml()), defaultDryRunNamespace)
	if err != nil {
		return false, nil, errors.Wrap(err, "error during DryRunCreate for Patch")
	}
	simNode, _ := mapnode.NewFromYamlBytes(simPatchedObj)
	mask := CommonResourceMaskKeys
	mask = append(mask, "metadata.name") // name is overwritten for dryrun like `sample-configmap-dryrun`
	maskedObjNode := objNode.Mask(mask)
	maskedSimNode := simNode.Mask(mask)
	diff := maskedObjNode.Diff(maskedSimNode)
	if diff == nil || diff.Size() == 0 {
		return true, nil, nil
	}
	return false, diff, nil

}

func dryrunPatchMatch(objBytes, manifestBytes []byte) (bool, *mapnode.DiffResult, error) {
	objNode, err := mapnode.NewFromBytes(objBytes)
	if err != nil {
		return false, nil, errors.Wrap(err, "failed to initialize object node")
	}
	patchedBytes, err := kubeutil.StrategicMergePatch(objBytes, manifestBytes, "")
	if err != nil {
		return false, nil, errors.Wrap(err, "error during getting patched bytes")
	}
	patchedNode, _ := mapnode.NewFromBytes(patchedBytes)
	nsMaskedPatchedNode := patchedNode.Mask([]string{"metadata.namespace"})
	simPatchedObj, err := kubeutil.DryRunCreate([]byte(nsMaskedPatchedNode.ToYaml()), defaultDryRunNamespace)
	if err != nil {
		return false, nil, errors.Wrap(err, "error during DryRunCreate for Patch:")
	}
	simNode, _ := mapnode.NewFromYamlBytes(simPatchedObj)
	mask := CommonResourceMaskKeys
	mask = append(mask, "metadata.name") // name is overwritten for dryrun like `sample-configmap-dryrun`
	maskedObjNode := objNode.Mask(mask)
	maskedSimNode := simNode.Mask(mask)
	diff := maskedObjNode.Diff(maskedSimNode)
	if diff == nil || diff.Size() == 0 {
		return true, nil, nil
	}
	return false, diff, nil
}
