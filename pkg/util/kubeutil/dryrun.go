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

package kubeutil

import (
	"bytes"
	"context"

	// "context"
	"encoding/json"
	"fmt"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	oapi "k8s.io/kube-openapi/pkg/util/proto"
	"k8s.io/kubectl/pkg/scheme"
	"k8s.io/kubectl/pkg/util"
	"k8s.io/kubectl/pkg/util/openapi"
)

func DryRunCreate(objBytes []byte, namespace string) ([]byte, error) {
	config, err := GetKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("Error in getting k8s config; %s", err.Error())
	}
	dyClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("Error in creating DynamicClient; %s", err.Error())
	}

	obj := &unstructured.Unstructured{}
	objJsonBytes, err := yaml.YAMLToJSON(objBytes)
	if err != nil {
		return nil, fmt.Errorf("Error in converting YamlToJson; %s", err.Error())
	}
	err = obj.UnmarshalJSON(objJsonBytes)
	if err != nil {
		return nil, fmt.Errorf("Error in Unmarshal into unstructured obj; %s", err.Error())
	}
	gvk := obj.GroupVersionKind()

	if gvk.Kind == "CustomResourceDefinition" {
		var crdObj map[string]interface{}
		err := json.Unmarshal(objJsonBytes, &crdObj)
		if err == nil {
			specMapIf, _ := crdObj["spec"]
			specMap, _ := specMapIf.(map[string]interface{})
			namesMapIf, _ := specMap["names"]
			namesMap, _ := namesMapIf.(map[string]interface{})
			if namesMap["kind"] != nil {
				namesMap["kind"] = "Sim" + namesMap["kind"].(string)
			}
			if namesMap["listKind"] != nil {
				namesMap["listKind"] = "Sim" + namesMap["listKind"].(string)
			}
			if namesMap["singular"] != nil {
				namesMap["singular"] = "sim" + namesMap["singular"].(string)
			}
			if namesMap["plural"] != nil {
				namesMap["plural"] = "sim" + namesMap["plural"].(string)
			}
			specMap["names"] = namesMap
			crdObj["spec"] = specMap

			metaMapIf, _ := crdObj["metadata"]
			metaMap, _ := metaMapIf.(map[string]interface{})
			if metaMap["name"] != nil {
				metaMap["name"] = "sim" + metaMap["name"].(string)
			}
			crdObj["metadata"] = metaMap

			crdObjBytes, err := json.Marshal(crdObj)
			if err == nil {
				tmpObj := &unstructured.Unstructured{}
				err = tmpObj.UnmarshalJSON(crdObjBytes)
				if err == nil {
					obj = tmpObj
				}
			}
		}
	} else {
		obj.SetName(fmt.Sprintf("%s-dry-run", obj.GetName()))
	}

	gvr, _ := meta.UnsafeGuessKindToResource(gvk)
	gvClient := dyClient.Resource(gvr)

	var simObj *unstructured.Unstructured
	if namespace == "" {
		simObj, err = gvClient.Create(context.Background(), obj, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	} else {
		simObj, err = gvClient.Namespace(namespace).Create(context.Background(), obj, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	}
	if err != nil {
		return nil, fmt.Errorf("Error in creating resource; %s, gvk: %s", err.Error(), gvk)
	}
	simObjBytes, err := yaml.Marshal(simObj)
	if err != nil {
		return nil, fmt.Errorf("Error in converting ojb to yaml; %s", err.Error())
	}
	return simObjBytes, nil
}

func StrategicMergePatch(objBytes, patchBytes []byte, namespace string) ([]byte, error) {
	config, err := GetKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("Error in getting k8s config; %s", err.Error())
	}
	dyClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("Error in creating DynamicClient; %s", err.Error())
	}

	obj := &unstructured.Unstructured{}
	err = obj.UnmarshalJSON(objBytes)
	if err != nil {
		return nil, fmt.Errorf("Error in Unmarshal into unstructured obj; %s", err.Error())
	}
	gvk := obj.GroupVersionKind()
	gvr, _ := meta.UnsafeGuessKindToResource(gvk)
	gvClient := dyClient.Resource(gvr)
	claimedNamespace := obj.GetNamespace()
	claimedName := obj.GetName()
	if namespace != "" && claimedNamespace != "" && namespace != claimedNamespace {
		return nil, fmt.Errorf("namespace is not identical, requested: %s, defined in yaml: %s", namespace, claimedNamespace)
	}
	if namespace == "" && claimedNamespace != "" {
		namespace = claimedNamespace
	}

	var currentObj *unstructured.Unstructured
	if namespace == "" {
		currentObj, err = gvClient.Get(context.Background(), claimedName, metav1.GetOptions{})
	} else {
		currentObj, err = gvClient.Namespace(namespace).Get(context.Background(), claimedName, metav1.GetOptions{})
	}
	if err != nil && !k8serrors.IsNotFound(err) {
		return nil, fmt.Errorf("Error in getting current obj; %s", err.Error())
	}
	currentObjBytes, err := json.Marshal(currentObj)
	if err != nil {
		return nil, fmt.Errorf("Error in converting current obj to json; %s", err.Error())
	}
	creator := scheme.Scheme
	if !creator.Recognizes(gvk) {
		creator.AddKnownTypeWithName(gvk, obj)
	}
	mocObj, err := creator.New(gvk)
	if err != nil {
		return nil, fmt.Errorf("Error in getting moc obj; %s", err.Error())
	}
	patchJsonBytes, err := yaml.YAMLToJSON(patchBytes)
	if err != nil {
		return nil, fmt.Errorf("Error in converting patchBytes to json; %s", err.Error())
	}
	patchedBytes, err := strategicpatch.StrategicMergePatch(currentObjBytes, patchJsonBytes, mocObj)
	if err != nil {
		return nil, fmt.Errorf("Error in getting patched obj bytes; %s", err.Error())
	}
	return patchedBytes, nil
}

func GetApplyPatchBytes(manifestBytes []byte, objNamespace string) ([]byte, []byte, error) {
	config, err := GetKubeConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("Error in getting k8s config; %s", err.Error())
	}
	dyClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in creating DynamicClient; %s", err.Error())
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in creating DiscoveryClient; %s", err.Error())
	}
	openAPISchemaDoc, err := discoveryClient.OpenAPISchema()
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get OpenAPISchema Document; %s", err.Error())
	}
	openAPISchema, err := openapi.NewOpenAPIData(openAPISchemaDoc)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to get OpenAPISchema; %s", err.Error())
	}

	mnfObj := &unstructured.Unstructured{}
	manifestJsonBytes, err := yaml.YAMLToJSON(manifestBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in converting YamlToJson; %s", err.Error())
	}
	err = mnfObj.UnmarshalJSON(manifestJsonBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in Unmarshal into unstructured obj; %s", err.Error())
	}
	gvk := mnfObj.GroupVersionKind()
	gvr, _ := meta.UnsafeGuessKindToResource(gvk)
	gvClient := dyClient.Resource(gvr)
	claimedNamespace := mnfObj.GetNamespace()
	claimedName := mnfObj.GetName()
	if objNamespace != "" && claimedNamespace != "" && objNamespace != claimedNamespace {
		objNamespace = claimedNamespace
	}
	if objNamespace == "" && claimedNamespace != "" {
		objNamespace = claimedNamespace
	}

	var currentObj *unstructured.Unstructured
	if objNamespace == "" {
		currentObj, err = gvClient.Get(context.Background(), claimedName, metav1.GetOptions{})
	} else {
		currentObj, err = gvClient.Namespace(objNamespace).Get(context.Background(), claimedName, metav1.GetOptions{})
	}
	if err != nil && !k8serrors.IsNotFound(err) {
		return nil, nil, fmt.Errorf("Error in getting current obj; %s", err.Error())
	}
	currentObjBytes, err := json.Marshal(currentObj)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in converting current obj to json; %s", err.Error())
	}
	//sourceFileName := "/tmp/obj.yaml"
	var originalObjBytes []byte
	if currentObj != nil {
		originalObjBytes, err = util.GetOriginalConfiguration(currentObj)
		if err != nil {
			return nil, nil, errors.Wrap(err, fmt.Sprintf("error while retrieving original configuration from:\n%v\n", mnfObj))
		}
	}
	modifiedBytes, err := util.GetModifiedConfiguration(mnfObj, true, unstructured.UnstructuredJSONScheme)
	if err != nil {
		return nil, nil, errors.Wrap(err, fmt.Sprintf("error while retrieving modified configuration from:\n%s\n", claimedName))
	}

	var patch []byte
	var lookupPatchMeta strategicpatch.LookupPatchMeta
	var schema oapi.Schema
	overwrite := true
	errout := bytes.NewBufferString("")
	createPatchErrFormat := "creating patch with:\noriginal:\n%s\nmodified:\n%s\ncurrent:\n%s\nfor:"
	creator := scheme.Scheme
	if !creator.Recognizes(gvk) {
		creator.AddKnownTypeWithName(gvk, mnfObj)
	}
	versionedObject, err := creator.New(gvk)

	if openAPISchema != nil {
		if schema = openAPISchema.LookupResource(mnfObj.GroupVersionKind()); schema != nil {
			lookupPatchMeta = strategicpatch.PatchMetaFromOpenAPI{Schema: schema}
			if openapiPatch, err := strategicpatch.CreateThreeWayMergePatch(originalObjBytes, modifiedBytes, currentObjBytes, lookupPatchMeta, overwrite); err != nil {
				fmt.Fprintf(errout, "warning: error calculating patch from openapi spec: %v\n", err)
			} else {
				patch = openapiPatch
			}
		}
	}

	if patch == nil {
		lookupPatchMeta, err = strategicpatch.NewPatchMetaFromStruct(versionedObject)
		if err != nil {
			return nil, nil, errors.Wrap(err, fmt.Sprintf(createPatchErrFormat, originalObjBytes, modifiedBytes, currentObjBytes))
		}
		patch, err = strategicpatch.CreateThreeWayMergePatch(originalObjBytes, modifiedBytes, currentObjBytes, lookupPatchMeta, overwrite)
		if err != nil {
			return nil, nil, errors.Wrap(err, fmt.Sprintf(createPatchErrFormat, originalObjBytes, modifiedBytes, currentObjBytes))
		}
	}

	if err != nil {
		return nil, nil, fmt.Errorf("Error in getting moc obj; %s", err.Error())
	}
	patched, err := strategicpatch.StrategicMergePatchUsingLookupPatchMeta(currentObjBytes, patch, lookupPatchMeta)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in patching to obj; %s", err.Error())
	}
	patchedObj := &unstructured.Unstructured{}
	err = patchedObj.UnmarshalJSON(patched)
	if err != nil {
		return nil, nil, fmt.Errorf("Error in Unmarshal into unstructured obj; %s", err.Error())
	}
	patchedObjBytes, _ := json.Marshal(patchedObj)
	return patch, patchedObjBytes, nil
}
