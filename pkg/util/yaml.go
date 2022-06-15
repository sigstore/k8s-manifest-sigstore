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

package util

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sort"

	goyaml "gopkg.in/yaml.v2"

	"github.com/ghodss/yaml"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

const defaultmaxResourceManifestsNum = 3

type ResourceInfo struct {
	group     string
	version   string
	kind      string
	name      string
	namespace string
	raw       []byte
}

func (ri ResourceInfo) Map() map[string]string {
	m := map[string]string{}
	m["group"] = ri.group
	m["version"] = ri.version
	m["kind"] = ri.kind
	m["namespace"] = ri.namespace
	m["name"] = ri.name
	return m
}

func FindYAMLsInDir(dirPath string) ([][]byte, error) {

	foundYAMLs := [][]byte{}
	err := filepath.Walk(dirPath, func(fpath string, info os.FileInfo, err error) error {
		if err == nil && (path.Ext(info.Name()) == ".yaml" || path.Ext(info.Name()) == ".yml") {
			yamlBytes, err := ioutil.ReadFile(fpath)
			if err == nil && isK8sResourceYAML(yamlBytes) {
				foundYAMLs = append(foundYAMLs, yamlBytes)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return foundYAMLs, nil
}

func LoadYAMLsInDirWithMutationOptions(dirPath string, moList ...*MutateOptions) ([][]byte, error) {
	yamls, err := FindYAMLsInDir(dirPath)
	if err != nil {
		return nil, err
	}
	mYamls := [][]byte{}
	for _, yaml := range yamls {
		mYaml := yaml
		for _, mo := range moList {
			if mo == nil {
				continue
			}
			mYaml, err = mo.AW(mYaml, mo.Annotations)
			if err != nil {
				return nil, err
			}
		}
		mYamls = append(mYamls, mYaml)
	}
	return mYamls, nil
}

// Out of `concatYamlBytes`, find YAML manifests that are corresponding to the `objBytes`.
// `maxResourceManifestNum` determines how many candidate manifests can be returned. If empty, default to 3.
// `ignoreFields` is used for value based search, the specified fields are ignored on the comparison.
func FindManifestYAML(concatYamlBytes, objBytes []byte, maxResourceManifestNum *int, ignoreFields []string) (bool, [][]byte) {
	var obj *unstructured.Unstructured
	err := yaml.Unmarshal(objBytes, &obj)
	if err != nil {
		log.Debugf("failed to unmarshal object: %s", err.Error())
		return false, nil
	}
	apiVersion := obj.GetAPIVersion()
	kind := obj.GetKind()
	name := obj.GetName()
	namespace := obj.GetNamespace()

	// extract candidate manifests that have an identical kind with object
	candidateManifestBytes := extractKindMatchedManifests(concatYamlBytes, kind)
	if candidateManifestBytes == nil {
		log.Debugf("failed to find candidates that has kind: %s", kind)
		return false, nil
	}

	// gvk/name/namespace-based detection
	found, foundBytes := ManifestSearchByGVKNameNamespace(candidateManifestBytes, apiVersion, kind, name, namespace)
	if found {
		return found, [][]byte{foundBytes}
	}
	// value-based detection
	var foundCandidateBytes [][]byte
	found, foundCandidateBytes = ManifestSearchByValue(candidateManifestBytes, objBytes, maxResourceManifestNum, ignoreFields)
	return found, foundCandidateBytes
}

func ManifestSearchByGVKNameNamespace(concatYamlBytes []byte, apiVersion, kind, name, namespace string) (bool, []byte) {
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return false, nil
	}
	reqInfos := map[string]string{}
	reqInfos["group"] = gv.Group
	reqInfos["version"] = gv.Version
	reqInfos["kind"] = kind
	reqInfos["namespace"] = namespace
	reqInfos["name"] = name

	resourcesInConcatYaml := parseResourceInfo(concatYamlBytes)
	matchedItems := []ResourceInfo{}
	for _, ri := range resourcesInConcatYaml {
		msgInfo := ri.Map()
		if matchResourceInfo(msgInfo, reqInfos, []string{"group", "kind", "name"}) {
			matchedItems = append(matchedItems, ri)
		}
	}
	if len(matchedItems) == 0 {
		return false, nil
	}
	if len(matchedItems) == 1 {
		return true, matchedItems[0].raw
	}

	matchedItems2 := []ResourceInfo{}
	for _, ri := range resourcesInConcatYaml {
		msgInfo := ri.Map()
		if matchResourceInfo(msgInfo, reqInfos, []string{"group", "kind", "name", "namespace"}) {
			matchedItems2 = append(matchedItems2, ri)
		}
	}
	if len(matchedItems2) == 0 {
		return true, matchedItems[0].raw
	} else {
		return true, matchedItems2[0].raw
	}
}

type candidateManifest struct {
	yaml  []byte
	table map[string]interface{}
	count int
	name  string
}

func ManifestSearchByValue(concatYamlBytes, objBytes []byte, maxResourceManifests *int, ignoreFields []string) (bool, [][]byte) {
	var maxResourceManifestsNum int
	if maxResourceManifests == nil {
		maxResourceManifestsNum = defaultmaxResourceManifestsNum
	} else {
		maxResourceManifestsNum = *maxResourceManifests
	}

	objNode, err := mapnode.NewFromYamlBytes(objBytes)
	if err != nil {
		log.Debug("failed to create a new node from objBytes:", err.Error())
		return false, nil
	}
	maskedObjNode := objNode.Mask(ignoreFields)
	objTableMap := maskedObjNode.Ravel()

	objKeyValArray := [][2]string{}
	for key, val := range objTableMap {
		keyVal := [2]string{key, fmt.Sprintf("%v", val)}
		objKeyValArray = append(objKeyValArray, keyVal)
	}
	// sort keys by length of value string in descending order
	// because a field which has longer value could be more important field to identify manifest
	// e.g.) `spec.templates.spec.containers[].image: sample-registry/smaple-image-name:sample-image-tag` is more unique than `spec.replicas: 1`
	sort.Slice(objKeyValArray, func(i, j int) bool { return len(objKeyValArray[i][1]) > len(objKeyValArray[j][1]) })

	yamls := SplitConcatYAMLs(concatYamlBytes)
	candidates := []candidateManifest{}
	for _, mnfBytes := range yamls {
		mnfNode, err := mapnode.NewFromYamlBytes(mnfBytes)
		if err != nil {
			log.Debug("failed to create a new node from mnfBytes:", err.Error())
			return false, nil
		}
		mnfName := mnfNode.GetString("metadata.name")
		maskedMnfNode := mnfNode.Mask(ignoreFields)
		mnfTableMap := maskedMnfNode.Ravel()
		candidates = append(candidates, candidateManifest{
			yaml:  mnfBytes,
			table: mnfTableMap,
			count: 0,
			name:  mnfName,
		})
	}

	matchedCandNumInLastLoop := -1
	loopCountWithSameMatchedCandNum := 0
	for i, keyVal := range objKeyValArray {
		keyInObj := keyVal[0]
		valInObj := keyVal[1]
		matchedCandNumForThisKey := 0
		for j := range candidates {
			valIf, keyFound := candidates[j].table[keyInObj]
			var valInMnf string
			if keyFound {
				valInMnf = fmt.Sprintf("%v", valIf)
			}
			if keyFound && valInObj == valInMnf {
				candidates[j].count += 1
				matchedCandNumForThisKey += 1
			}
		}
		// loop exit conditions
		// if these conditions are not satisfied during the loop, just use all key/values in manifests
		if i > len(objKeyValArray)/10.0 && matchedCandNumForThisKey > 0 && matchedCandNumForThisKey < maxResourceManifestsNum {
			if matchedCandNumForThisKey == matchedCandNumInLastLoop {
				loopCountWithSameMatchedCandNum += 1
			} else {
				loopCountWithSameMatchedCandNum = 0
			}
		}
		if loopCountWithSameMatchedCandNum > len(objKeyValArray)/10.0 {
			break
		}
		matchedCandNumInLastLoop = matchedCandNumForThisKey
	}

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].count > candidates[j].count })

	for _, cand := range candidates {
		log.Debugf("candidate name %s, count %v", cand.name, cand.count)
	}

	narrowedCandidatesBasedOnCount := []candidateManifest{}
	maxCount := candidates[0].count
	for i := range candidates {
		if candidates[i].count == maxCount {
			narrowedCandidatesBasedOnCount = append(narrowedCandidatesBasedOnCount, candidates[i])
		}
	}
	if len(narrowedCandidatesBasedOnCount) > maxResourceManifestsNum {
		narrowedCandidatesBasedOnCount = narrowedCandidatesBasedOnCount[:maxResourceManifestsNum]
	}
	for _, cand := range narrowedCandidatesBasedOnCount {
		log.Debugf("final candidate name %s, count %v", cand.name, cand.count)
	}

	candidateBytes := [][]byte{}
	for _, c := range narrowedCandidatesBasedOnCount {
		candidateBytes = append(candidateBytes, c.yaml)
	}
	found := len(candidateBytes) > 0

	return found, candidateBytes
}

func extractKindMatchedManifests(concatYamlBytes []byte, kind string) []byte {
	yamls := SplitConcatYAMLs(concatYamlBytes)
	kindMatchedYAMLs := [][]byte{}
	for _, manifest := range yamls {
		var mnfObj *unstructured.Unstructured
		err := yaml.Unmarshal(manifest, &mnfObj)
		if err != nil {
			continue
		}
		mnfKind := mnfObj.GetKind()
		if kind == mnfKind {
			kindMatchedYAMLs = append(kindMatchedYAMLs, manifest)
		}
	}

	if len(kindMatchedYAMLs) == 0 {
		return nil
	}

	candidateManifestBytes := ConcatenateYAMLs(kindMatchedYAMLs)
	return candidateManifestBytes
}

func ConcatenateYAMLs(yamls [][]byte) []byte {
	concatYamls := ""
	for i, y := range yamls {
		concatYamls = fmt.Sprintf("%s%s", concatYamls, string(y))
		if i < len(yamls)-1 {
			concatYamls = fmt.Sprintf("%s\n---\n", concatYamls)
		}
	}
	return []byte(concatYamls)
}

func IsConcatYAMLs(yaml []byte) bool {
	yamls := SplitConcatYAMLs(yaml)
	return len(yamls) > 1
}

func SplitConcatYAMLs(yaml []byte) [][]byte {
	yamls := [][]byte{}
	r := bytes.NewReader(yaml)
	dec := k8syaml.NewYAMLToJSONDecoder(r)
	var t interface{}
	for dec.Decode(&t) == nil {
		tB, err := goyaml.Marshal(t)
		if err != nil {
			continue
		}
		yamls = append(yamls, tB)
	}
	return yamls
}

func GetAnnotationsInYAML(yamlBytes []byte) map[string]string {
	emptyMap := map[string]string{}
	var obj unstructured.Unstructured
	err := yaml.Unmarshal(yamlBytes, &obj)
	if err != nil {
		return emptyMap
	}
	return obj.GetAnnotations()
}

func parseResourceInfo(concatYamlBytes []byte) []ResourceInfo {
	yamls := SplitConcatYAMLs(concatYamlBytes)
	resources := []ResourceInfo{}
	for _, yamlBytes := range yamls {
		var obj *unstructured.Unstructured
		_ = yaml.Unmarshal(yamlBytes, &obj)
		if obj == nil {
			continue
		}
		resources = append(resources, ResourceInfo{
			group:     obj.GroupVersionKind().Group,
			version:   obj.GroupVersionKind().Version,
			kind:      obj.GetKind(),
			name:      obj.GetName(),
			namespace: obj.GetNamespace(),
			raw:       yamlBytes,
		})
	}

	return resources
}

func matchResourceInfo(msgInfos, reqInfos map[string]string, useKeys []string) bool {
	keyCount := len(useKeys)
	matchedCount := 0
	for _, key := range useKeys {
		mval := msgInfos[key]
		rval := reqInfos[key]
		if mval == rval {
			matchedCount += 1
		}
	}
	matched := false
	if keyCount == matchedCount && matchedCount > 0 {
		matched = true
	}
	return matched
}

func isK8sResourceYAML(data []byte) bool {
	var obj *unstructured.Unstructured
	err := yaml.Unmarshal(data, &obj)
	return err == nil
}
