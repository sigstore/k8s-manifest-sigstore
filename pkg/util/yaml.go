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
	"math"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	goyaml "gopkg.in/yaml.v2"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

var defaultSimilarityThreshold = 0.85

// weight for calculating a similarity value
// all other fields that are not defined here will have weight 1.0
// more weight-ed fields contribute more to a similarity value
var defaultSimilarityWeight map[string]float64 = map[string]float64{
	"metadata.managedFields": 0.1,
	"status":                 0.1,
	"spec":                   1.5,
}

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

func FindManifestYAML(concatYamlBytes, objBytes []byte) (bool, []byte) {
	var obj *unstructured.Unstructured
	err := yaml.Unmarshal(objBytes, &obj)
	if err != nil {
		return false, nil
	}
	apiVersion := obj.GetAPIVersion()
	kind := obj.GetKind()
	name := obj.GetName()
	namespace := obj.GetNamespace()
	// manifest search by gvk/name/namespace
	found, foundBytes := FindSingleYaml(concatYamlBytes, apiVersion, kind, name, namespace)
	if found {
		return found, foundBytes
	}
	// similarity based search
	// TODO: add some control here?
	found, foundBytes, _ = SimilarityBasedFindManifestYAML(concatYamlBytes, objBytes, nil, nil)
	return found, foundBytes
}

func FindSingleYaml(concatYamlBytes []byte, apiVersion, kind, name, namespace string) (bool, []byte) {
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

func SimilarityBasedFindManifestYAML(concatYamlBytes, objBytes []byte, threshold *float64, similarityWeight map[string]float64) (bool, []byte, float64) {
	var thresholdNum float64
	if threshold == nil {
		thresholdNum = defaultSimilarityThreshold
	} else {
		thresholdNum = *threshold
	}
	if thresholdNum < 0.0 || thresholdNum > 1.0 {
		return false, nil, -1.0
	}

	yamls := SplitConcatYAMLs(concatYamlBytes)

	found := false
	var foundBytes []byte
	maxSimilarity := -1.0
	for _, mnfBytes := range yamls {
		sim, err := GetSimilarityOfTwoYamls(mnfBytes, objBytes, similarityWeight)
		if err != nil {
			log.Debug("similarity calculation error (most of errors are normal cases here): ", err.Error())
			continue
		}
		log.Debug("sim: ", sim)
		log.Debug("manifest: ", string(mnfBytes))
		log.Debug("object: ", string(objBytes))
		if sim > thresholdNum && sim > maxSimilarity {
			found = true
			foundBytes = mnfBytes
			maxSimilarity = sim
		}
	}

	return found, foundBytes, maxSimilarity
}

func GetSimilarityOfTwoYamls(a, b []byte, similarityWeight map[string]float64) (float64, error) {
	var nodeA, nodeB *mapnode.Node
	var err error
	nodeA, err = mapnode.NewFromYamlBytes(a)
	if err != nil {
		return -1.0, err
	}
	nodeB, err = mapnode.NewFromYamlBytes(b)
	if err != nil {
		return -1.0, err
	}
	aKind := nodeA.GetString("kind")
	bKind := nodeB.GetString("kind")
	if aKind != bKind {
		return -1.0, errors.New("kinds are different")
	}
	aFieldMap := nodeA.Ravel()
	bFieldMap := nodeB.Ravel()
	if len(aFieldMap) <= 10 || len(bFieldMap) <= 10 {
		return -1.0, errors.New("too few attributes in the objects to calculate cosine similarity")
	}

	aVector, bVector := makeVectorsForTwoNodes(nodeA, nodeB, similarityWeight)
	similarity := calculateCosineSimilarity(aVector, bVector)

	return similarity, nil
}

func makeVectorsForTwoNodes(a, b *mapnode.Node, similarityWeight map[string]float64) ([]float64, []float64) {
	aFieldMap := a.Ravel()
	bFieldMap := b.Ravel()

	aFields := map[string]bool{}
	bFields := map[string]bool{}
	for key, val := range aFieldMap {
		f := fmt.Sprintf("%s:%s", key, reflect.ValueOf(val).String())
		aFields[f] = true
	}
	for key, val := range bFieldMap {
		f := fmt.Sprintf("%s:%s", key, reflect.ValueOf(val).String())
		bFields[f] = true
	}
	corpus := map[string]bool{}
	for f := range aFields {
		corpus[f] = true
	}
	for f := range bFields {
		corpus[f] = true
	}
	aVector := []float64{}
	bVector := []float64{}
	for f := range corpus {
		aVal := 0.0
		if aFields[f] {
			if wFound, wVal := getSimilarityWeight(similarityWeight, f); wFound {
				aVal = wVal
			} else {
				aVal = 1.0
			}
		}
		aVector = append(aVector, aVal)

		bVal := 0.0
		if bFields[f] {
			if wFound, wVal := getSimilarityWeight(similarityWeight, f); wFound {
				bVal = wVal
			} else {
				bVal = 1.0
			}
		}
		bVector = append(bVector, bVal)
	}
	return aVector, bVector
}

func calculateCosineSimilarity(aVector, bVector []float64) float64 {
	// Dot
	dot := 0.0
	for i := range aVector {
		aVal := aVector[i]
		bVal := bVector[i]
		dot += aVal * bVal
	}

	// len A
	lenA := 0.0
	for _, aVal := range aVector {
		v := aVal * aVal
		lenA += v
	}
	lenA = math.Sqrt(lenA)

	// len B
	lenB := 0.0
	for _, bVal := range bVector {
		v := bVal * bVal
		lenB += v
	}
	lenB = math.Sqrt(lenB)

	similarity := dot / (lenA * lenB) // cosine similarity
	return similarity
}

func getSimilarityWeight(similarityWeight map[string]float64, key string) (bool, float64) {
	var weightMap map[string]float64
	if similarityWeight == nil {
		weightMap = defaultSimilarityWeight
	} else {
		weightMap = similarityWeight
	}
	for wkey, wval := range weightMap {
		if strings.HasPrefix(key, wkey) {
			return true, wval
		}
	}
	return false, 1.0
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
