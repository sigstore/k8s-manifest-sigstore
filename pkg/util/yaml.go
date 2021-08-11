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
	"sort"
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

const defaultMaxCandidatesNumForContentSearch = 3

var defaultThresholdForContentSearch = 0.5

// weight for calculating a similarity value
// all other fields that are not defined here will have weight 1.0
// more weighted fields contribute more to a similarity value
var defaultFieldWeightForContentSearch map[string]float64 = map[string]float64{
	"metadata.managedFields": 0.0,
	"status":                 0.0,
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

// Out of `concatYamlBytes`, find YAML manifests that are corresponding to the `objBytes`.
// `maxCandidateNum` determines how many candidate manifests can be returned. If empty, default to 3.
// `ignoreFields` is used for content based search, the specified fields are ignored on the comparison.
func FindManifestYAML(concatYamlBytes, objBytes []byte, maxCandidateNum *int, ignoreFields []string) (bool, [][]byte) {
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

	// manifest search based on gvk/name/namespace
	found, foundBytes := ManifestSearchByGVKNameNamespace(candidateManifestBytes, apiVersion, kind, name, namespace)
	if found {
		return found, [][]byte{foundBytes}
	}
	// content-based manifest search
	var foundCandidateBytes [][]byte
	weightMap := generateWeightMapWithIgnoreFields(ignoreFields)
	found, foundCandidateBytes, _ = ManifestSearchByContent(candidateManifestBytes, objBytes, nil, maxCandidateNum, weightMap)
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

func ManifestSearchByContent(concatYamlBytes, objBytes []byte, threshold *float64, maxCandidates *int, fieldWeight map[string]float64) (bool, [][]byte, float64) {
	var thresholdNum float64
	if threshold == nil {
		thresholdNum = defaultThresholdForContentSearch
	} else {
		thresholdNum = *threshold
	}
	if thresholdNum < 0.0 || thresholdNum > 1.0 {
		return false, nil, -1.0
	}
	var maxCandidatesNum int
	if maxCandidates == nil {
		maxCandidatesNum = defaultMaxCandidatesNumForContentSearch
	} else {
		maxCandidatesNum = *maxCandidates
	}

	var weightMap map[string]float64
	if fieldWeight == nil {
		weightMap = defaultFieldWeightForContentSearch
	} else {
		weightMap = fieldWeight
	}

	yamls := SplitConcatYAMLs(concatYamlBytes)

	found := false
	maxSimilarity := -1.0
	candidates := []struct {
		sim  float64
		yaml []byte
	}{}
	for _, mnfBytes := range yamls {
		sim, err := GetSimilarityOfTwoYamls(mnfBytes, objBytes, weightMap)
		if err != nil {
			log.Debug("similarity calculation error (most of errors here can be ignored): ", err.Error())
			continue
		}
		log.Debug("sim: ", sim)
		log.Debug("manifest: ", string(mnfBytes))
		log.Debug("object: ", string(objBytes))
		if sim < thresholdNum {
			continue
		}
		candidates = append(candidates, struct {
			sim  float64
			yaml []byte
		}{
			sim:  sim,
			yaml: mnfBytes,
		})
	}
	if len(candidates) > 0 {
		found = true
	}

	// sort candidates by similarity in descending order
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].sim > candidates[j].sim })

	if len(candidates) > maxCandidatesNum {
		candidates = candidates[:maxCandidatesNum]
	}
	candidateBytes := [][]byte{}
	for _, c := range candidates {
		candidateBytes = append(candidateBytes, c.yaml)
	}

	return found, candidateBytes, maxSimilarity
}

func GetSimilarityOfTwoYamls(a, b []byte, weightMap map[string]float64) (float64, error) {
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

	aVector, bVector := makeVectorsForTwoNodes(nodeA, nodeB, weightMap)
	log.Trace("aVector: ", aVector)
	log.Trace("bVector: ", bVector)
	similarity := calculateCosineSimilarity(aVector, bVector)

	return similarity, nil
}

func generateWeightMapWithIgnoreFields(ignoreFields []string) map[string]float64 {
	weightMap := map[string]float64{}
	if len(ignoreFields) == 0 {
		weightMap = defaultFieldWeightForContentSearch
	} else {
		for _, key := range ignoreFields {
			wkey := key
			if !strings.HasSuffix(wkey, "*") {
				wkey = wkey + "*"
			}
			weightMap[wkey] = 0.0
		}
		for key, val := range defaultFieldWeightForContentSearch {
			wkey := key
			if !strings.HasSuffix(wkey, "*") {
				wkey = wkey + "*"
			}
			weightMap[wkey] = val
		}
	}
	return weightMap
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

func makeVectorsForTwoNodes(a, b *mapnode.Node, weightMap map[string]float64) ([]float64, []float64) {
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
		wFound, weight := getSimilarityWeight(weightMap, f)
		if !wFound {
			weight = 1.0
		}
		if weight == 0.0 {
			continue
		}

		aVal := 0.0
		if aFields[f] {
			aVal = weight * 1.0
		}
		aVector = append(aVector, aVal)

		bVal := 0.0
		if bFields[f] {
			bVal = weight * 1.0
		}
		bVector = append(bVector, bVal)

		log.Tracef("field[%s], a: %v, b: %v", f, aVal, bVal)
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

func getSimilarityWeight(weightMap map[string]float64, key string) (bool, float64) {
	// sort keys in weightMap first, in order to use prefix match later
	wkeys := []string{}
	for wkey := range weightMap {
		wkeys = append(wkeys, wkey)
	}
	sort.Slice(wkeys, func(i, j int) bool { return len(wkeys[i]) > len(wkeys[j]) })

	for _, wkey := range wkeys {
		wval := weightMap[wkey]
		if MatchPattern(wkey, key) {
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
