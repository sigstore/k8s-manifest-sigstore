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

package mapnode

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/jinzhu/copier"
	"github.com/oliveagle/jsonpath"
	"github.com/r3labs/diff"
)

const MapnodeVersion = "0.0.2"

/**********************************************

					Node Value

***********************************************/

type NodeValue struct {
	Type  reflect.Type
	Value interface{}
}

func NewNodeValue(val interface{}) *NodeValue {
	nv := &NodeValue{
		Type:  reflect.TypeOf(val),
		Value: val,
	}
	return nv
}

func (nv *NodeValue) Interface() interface{} {
	return nv.Value
}

func (nv *NodeValue) String() string {
	nvStr := fmt.Sprintf("{\"Type\":%s,\"Value\":%s}", nv.Type, nv.Value)
	return nvStr
}

/**********************************************

					Node

***********************************************/

type Node struct {
	Value    *NodeValue
	Children interface{}
}

func emptyNode() *Node {
	return &Node{
		Value:    nil,
		Children: nil,
	}
}

func NewFromBytes(rawObj []byte) (*Node, error) {
	var objMap map[string]interface{}
	err := json.Unmarshal(rawObj, &objMap)
	if err != nil {
		return emptyNode(), err
	}
	tn, err := NewFromMap(objMap)
	if err != nil {
		return emptyNode(), err
	}
	return tn, nil
}

func NewFromYamlBytes(rawObj []byte) (*Node, error) {
	var objMap map[string]interface{}
	err := yaml.Unmarshal(rawObj, &objMap)
	if err != nil {
		return emptyNode(), err
	}
	tn, err := NewFromMap(objMap)
	if err != nil {
		return emptyNode(), err
	}
	return tn, nil
}

func NewFromInterfaceBytes(rawObj []byte) (*Node, error) {
	var obj interface{}
	err := json.Unmarshal(rawObj, &obj)
	if err != nil {
		return emptyNode(), err
	}
	node := NewNode(obj)
	return node, nil
}

func NewFromMap(objMap map[string]interface{}) (*Node, error) {
	node := NewNode(objMap)
	if node == nil {
		return emptyNode(), errors.New("Created Node is nil")
	}
	return node, nil
}

func NewNode(val interface{}) *Node {
	var value *NodeValue
	var children interface{}
	if val != nil {
		if reflect.TypeOf(val).Kind() == reflect.Map {
			childrenMap := make(map[string]*Node)
			valMap, _ := val.(map[string]interface{})
			for k, v := range valMap {
				childrenMap[k] = NewNode(v)
			}
			children = childrenMap
		} else if reflect.TypeOf(val).Kind() == reflect.Slice {
			childrenSlice := []*Node{}
			valSlice, _ := val.([]interface{})
			for _, v := range valSlice {
				childrenSlice = append(childrenSlice, NewNode(v))
			}
			children = childrenSlice
		} else {
			value = NewNodeValue(val)
		}
	}
	node := &Node{
		Value:    value,
		Children: children,
	}
	return node
}

func (n *Node) KeyExists(concatKey string) bool {
	_, ok := n.Get(concatKey)
	return ok
}

func (n *Node) DeepCopyInto(n2 *Node) {
	copier.Copy(&n2, &n)
}

func (n *Node) Copy() *Node {
	n2 := emptyNode()
	n.DeepCopyInto(n2)
	return n2
}

func (n *Node) Merge(n2 *Node) (*Node, error) {
	if n.IsValue() != n2.IsValue() {
		return emptyNode(), errors.New("Type of 2 nodes are different.")
	}
	if n.IsSlice() != n2.IsSlice() {
		return emptyNode(), errors.New("Type of 2 nodes are different.")
	}
	if n.IsMap() != n2.IsMap() {
		return emptyNode(), errors.New("Type of 2 nodes are different.")
	}

	if n.IsValue() {
		if (n.Value == nil) != (n2.Value == nil) {
			return emptyNode(), errors.New("Type of 2 values are different.")
		}
		if n.Value == nil && n2.Value == nil {
			return n2, nil
		}
		if n.Value.Type != n2.Value.Type {
			return emptyNode(), errors.New("Type of 2 values are different.")
		}
		return n2, nil
	} else if n.IsSlice() {
		children := n.Children.([]*Node)
		children2 := n2.Children.([]*Node)
		children = append(children, children2...)
		return &Node{
			Value:    nil,
			Children: children,
		}, nil
	} else if n.IsMap() {
		children := n.Children.(map[string]*Node)
		children2 := n2.Children.(map[string]*Node)
		for key, childNode := range children2 {
			if _, ok := children[key]; !ok {
				var tmpNode *Node
				if childNode.IsValue() {
					tmpNode = &Node{
						Value: &NodeValue{
							Type:  childNode.Value.Type,
							Value: nil,
						},
						Children: nil}
				} else if childNode.IsSlice() {
					tmpNode = &Node{
						Value:    nil,
						Children: []*Node{},
					}
				} else if childNode.IsMap() {
					tmpNode = &Node{
						Value:    nil,
						Children: make(map[string]*Node),
					}
				}
				children[key] = tmpNode
			}
			mergedNode, err := (children[key]).Merge(childNode)
			if err != nil {
				return emptyNode(), err
			}
			children[key] = mergedNode
		}
		return &Node{
			Value:    nil,
			Children: children,
		}, nil
	}

	return emptyNode(), errors.New("Unsupported type of node.")
}

// extract elements that match input key
func (n *Node) Extract(filterKeys []string) *Node {
	m := n.Ravel()
	allKeysInNode := []string{}
	for k := range m {
		allKeysInNode = append(allKeysInNode, k)
	}
	maskKeys := []string{}
	validFilterKeys := n.validateKeyList(filterKeys)
	for _, k := range allKeysInNode {
		keyFoundInFilters := false
		for _, fk := range validFilterKeys {
			if strings.HasPrefix(k, fk) {
				keyFoundInFilters = true
				break
			}
		}
		if !keyFoundInFilters {
			maskKeys = append(maskKeys, k)
		}

		keyParts := strings.Split(k, ".")
		for i := range keyParts {
			if i == len(keyParts)-1 {
				continue
			}
			parentKeyUsedInFilters := false
			parentKey := strings.Join(keyParts[:i+1], ".")
			for _, fk := range validFilterKeys {
				if strings.HasPrefix(fk, parentKey) || strings.HasPrefix(parentKey, fk) {
					parentKeyUsedInFilters = true
					break
				}
			}
			if !parentKeyUsedInFilters {
				maskKeys = append(maskKeys, parentKey)
			}
		}
	}
	node := n.Mask(maskKeys)
	return node
}

// remove elements that match input key
func (t *Node) Mask(keys []string) *Node {
	validKeys := t.validateKeyList(keys)
	node := t.recursiveMask("", validKeys)
	return node
}

func (n *Node) recursiveMask(currentPath string, maskKeys []string) *Node {
	if n.IsValue() {
		return n
	}
	var newChildren interface{}
	if n.IsMap() {
		children := n.Children.(map[string]*Node)
		newChildrenMap := make(map[string]*Node)
		for k, v := range children {
			var currentKey string
			if currentPath == "" {
				currentKey = k
			} else {
				currentKey = fmt.Sprintf("%s.%s", currentPath, k)
			}

			if matched, _ := keyExistsInList(maskKeys, currentKey); matched {
				continue
			}
			mn := v.recursiveMask(currentKey, maskKeys)
			newChildrenMap[k] = mn
		}
		newChildren = newChildrenMap
	}
	if n.IsSlice() {
		children := n.Children.([]*Node)
		newChildrenSlice := []*Node{}
		for i, v := range children {
			k := strconv.Itoa(i)
			var currentKey string
			if currentPath == "" {
				currentKey = k
			} else {
				currentKey = fmt.Sprintf("%s.%s", currentPath, k)
			}
			if matched, _ := keyExistsInList(maskKeys, currentKey); matched {
				continue
			}
			mn := v.recursiveMask(currentKey, maskKeys)
			newChildrenSlice = append(newChildrenSlice, mn)
		}
		newChildren = newChildrenSlice
	}
	return &Node{Value: nil, Children: newChildren}
}

func (n *Node) IsValue() bool {
	return (!n.IsMap() && !n.IsSlice())
}

func (n *Node) IsMap() bool {
	if n.Children == nil {
		return false
	}
	return (reflect.TypeOf(n.Children).Kind() == reflect.Map)
}

func (n *Node) IsSlice() bool {
	if n.Children == nil {
		return false
	}
	return (reflect.TypeOf(n.Children).Kind() == reflect.Slice)
}

func (n *Node) Size() int {
	if n.IsValue() {
		return 1
	} else {
		return reflect.ValueOf(n.Children).Len()
	}
}

func (n *Node) GetChildrenMap() map[string]*Node {
	if n.IsValue() {
		return nil
	} else if n.IsMap() {
		children := n.Children.(map[string]*Node)
		return children
	} else if n.IsSlice() {
		childrenMap := make(map[string]*Node)
		children := n.Children.([]*Node)
		for i, v := range children {
			k := strconv.Itoa(i)
			childrenMap[k] = v
		}
		return childrenMap
	} else {
		return nil
	}
}

func (n *Node) GetChildrenSlice() []*Node {
	if n.IsValue() {
		return nil
	} else if n.IsMap() {
		return nil
	} else if n.IsSlice() {
		children := n.Children.([]*Node)
		return children
	} else {
		return nil
	}
}

func (n *Node) GetNodeByJSONPath(jpathKey string) (*Node, error) {
	jsonStr := n.ToJson()
	var nIf interface{}
	err := json.Unmarshal([]byte(jsonStr), &nIf)
	if err != nil {
		return emptyNode(), err
	}
	res, err := jsonpath.JsonPathLookup(nIf, jpathKey)
	if err != nil {
		return emptyNode(), err
	}
	found, err := json.Marshal(res)
	if err != nil {
		return emptyNode(), err
	}
	foundNode, err := NewFromInterfaceBytes(found)
	if err != nil {
		return emptyNode(), err
	}
	return foundNode, nil
}

// convert key "foo[1].bar" to "foo.1.bar" and then generate actual existing keys by generateKeyList()
func (t *Node) validateKeyList(keys []string) []string {
	newKeys := []string{}
	for i, key := range keys {
		keyAlt := parseConcatKey(key)
		if key != keyAlt {
			keys[i] = keyAlt
		}
	}
	for _, key := range keys {
		tmpList := t.generateKeyList(key)
		if len(tmpList) > 0 {
			newKeys = append(newKeys, tmpList...)
		} else {
			newKeys = append(newKeys, key)
		}
	}
	return newKeys
}

func GetConcreteKeys(keys []string, n *Node) []string {
	validatedKeyList := n.validateKeyList(keys)
	return validatedKeyList
}

// expand input key "foo[].bar" to actual exsiting keys like ["foo.1.bar", "foo.2.bar"]
func (t *Node) generateKeyList(concatKey string) []string {
	if !strings.Contains(concatKey, "[]") {
		return []string{}
	}
	parts := strings.Split(concatKey, "[]")
	for i := range parts {
		parts[i] = strings.Trim(parts[i], ".")
	}
	indexList := []int{}
	finished := []bool{}

	concatKeySlice := []string{}
	for i := 0; i < len(parts)-1; i++ {
		indexList = append(indexList, 0)
		finished = append(finished, false)
	}
	allFinished := false
	for !allFinished {
		key := ""
		checkKey := ""
		for i, p := range parts {
			key += p
			if i < len(parts)-1 {
				key += fmt.Sprintf(".%s.", strconv.Itoa(indexList[i]))
				checkKey += p
				checkKey += fmt.Sprintf(".%s.", strconv.Itoa(indexList[i]))
			}
		}
		key = strings.TrimSuffix(key, ".")
		checkKey = strings.TrimSuffix(checkKey, ".")
		ok := t.KeyExists(checkKey)
		notFinishedI := -1
		for i := len(finished) - 1; i >= 0; i-- {
			if finished[i] {
				continue
			} else {
				notFinishedI = i
				break
			}
		}
		if ok {
			concatKeySlice = append(concatKeySlice, key)
			indexList[notFinishedI] += 1
		} else {
			finished[notFinishedI] = true
			if finished[0] {
				allFinished = true
			}
		}
	}
	return concatKeySlice
}

func (t *Node) MultipleSubNode(concatKey string) []*Node {
	if !strings.Contains(concatKey, "[]") {
		subNode := t.SubNode(concatKey)
		return []*Node{subNode}
	}

	concatKeySlice := t.generateKeyList(concatKey)
	nodeSlice := []*Node{}
	for _, key := range concatKeySlice {
		tmpNode := t.SubNode(key)
		nodeSlice = append(nodeSlice, tmpNode)
	}

	return nodeSlice
}

func (t *Node) GetNode(concatKey string) (*Node, bool) {
	keys := splitConcatKey(concatKey)
	currentNode := &Node{
		Value:    t.Value,
		Children: t.Children,
	}
	for _, key := range keys {
		tmpNode, ok := currentNode.GetChild(key)
		if !ok {
			return emptyNode(), false
		}
		currentNode = &Node{
			Value:    tmpNode.Value,
			Children: tmpNode.Children,
		}
	}
	return currentNode, true
}

func (t *Node) SubNode(concatKey string) *Node {
	node, ok := t.GetNode(concatKey)
	if !ok {
		return emptyNode()
	}
	return node
}

func (t *Node) GetString(concatKey string) string {
	if v, ok := t.Get(concatKey); !ok {
		return ""
	} else if s, ok := v.(string); ok {
		return s
	} else if s, err := json.Marshal(v); err != nil {
		return ""
	} else {
		return string(s)
	}
}

func (t *Node) GetBool(concatKey string, defaultValue bool) bool {
	if v, ok := t.Get(concatKey); !ok {
		return defaultValue
	} else if b, ok := v.(bool); ok {
		return b
	} else if s, ok := v.(string); ok {
		if b, err := strconv.ParseBool(s); err != nil {
			return defaultValue
		} else {
			return b
		}
	} else {
		return defaultValue
	}
}

func (t *Node) Get(concatKey string) (interface{}, bool) {
	node, ok := t.GetNode(concatKey)
	if !ok {
		return nil, false
	}
	if node.Value != nil {
		return node.Value.Value, true
	} else {
		return node, true
	}

}

func (n *Node) GetChild(key string) (*Node, bool) {
	if n.IsValue() {
		return nil, false
	} else if n.IsMap() {
		children := n.Children.(map[string]*Node)
		childNode, ok := children[key]
		if !ok {
			return nil, false
		}
		return childNode, true
	} else if n.IsSlice() {
		i, err := strconv.Atoi(key)
		if err != nil {
			return nil, false
		}
		children := n.Children.([]*Node)
		if i < 0 || i >= len(children) {
			return nil, false
		}
		childNode := children[i]
		return childNode, true
	} else {
		return nil, false
	}
}

func (t *Node) Ravel() map[string]interface{} {
	m := t.recursiveRavel("", nil)
	return m
}

func (n *Node) recursiveRavel(currentPath string, m map[string]interface{}) map[string]interface{} {
	if m == nil {
		m = make(map[string]interface{})
	}

	var currentKey string
	if n.Value != nil {
		currentKey = currentPath
		m[currentKey] = n.Value.Interface()
		return m
	}

	for k, v := range n.GetChildrenMap() {
		if currentPath == "" {
			currentKey = k
		} else {
			currentKey = fmt.Sprintf("%s.%s", currentPath, k)
		}
		m = v.recursiveRavel(currentKey, m)
	}
	return m
}

func (n *Node) Interface() interface{} {
	if n.IsValue() {
		if n.Value != nil {
			valIf := n.Value.Interface()
			return valIf
		} else {
			return nil
		}
	} else if n.IsMap() {
		m := make(map[string]interface{})
		children := n.Children.(map[string]*Node)
		for k, v := range children {
			m[k] = v.Interface()
		}
		return m
	} else if n.IsSlice() {
		s := []interface{}{}
		children := n.Children.([]*Node)
		for _, v := range children {
			s = append(s, v.Interface())
		}
		return s
	} else {
		return nil
	}
}

func (t *Node) ToMap() map[string]interface{} {
	mIf := t.Interface()
	m, ok := mIf.(map[string]interface{})
	if !ok {
		return nil
	}
	return m
}

func (n *Node) ToJson() string {
	nStr := ""
	if n.IsValue() {
		if n.Value == nil {
			nStr = "null"
		} else {
			nStr = fmt.Sprintf("%s", n.Value.Interface())
		}
	} else if n.IsMap() {
		m := make(map[string]interface{})
		children := n.Children.(map[string]*Node)
		for k, v := range children {
			m[k] = v.Interface()
		}
		b, _ := json.Marshal(m)
		nStr = string(b)
	} else if n.IsSlice() {
		s := []interface{}{}
		children := n.Children.([]*Node)
		for _, v := range children {
			s = append(s, v.Interface())
		}
		b, _ := json.Marshal(s)
		nStr = string(b)
	}
	return nStr
}

func (n *Node) ToYaml() string {
	nStr := ""
	if n.IsValue() {
		nStr = fmt.Sprintf("%s", n.Value.Interface())

	} else if n.IsMap() {
		m := make(map[string]interface{})
		children := n.Children.(map[string]*Node)
		for k, v := range children {
			m[k] = v.Interface()
		}
		b, _ := yaml.Marshal(m)
		nStr = string(b)
	} else if n.IsSlice() {
		s := []interface{}{}
		children := n.Children.([]*Node)
		for _, v := range children {
			s = append(s, v.Interface())
		}
		b, _ := yaml.Marshal(s)
		nStr = string(b)
	}
	return nStr
}

func (n *Node) String() string {
	nStr := n.ToJson()
	return nStr
}

func (t *Node) Diff(t2 *Node) *DiffResult {
	dr := FindDiffBetweenNodes(t, t2, nil)
	return dr
}

func (t *Node) DiffSpecificType(t2 *Node, findTypeList []string) *DiffResult {
	findType := make(map[string]bool)
	for _, t := range findTypeList {
		findType[t] = true
	}
	dr := FindDiffBetweenNodes(t, t2, findType)
	return dr
}

func (t *Node) FindUpdatedAndDeleted(t2 *Node) *DiffResult {
	dr := t.DiffSpecificType(t2, []string{"update", "delete"})
	return dr
}

func (t *Node) FindUpdatedAndCreated(t2 *Node) *DiffResult {
	dr := t.DiffSpecificType(t2, []string{"update", "create"})
	return dr
}

// separate inconsistent type key & values from maps
func extractComparableMap(m1, m2 map[string]interface{}) (map[string]interface{}, map[string]interface{}, []Difference) {
	keys := map[string]bool{}
	for k := range m1 {
		keys[k] = true
	}
	for k := range m2 {
		keys[k] = true
	}
	nm1 := map[string]interface{}{}
	nm2 := map[string]interface{}{}
	typeDiffs := []Difference{}
	for k := range keys {
		v1, ok1 := m1[k]
		v2, ok2 := m2[k]

		if v1 != nil && v2 != nil && reflect.TypeOf(v1) != reflect.TypeOf(v2) {
			d := Difference{
				Key: k,
				Values: map[string]interface{}{
					"before": fmt.Sprintf("(type: %T) %s", v1, v1),
					"after":  fmt.Sprintf("(type: %T) %s", v2, v2),
				},
			}
			typeDiffs = append(typeDiffs, d)
			continue
		}
		if ok1 {
			nm1[k] = v1
		}
		if ok2 {
			nm2[k] = v2
		}
	}
	return nm1, nm2, typeDiffs
}

func FindDiffBetweenNodes(t1, t2 *Node, findType map[string]bool) *DiffResult {
	if findType == nil {
		findType = map[string]bool{
			"create": true,
			"update": true,
			"delete": true,
		}
	}

	m1 := t1.Ravel()
	m2 := t2.Ravel()
	if reflect.DeepEqual(m1, m2) {
		return nil
	}

	nm1, nm2, typeDiffs := extractComparableMap(m1, m2)

	changelog, err := diff.Diff(nm1, nm2)
	if err != nil {
		return nil
	}

	if len(changelog) == 0 && len(typeDiffs) == 0 {
		return nil
	}
	items := []Difference{}
	for _, c := range changelog {
		if !findType[c.Type] {
			continue
		}
		key := c.Path[0]
		before := c.From
		after := c.To
		d := Difference{
			Key:    key,
			Values: map[string]interface{}{"before": before, "after": after},
		}
		items = append(items, d)
	}

	items = removeKeyDiffsInListNode(items)

	items = append(items, typeDiffs...)
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].Key < items[j].Key
	})
	dr := &DiffResult{
		Items: items,
	}
	return dr
}

func recursiveGetByKey(m map[string]interface{}, i int, keyList []string) (interface{}, error) {
	key := keyList[i]
	val, ok := m[key]
	current := strings.Join(keyList[:i+1], ".")
	if !ok {
		return nil, errors.New(fmt.Sprintf("key `%s` not found", current))
	}
	if i == len(keyList)-1 {
		return val, nil
	} else if valMap, ok := val.(map[string]interface{}); ok {
		if valIf, err := recursiveGetByKey(valMap, i+1, keyList); err != nil {
			return nil, err
		} else {
			return valIf, nil
		}
	} else if valSlice, ok := val.([]interface{}); ok {
		valMap := make(map[string]interface{})
		for j, v := range valSlice {
			k := strconv.Itoa(j)
			valMap[k] = v
		}
		if valIf, err := recursiveGetByKey(valMap, i+1, keyList); err != nil {
			return nil, err
		} else {
			return valIf, nil
		}
	} else {
		return nil, errors.New(fmt.Sprintf("cannot cast `%s` to map[string]interface{}", current))
	}
}

func parseConcatKey(concatKey string) string {
	return strings.Join(splitConcatKey(concatKey), ".")
}

func splitConcatKey(concatKey string) []string {
	var keys []string
	if !strings.Contains(concatKey, "\"") {
		keys = strings.Split(concatKey, ".")
	} else {
		r := csv.NewReader(strings.NewReader(concatKey))
		r.Comma = '.' // delimiter
		loadedKeys, err := r.Read()
		if err != nil {
			return []string{}
		}
		keys = loadedKeys
	}
	parsedKeys := []string{}
	for _, k := range keys {
		re := regexp.MustCompile(`\[\d+\]$`)
		if found := re.FindString(k); found == "" {
			parsedKeys = append(parsedKeys, k)
		} else {
			k1 := strings.ReplaceAll(k, found, "")
			k2 := strings.Trim(found, "[]")
			if k1 != "" {
				parsedKeys = append(parsedKeys, k1)
			}
			parsedKeys = append(parsedKeys, k2)
		}
	}
	return parsedKeys
}

// extract actual diff (remove "key-only diffs" in list)
func removeKeyDiffsInListNode(items []Difference) []Difference {
	items2 := []Difference{}
	for _, item := range items {
		keyOk, _ := regexp.MatchString(`\.\d+\.`, item.Key)
		valBeforeNil := (item.Values["before"] == nil)
		valAfterNil := (item.Values["after"] == nil)
		addThis := true
		if keyOk && (valBeforeNil || valAfterNil) {
			re := regexp.MustCompile(`\.\d+\.`)
			searchKey := re.ReplaceAllString(item.Key, `\.\d+\.`)
			for _, tmpItem := range items {
				keyMatched, _ := regexp.MatchString(searchKey, tmpItem.Key)
				tmpValAfterMatched := (item.Values["before"] == tmpItem.Values["after"]) && (tmpItem.Values["before"] == nil) && valAfterNil
				tmpValBeforeMatched := (item.Values["after"] == tmpItem.Values["before"]) && (tmpItem.Values["after"] == nil) && valBeforeNil
				if keyMatched && (tmpValBeforeMatched || tmpValAfterMatched) {
					addThis = false
					break
				}
			}
		}
		if addThis {
			items2 = append(items2, item)
		}
	}
	return items2
}

func GetValueByLongKey(m map[string]interface{}, longKey string) (interface{}, error) {
	keyList := splitConcatKey(longKey)
	val, err := recursiveGetByKey(m, 0, keyList)
	if err != nil {
		return nil, err
	}
	return val, nil
}

func SplitCommaSeparatedKeys(key string) []string {
	key = strings.ReplaceAll(key, "\n", "")
	keys := strings.Split(key, ",")
	for i := range keys {
		keys[i] = strings.Trim(keys[i], " ")
	}
	return keys
}
