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
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

/**********************************************

					Difference

***********************************************/

type Difference struct {
	Key    string                 `json:"key"`
	Values map[string]interface{} `json:"values"`
}

func (d *Difference) Equal(d2 *Difference) bool {
	equal := false
	if d.Key == d2.Key {
		if reflect.DeepEqual(d.Values, d2.Values) {
			equal = true
		}
	}
	return equal
}

type DiffPattern Difference

func (dp *DiffPattern) Match(diff *Difference) bool {
	if dp.Key == diff.Key {
		// quick match by checking deep equality
		if reflect.DeepEqual(dp.Values, diff.Values) {
			return true
		}

		patternBeforeIf, patternBeforeExists := dp.Values["before"]
		patternAfterIf, patternAfterExists := dp.Values["after"]
		diffBeforeIf, diffBeforeExists := diff.Values["before"]
		diffAfterIf, diffAfterExists := diff.Values["after"]

		// both `before` and `after` must exist in the actual diff value,
		// so exit here if either does not exist for some reason
		if !diffBeforeExists || !diffAfterExists {
			return false
		}

		beforeOK := false
		if patternBeforeExists {
			beforeOK = patternMatch(diffBeforeIf, patternBeforeIf)
		} else {
			beforeOK = true
		}

		afterOK := false
		if patternAfterExists {
			afterOK = patternMatch(diffAfterIf, patternAfterIf)
		} else {
			afterOK = true
		}

		if beforeOK && afterOK {
			return true
		}
	}
	return false
}

type DiffResult struct {
	Items []Difference `json:"items"`
}

func (d *DiffResult) Keys() []string {
	keys := []string{}
	for _, di := range d.Items {
		keys = append(keys, di.Key)
	}
	return keys
}

func (d *DiffResult) Values() []map[string]interface{} {
	vals := []map[string]interface{}{}
	for _, di := range d.Items {
		vals = append(vals, di.Values)
	}
	return vals
}

func (dr *DiffResult) Size() int {
	return len(dr.Items)
}

func (dr *DiffResult) Remove(patterns []*DiffPattern) *DiffResult {
	items := []Difference{}
	for i := range dr.Items {
		d := dr.Items[i]
		d0 := &d
		patternMatched := false
		for _, p := range patterns {
			if (p).Match(d0) {
				patternMatched = true
				break
			}
		}
		if !patternMatched {
			items = append(items, d)
		}
	}
	return &DiffResult{Items: items}
}

func (dr *DiffResult) Filter(maskKeys []string) (*DiffResult, *DiffResult, []string) {
	for i, key := range maskKeys {
		// to match diff fields with maskKey prefix, "*" is added here
		maskKeys[i] = fmt.Sprintf("%s*", key)
	}
	filtered := &DiffResult{}
	unfiltered := &DiffResult{}
	matchedKeys := []string{}
	for _, dri := range dr.Items {
		driKey := dri.Key
		exists, matched := keyExistsInList(maskKeys, driKey)
		if exists {
			filtered.Items = append(filtered.Items, dri)
			matchedKeys = append(matchedKeys, matched)
		} else {
			unfiltered.Items = append(unfiltered.Items, dri)
		}
	}
	return filtered, unfiltered, matchedKeys
}

func (d *DiffResult) ToJson() string {
	dByte, err := json.Marshal(d)
	if err != nil {
		return ""
	}
	return string(dByte)
}

func (d *DiffResult) String() string {
	if d.Size() == 0 {
		return ""
	}
	return d.ToJson()
}

func (d *DiffResult) KeyString() string {
	keys := d.Keys()
	keyMap := map[string][]map[string]string{
		"items": {},
	}
	for _, k := range keys {
		keyMap["items"] = append(keyMap["items"], map[string]string{"key": k})
	}
	keysByte, err := json.Marshal(keyMap)
	if err != nil {
		return ""
	}
	return string(keysByte)
}

func keyExistsInList(slice []string, val string) (bool, string) {
	var matched bool
	for _, item := range slice {
		matched = patternMatchString(val, item)
		if matched {
			return true, item
		}
	}
	return false, ""
}

func patternMatchString(data, pattern string) bool {
	matched := false
	if data == pattern {
		matched = true
	} else if pattern == "*" {
		matched = true
	} else if pattern == "" {
		matched = true
	} else if strings.Contains(pattern, "*") {
		pattern2 := strings.Replace(pattern, "*", ".*", -1)
		if m, _ := regexp.MatchString(pattern2, data); m {
			matched = true
		}
	}
	return matched
}

func patternMatch(data, pattern interface{}) bool {
	if reflect.TypeOf(pattern) == reflect.TypeOf(data) {
		dataType := reflect.TypeOf(data)
		// if data type is nil, both data and pattern must be nil
		if dataType == nil {
			return (data == nil && pattern == nil)
		}
		// if the type is string, use the special pattern match
		// otherwise, just call reflect.DeepEqual()
		if dataType.Kind() == reflect.String {
			patternStr := pattern.(string)
			dataStr := data.(string)
			return patternMatchString(dataStr, patternStr)
		} else {
			return reflect.DeepEqual(data, pattern)
		}
	}
	return false
}
