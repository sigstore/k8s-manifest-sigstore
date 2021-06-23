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
	"math/big"
	"strconv"
	"strings"
)

/**********************************************

				Pattern Functions

***********************************************/

func MatchPattern(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return true
	} else if pattern == "*" {
		return true
	} else if pattern == "-" && value == "" {
		return true
	} else if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, strings.TrimRight(pattern, "*"))
	} else if pattern == value {
		return true
	} else if strings.Contains(pattern, ",") {
		patterns := SplitRule(pattern)
		return MatchWithPatternArray(value, patterns)
	} else {
		return false
	}
}

func MatchSinglePattern(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return true
	} else if pattern == "*" {
		return true
	} else if pattern == "-" && value == "" {
		return true
	} else if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, strings.TrimRight(pattern, "*"))
	} else if pattern == value {
		return true
	} else {
		return false
	}
}

func ExactMatch(pattern, value string) bool {
	return pattern == value
}

func ExactMatchWithPatternArray(value string, patternArray []string) bool {
	for _, pattern := range patternArray {
		if ExactMatch(pattern, value) {
			return true
		}
	}
	return false
}

func GetUnionOfArrays(array1, array2 []string) []string {
	newArray := []string{}
	for _, val := range array1 {
		exists := ExactMatchWithPatternArray(val, newArray)
		if !exists {
			newArray = append(newArray, val)
		}
	}
	for _, val := range array2 {
		exists := ExactMatchWithPatternArray(val, newArray)
		if !exists {
			newArray = append(newArray, val)
		}
	}
	return newArray
}

func MatchPatternWithArray(pattern string, valueArray []string) bool {
	for _, value := range valueArray {
		if MatchPattern(pattern, value) {
			return true
		}
	}
	return false
}

func MatchWithPatternArray(value string, patternArray []string) bool {
	for _, pattern := range patternArray {
		if MatchPattern(pattern, value) {
			return true
		}
	}
	return false
}

func MatchBigInt(pattern string, value *big.Int) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return true
	} else if pattern == "*" {
		return true
	} else if pattern == "-" && value == nil {
		return true
	} else if strings.Contains(pattern, ":") {
		return pattern2BigInt(pattern).Cmp(value) == 0
	} else if i, err := strconv.Atoi(pattern); err == nil {
		return i == int(value.Int64())
	} else {
		return false
	}
}

func pattern2BigInt(pattern string) *big.Int {
	a := strings.ReplaceAll(pattern, ":", "")
	i := new(big.Int)
	i.SetString(a, 16)
	return i
}

func SplitRule(rules string) []string {
	result := []string{}
	slice := strings.Split(rules, ",")
	for _, s := range slice {
		rule := strings.TrimSpace(s)
		result = append(result, rule)
	}
	return result
}
