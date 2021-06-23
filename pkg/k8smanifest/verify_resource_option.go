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
	"os"

	"github.com/ghodss/yaml"
	k8ssigutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type VerifyOption struct {
	SkipObjects  ObjectReferenceList    `json:"skipObjects,omitempty"`
	IgnoreFields ObjectFieldBindingList `json:"ignoreFields,omitempty"`
	Signers      SignerList             `json:"signers,omitempty"`
}

type ObjectReference struct {
	Group     string `json:"group,omitempty"`
	Version   string `json:"version,omitempty"`
	Kind      string `json:"kind,omitempty"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

type ObjectReferenceList []ObjectReference

type ObjectUserBinding struct {
	Users   []string            `json:"users,omitempty"`
	Objects ObjectReferenceList `json:"objects,omitempty"`
}

type ObjectFieldBinding struct {
	Fields  []string            `json:"fields,omitempty"`
	Objects ObjectReferenceList `json:"objects,omitempty"`
}

type ObjectFieldBindingList []ObjectFieldBinding

type SignerList []string

func ObjectToReference(obj unstructured.Unstructured) ObjectReference {
	return ObjectReference{
		Group:     obj.GroupVersionKind().Group,
		Version:   obj.GroupVersionKind().Version,
		Kind:      obj.GroupVersionKind().Kind,
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
	}
}

func (l ObjectReferenceList) Match(obj unstructured.Unstructured) bool {
	if len(l) == 0 {
		return true
	}
	for _, r := range l {
		if r.Match(obj) {
			return true
		}
	}
	return false
}

func (r ObjectReference) Match(obj unstructured.Unstructured) bool {
	return r.Equal(ObjectToReference(obj))
}

func (r ObjectReference) Equal(r2 ObjectReference) bool {
	return k8ssigutil.MatchPattern(r.Group, r2.Group) &&
		k8ssigutil.MatchPattern(r.Version, r2.Version) &&
		k8ssigutil.MatchPattern(r.Kind, r2.Kind) &&
		k8ssigutil.MatchPattern(r.Name, r2.Name) &&
		k8ssigutil.MatchPattern(r.Namespace, r2.Namespace)
}

func (l ObjectFieldBindingList) Match(obj unstructured.Unstructured) (bool, []string) {
	if len(l) == 0 {
		return false, nil
	}
	matched := false
	matchedFields := []string{}
	for _, f := range l {
		if tmpMatched, tmpFields := f.Match(obj); tmpMatched {
			matched = tmpMatched
			matchedFields = append(matchedFields, tmpFields...)
		}
	}
	return matched, matchedFields
}

func (f ObjectFieldBinding) Match(obj unstructured.Unstructured) (bool, []string) {
	if f.Objects.Match(obj) {
		return true, f.Fields
	}
	return false, nil
}

func (l SignerList) Match(signerName string) bool {
	if len(l) == 0 {
		return true
	}
	for _, s := range l {
		if k8ssigutil.MatchPattern(s, signerName) {
			return true
		}
	}
	return false
}

func LoadVerifyConfig(fpath string) (*VerifyOption, error) {
	cfgBytes, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	var option *VerifyOption
	err = yaml.Unmarshal(cfgBytes, &option)
	if err != nil {
		return nil, err
	}
	return option, nil
}
