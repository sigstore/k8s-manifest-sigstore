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
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	k8ssigutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	kubeutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const InClusterObjectPrefix = "k8s://"

// option for Sign()
type SignOption struct {
	// these options should be input from CLI arguments
	KeyPath          string                 `json:"-"`
	ImageRef         string                 `json:"-"`
	CertPath         string                 `json:"-"`
	Output           string                 `json:"-"`
	UpdateAnnotation bool                   `json:"-"`
	ImageAnnotations map[string]interface{} `json:"-"`
	PassFunc         cosign.PassFunc        `json:"-"`
}

// option for VerifyResource()
type VerifyResourceOption struct {
	verifyOption `json:""`
	SkipObjects  ObjectReferenceList `json:"skipObjects,omitempty"`

	CheckDryRunForApply bool   `json:"-"`
	DryRunNamespace     string `json:"-"`
}

// option for VerifyManifest()
type VerifyManifestOption struct {
	verifyOption `json:""`
}

// common options for verify functions
// this verifyOption should not be used directly by those functions
type verifyOption struct {
	IgnoreFields ObjectFieldBindingList `json:"ignoreFields,omitempty"`
	Signers      SignerList             `json:"signers,omitempty"`

	// the maximum number of resource manifests to be checked against single resource. If empty, use 3 as default.
	MaxResourceManifestNum int `json:"maxResourceManifestNum,omitempty"`

	// these options should be input from CLI arguments
	KeyPath  string `json:"-"`
	ImageRef string `json:"-"`
	UseCache bool   `json:"-"`
	CacheDir string `json:"-"`
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

func LoadVerifyManifestConfig(fpath string) (*VerifyManifestOption, error) {
	cfgBytes, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	var option *VerifyManifestOption
	err = yaml.Unmarshal(cfgBytes, &option)
	if err != nil {
		return nil, err
	}
	return option, nil
}

func LoadVerifyResourceConfig(fpath string) (*VerifyResourceOption, error) {
	cfgBytes, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	var option *VerifyResourceOption
	err = yaml.Unmarshal(cfgBytes, &option)
	if err != nil {
		return nil, err
	}
	return option, nil
}

func LoadVerifyResourceConfigFromResource(configPath, configField string) (*VerifyResourceOption, error) {
	kind, ns, name, err := parseObjectInCluster(configPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse config in cluster `%s`", configPath)
	}
	log.Debugf("trying to find config resource kind: %s, name: %s, namespace: %s", kind, name, ns)
	configObj, err := kubeutil.GetResource("", kind, ns, name)
	if err != nil {
		nsDetail := ""
		if ns != "" {
			nsDetail = fmt.Sprintf("in %s namespace", ns)
		}
		return nil, errors.Wrapf(err, "failed to get config resource %s %s %s", kind, name, nsDetail)
	}
	log.Debug("found config resource: ", configObj.GetName())
	return parseConfigObj(configObj, configField)
}

func parseObjectInCluster(configPath string) (string, string, string, error) {
	parts := strings.Split(strings.TrimPrefix(configPath, InClusterObjectPrefix), "/")
	if len(parts) != 2 && len(parts) != 3 {
		return "", "", "", fmt.Errorf("object in cluster must be in format like %s[KIND]/[NAMESPACE]/[NAME] or %s[KIND]/[NAME]", InClusterObjectPrefix, InClusterObjectPrefix)
	}

	var kind, ns, name string
	if len(parts) == 2 {
		kind = parts[0]
		name = parts[1]
	} else if len(parts) == 3 {
		kind = parts[0]
		ns = parts[1]
		name = parts[2]
	}
	return kind, ns, name, nil
}

func parseConfigObj(configObj *unstructured.Unstructured, configField string) (*VerifyResourceOption, error) {
	objNode, err := mapnode.NewFromMap(configObj.Object)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load config object as mapnode")
	}
	cfgData, ok := objNode.Get(configField)
	if !ok {
		return nil, fmt.Errorf("failed to parse config field `%s` in `%s`", configField, configObj.GetName())
	}
	var configBytes []byte
	switch cfg := cfgData.(type) {
	case string:
		configBytes = []byte(cfg)
	case *mapnode.Node:
		configBytes = []byte(cfg.ToYaml())
	default:
		return nil, fmt.Errorf("cannot handle this type for config object: %T", cfg)
	}
	log.Debug("found config bytes: ", string(configBytes))
	var option *VerifyResourceOption
	err = yaml.Unmarshal(configBytes, &option)
	if err != nil {
		return nil, err
	}
	return option, nil
}

func (vo *VerifyResourceOption) AddDefaultConfig(defaultConfig *VerifyResourceOption) *VerifyResourceOption {
	if vo == nil {
		return nil
	}
	ignoreFields := []ObjectFieldBinding(vo.verifyOption.IgnoreFields)
	ignoreFields = append(ignoreFields, []ObjectFieldBinding(defaultConfig.verifyOption.IgnoreFields)...)
	vo.verifyOption.IgnoreFields = ignoreFields
	return vo
}
