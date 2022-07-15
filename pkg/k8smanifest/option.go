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
	_ "embed"
	"encoding/json"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/ghodss/yaml"
	gkmatch "github.com/open-policy-agent/gatekeeper/pkg/mutation/match"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/pkg/cosign"
	k8ssigutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	kubeutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// This is common ignore fields for changes by k8s system
//go:embed resources/default-config.yaml
var defaultConfigBytes []byte

// option for Sign()
type SignOption struct {
	commonOption     `json:""`
	cosignSignOption `json:""`

	// these options should be input from CLI arguments
	KeyPath           string                 `json:"-"`
	ResourceBundleRef string                 `json:"-"`
	CertPath          string                 `json:"-"`
	Output            string                 `json:"-"`
	UpdateAnnotation  bool                   `json:"-"`
	ImageAnnotations  map[string]interface{} `json:"-"`
	PassFunc          cosign.PassFunc        `json:"-"`
	ApplySigConfigMap bool                   `json:"-"`
	Tarball           *bool                  `json:"-"`
	AppendSignature   bool                   `json:"-"`
}

// option for VerifyResource()
type VerifyResourceOption struct {
	commonOption       `json:""`
	verifyOption       `json:""`
	cosignVerifyOption `json:""`

	SkipObjects ObjectReferenceList `json:"skipObjects,omitempty"`

	Provenance            bool   `json:"-"`
	DisableDryRun         bool   `json:"-"`
	CheckDryRunForApply   bool   `json:"-"`
	CheckMutatingResource bool   `json:"-"`
	DryRunNamespace       string `json:"-"`
}

func (o *VerifyResourceOption) SetAnnotationIgnoreFields() {
	if o.verifyOption.isAnnotationKeyAlreadySetToIgnoreFields() {
		return
	}
	o.verifyOption = o.verifyOption.setAnnotationKeyToIgnoreField(o.AnnotationConfig)
}

// option for VerifyManifest()
type VerifyManifestOption struct {
	commonOption       `json:""`
	verifyOption       `json:""`
	cosignVerifyOption `json:""`
}

func (o *VerifyManifestOption) SetAnnotationIgnoreFields() {
	if o.verifyOption.isAnnotationKeyAlreadySetToIgnoreFields() {
		return
	}
	o.verifyOption = o.verifyOption.setAnnotationKeyToIgnoreField(o.AnnotationConfig)
}

// common options for verify functions
// this verifyOption should not be used directly by those functions
type verifyOption struct {
	IgnoreFields ObjectFieldBindingList `json:"ignoreFields,omitempty"`
	Signers      SignerList             `json:"signers,omitempty"`

	// the maximum number of resource manifests to be checked against single resource. If empty, use 3 as default.
	MaxResourceManifestNum int `json:"maxResourceManifestNum,omitempty"`

	// these options should be input from CLI arguments
	KeyPath               string `json:"-"`
	ResourceBundleRef     string `json:"-"`
	SignatureResourceRef  string `json:"-"`
	ProvenanceResourceRef string `json:"-"`
	UseCache              bool   `json:"-"`
	CacheDir              string `json:"-"`

	annotationKeyToIgnoreFields bool `json:"-"`
}

func (o verifyOption) setAnnotationKeyToIgnoreField(annotationConfig AnnotationConfig) verifyOption {
	o.IgnoreFields = append(o.IgnoreFields, annotationConfig.AnnotationKeyIgnoreField()...)
	o.annotationKeyToIgnoreFields = true
	return o
}

func (o verifyOption) isAnnotationKeyAlreadySetToIgnoreFields() bool {
	return o.annotationKeyToIgnoreFields
}

// common options
type commonOption struct {
	AnnotationConfig `json:""`
}

// cosign sign option
type cosignSignOption struct {
	RekorURL string `json:"-"`
}

// cosign verify option
type cosignVerifyOption struct {
	Certificate      string `json:"-"`
	CertificateChain string `json:"-"`
	RekorURL         string `json:"-"`
	OIDCIssuer       string `json:"-"`
}

// annotation config for signing and verification
type AnnotationConfig struct {
	// default "cosign.sigstore.dev"
	AnnotationKeyDomain string `json:"annotationKeyDomain,omitempty"`

	ResourceBundleRefBaseName string `json:"resourceBundleRefBaseName,omitempty"`
	SignatureBaseName         string `json:"signatureBaseName,omitempty"`
	CertificateBaseName       string `json:"certificateBaseName,omitempty"`
	MessageBaseName           string `json:"messageBaseName,omitempty"`
	BundleBaseName            string `json:"bundleBaseName,omitempty"`
}

func (c AnnotationConfig) MessageAnnotationKey() string {
	return c.annotationKey(firstNonEmpty(c.MessageBaseName, defaultMessageAnnotationBaseName), 0)
}

func (c AnnotationConfig) SignatureAnnotationKey(i int) string {
	return c.annotationKey(firstNonEmpty(c.SignatureBaseName, defaultSignatureAnnotationBaseName), i)
}

func (c AnnotationConfig) CertificateAnnotationKey(i int) string {
	return c.annotationKey(firstNonEmpty(c.CertificateBaseName, defaultCertificateAnnotationBaseName), i)
}

func (c AnnotationConfig) BundleAnnotationKey(i int) string {
	return c.annotationKey(firstNonEmpty(c.BundleBaseName, defaultBundleAnnotationBaseName), i)
}

func (c AnnotationConfig) ResourceBundleRefAnnotationKey() string {
	return c.annotationKey(firstNonEmpty(c.ResourceBundleRefBaseName, defaultResourceBundleRefAnnotationBaseName), 0)
}

func (c AnnotationConfig) annotationKey(keyType string, i int) string {
	d := c.AnnotationKeyDomain
	if d == "" {
		d = DefaultAnnotationKeyDomain
	}
	key := fmt.Sprintf("%s/%s", d, keyType)
	if i > 0 {
		key = fmt.Sprintf("%s_%v", key, i)
	}
	return key
}

// this map determins annotations in the signed manifest
func (c AnnotationConfig) AnnotationKeyMap(i int) map[string]string {
	return map[string]string{
		defaultMessageAnnotationBaseName:           c.MessageAnnotationKey(),
		defaultSignatureAnnotationBaseName:         c.SignatureAnnotationKey(i),
		defaultCertificateAnnotationBaseName:       c.CertificateAnnotationKey(i),
		defaultBundleAnnotationBaseName:            c.BundleAnnotationKey(i),
		defaultResourceBundleRefAnnotationBaseName: c.ResourceBundleRefAnnotationKey(),
	}
}

func (c AnnotationConfig) GetAllSignatureSets(annotations map[string]string) []map[string]string {
	sigSets := []map[string]string{}
	msgKey := c.MessageAnnotationKey()
	msg, ok := annotations[msgKey]
	annotationBytes, _ := json.Marshal(annotations)
	log.Debugf("annotations: %s", string(annotationBytes))
	if !ok {
		return []map[string]string{}
	}
	for i := 0; ; i++ {
		sig, ok := annotations[c.SignatureAnnotationKey(i)]
		// if signature_i is not found, finish looking for signature set
		if !ok {
			break
		}
		sigMapi := map[string]string{}
		// message
		sigMapi[defaultMessageAnnotationBaseName] = msg
		// signature
		sigMapi[defaultSignatureAnnotationBaseName] = sig
		// certificate
		if cert, ok := annotations[c.CertificateAnnotationKey(i)]; ok {
			sigMapi[defaultCertificateAnnotationBaseName] = cert
		}
		// bundle
		if bndl, ok := annotations[c.BundleAnnotationKey(i)]; ok {
			sigMapi[defaultBundleAnnotationBaseName] = bndl
		}
		sigSets = append(sigSets, sigMapi)

		// prevent from infinite loop; the num of signature sets is always less than the num of annotations
		if i > len(annotations) {
			break
		}
	}
	sigSetsBytes, _ := json.Marshal(sigSets)
	log.Debugf("sigSets: %s", string(sigSetsBytes))
	return sigSets
}

// this list is used as ignorefields for verification
func (c AnnotationConfig) AnnotationKeyMask() []string {
	return []string{
		"metadata.annotations." + c.MessageAnnotationKey() + "*",
		"metadata.annotations." + c.SignatureAnnotationKey(0) + "*",
		"metadata.annotations." + c.CertificateAnnotationKey(0) + "*",
		"metadata.annotations." + c.BundleAnnotationKey(0) + "*",
		"metadata.annotations." + c.ResourceBundleRefAnnotationKey() + "*",
	}
}

func (c AnnotationConfig) AnnotationKeyIgnoreField() ObjectFieldBindingList {
	return ObjectFieldBindingList(
		[]ObjectFieldBinding{
			{
				Fields: c.AnnotationKeyMask(),
				Objects: ObjectReferenceList([]ObjectReference{
					{Kind: "*"},
				}),
			},
		},
	)
}

func firstNonEmpty(strArray ...string) string {
	for _, stri := range strArray {
		if stri != "" {
			return stri
		}
	}
	return ""
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
	configObj, err := GetConfigResource(configPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get config resource")
	}
	return parseConfigObj(configObj, configField)
}

func GetConfigResource(configPath string) (*unstructured.Unstructured, error) {
	kind, ns, name, err := kubeutil.ParseObjectRefInClusterWithKind(configPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse config in cluster `%s`", configPath)
	}
	configObj, err := kubeutil.GetResource("", kind, ns, name)
	if err != nil {
		nsDetail := ""
		if ns != "" {
			nsDetail = fmt.Sprintf("in %s namespace", ns)
		}
		return nil, errors.Wrapf(err, "failed to get config resource %s %s %s", kind, name, nsDetail)
	}
	log.Debug("found config resource: ", configObj.GetName())
	return configObj, nil
}

func GetMatchConditionFromConfigResource(configPath, matchField, inScopeObjectField string) (*gkmatch.Match, *ObjectReferenceList, error) {
	configObj, err := GetConfigResource(configPath)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to get config resource")
	}
	match, err := getMatchConditionInConstraint(configObj, matchField)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to get match condition from a config resource %s", configObj.GetName())
	}
	var iscopeCondition *ObjectReferenceList
	if inScopeObjectField != "" {
		iscopeCondition, err = parseInScopeObjectInConstraint(configObj, inScopeObjectField)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to get inScopeObject condition from a field `%s` in a config resource %s", inScopeObjectField, configObj.GetName())
		}
	}

	return match, iscopeCondition, nil
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
	var resBundleRefInConfigObj string
	switch cfg := cfgData.(type) {
	case string:
		configBytes = []byte(cfg)
	case *mapnode.Node:
		configBytes = []byte(cfg.ToYaml())
		if tmpResourceBundleRef := cfg.GetString("resourceBundleRef"); tmpResourceBundleRef != "" {
			resBundleRefInConfigObj = tmpResourceBundleRef
		}
	default:
		return nil, fmt.Errorf("cannot handle this type for config object: %T", cfg)
	}
	log.Debug("found config bytes: ", string(configBytes))
	var option *VerifyResourceOption
	err = yaml.Unmarshal(configBytes, &option)
	if err != nil {
		return nil, err
	}
	if resBundleRefInConfigObj != "" {
		option.ResourceBundleRef = resBundleRefInConfigObj
	}
	return option, nil
}

func getMatchConditionInConstraint(configObj *unstructured.Unstructured, matchField string) (*gkmatch.Match, error) {
	objNode, err := mapnode.NewFromMap(configObj.Object)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load config object as mapnode")
	}
	matchData, ok := objNode.Get(matchField)
	if !ok {
		return nil, fmt.Errorf("failed to find `%s` in `%s`", matchField, configObj.GetName())
	}
	var matchBytes []byte
	switch m := matchData.(type) {
	case *mapnode.Node:
		matchBytes = []byte(m.ToJson())
	default:
		return nil, fmt.Errorf("cannot handle this type for match condition object: %T", m)
	}
	log.Debug("found match condition bytes: ", string(matchBytes))
	var match *gkmatch.Match
	err = yaml.Unmarshal(matchBytes, &match)
	if err != nil {
		return nil, err
	}
	return match, nil
}

func parseInScopeObjectInConstraint(configObj *unstructured.Unstructured, inScopeObjectField string) (*ObjectReferenceList, error) {
	objNode, err := mapnode.NewFromMap(configObj.Object)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load config object as mapnode")
	}
	inScopeObjectData, ok := objNode.Get(inScopeObjectField)
	if !ok {
		log.Debugf("failed to find `%s` in `%s`", inScopeObjectField, configObj.GetName())
		return nil, nil
	}
	var inScopeObjectBytes []byte
	switch d := inScopeObjectData.(type) {
	case *mapnode.Node:
		inScopeObjectBytes = []byte(d.ToJson())
	default:
		return nil, fmt.Errorf("cannot handle this type for inScopeObject condition object: %T", d)
	}
	log.Debug("found inScopeObject condition bytes: ", string(inScopeObjectBytes))
	var inScopeCondition *ObjectReferenceList
	err = yaml.Unmarshal(inScopeObjectBytes, &inScopeCondition)
	if err != nil {
		return nil, err
	}
	return inScopeCondition, nil
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

func LoadDefaultConfig() *VerifyResourceOption {
	var defaultConfig *VerifyResourceOption
	err := yaml.Unmarshal(defaultConfigBytes, &defaultConfig)
	if err != nil {
		return nil
	}
	return defaultConfig
}

func AddDefaultConfig(vo *VerifyResourceOption) *VerifyResourceOption {
	dvo := LoadDefaultConfig()
	return vo.AddDefaultConfig(dvo)
}
