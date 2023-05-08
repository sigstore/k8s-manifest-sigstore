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
	cryptox509 "crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	k8smnfcosign "github.com/sigstore/k8s-manifest-sigstore/pkg/cosign"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	mapnode "github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
	sigtypes "github.com/sigstore/k8s-manifest-sigstore/pkg/util/sigtypes"
	pgp "github.com/sigstore/k8s-manifest-sigstore/pkg/util/sigtypes/pgp"
	x509 "github.com/sigstore/k8s-manifest-sigstore/pkg/util/sigtypes/x509"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

const SigRefEmbeddedInAnnotation = "__embedded_in_annotation__"

type SignatureVerifier interface {
	Verify() (bool, string, *int64, error)
}

type verificationIdentity struct {
	path string // for keyed
	name string // for keyless
}

type CosignVerifyConfig struct {
	CertRef       string
	CertChain     string
	RekorURL      string
	OIDCIssuer    string
	RootCerts     *cryptox509.CertPool
	AllowInsecure bool
}

func NewSignatureVerifier(objYAMLBytes []byte, sigRef string, pubkeyPath *string, signers []string, cosignVerifyConfig CosignVerifyConfig, annotationConfig AnnotationConfig) SignatureVerifier {
	var resBundleRef, resourceRef string

	resBundleRefAnnotationKey := annotationConfig.ResourceBundleRefAnnotationKey()
	annotations := k8smnfutil.GetAnnotationsInYAML(objYAMLBytes)
	if annoResBundleRef, ok := annotations[resBundleRefAnnotationKey]; ok {
		resBundleRef = annoResBundleRef
	}

	if strings.HasPrefix(sigRef, kubeutil.InClusterObjectPrefix) {
		resourceRef = sigRef
	} else if sigRef != "" && resBundleRef == "" {
		resBundleRef = sigRef
	}

	identityList := []verificationIdentity{}
	if pubkeyPath != nil && *pubkeyPath != "" {
		pubkeyPathList := k8smnfutil.SplitCommaSeparatedString(*pubkeyPath)
		for _, k := range pubkeyPathList {
			identityList = append(identityList, verificationIdentity{path: k})
		}
	} else if len(signers) > 0 {
		for _, s := range signers {
			identityList = append(identityList, verificationIdentity{name: s})
		}
	} else {
		// no key option and no signer option, this means keyless mode and any signer names are allowed
		identityList = append(identityList, verificationIdentity{name: ""})
	}

	if resBundleRef != "" && resBundleRef != SigRefEmbeddedInAnnotation {
		return &ImageSignatureVerifier{
			resBundleRef:         resBundleRef,
			onMemoryCacheEnabled: true,
			identityList:         identityList,
			annotationConfig:     annotationConfig,
			CosignVerifyConfig:   cosignVerifyConfig,
		}
	} else {
		return &BlobSignatureVerifier{
			annotations:        annotations,
			resourceRef:        resourceRef,
			identityList:       identityList,
			annotationConfig:   annotationConfig,
			CosignVerifyConfig: cosignVerifyConfig,
		}
	}
}

type ImageSignatureVerifier struct {
	resBundleRef         string
	onMemoryCacheEnabled bool
	annotationConfig     AnnotationConfig
	identityList         []verificationIdentity

	CosignVerifyConfig
}

func (v *ImageSignatureVerifier) Verify() (bool, string, *int64, error) {
	resBundleRef := v.resBundleRef
	if resBundleRef == "" {
		return false, "", nil, errors.New("no image reference is found")
	}

	verified := false
	signerName := ""
	var signedTimestamp *int64
	var err error
	if v.onMemoryCacheEnabled {
		cacheFound := false
		cacheFoundCount := 0
		allErrs := []string{}
		for i := range v.identityList {
			identity := v.identityList[i]
			// try getting result from cache
			cacheFound, verified, signerName, signedTimestamp, err = v.getResultFromCache(resBundleRef, identity.path)
			// if found and verified true, return it
			if cacheFound {
				cacheFoundCount += 1
				if verified {
					return verified, signerName, signedTimestamp, err
				}
			}
			if err != nil {
				allErrs = append(allErrs, err.Error())
			}
		}
		if !verified && cacheFoundCount == len(v.identityList) {
			return false, "", nil, fmt.Errorf("signature verification failed: %s", strings.Join(allErrs, "; "))
		}
	}

	log.Debug("image signature cache not found")
	allErrs := []string{}
	for i := range v.identityList {
		identity := v.identityList[i]
		// do normal image verification
		verified, signerName, signedTimestamp, err = k8smnfcosign.VerifyImage(resBundleRef, identity.path, v.CertRef, v.CertChain, v.RekorURL, v.OIDCIssuer, v.RootCerts, v.AllowInsecure)

		// cosign keyless returns signerName, so check if it matches the verificationIdentity
		if verified && identity.name != "" {
			if signerName != identity.name {
				verified = false
				err = fmt.Errorf("signature has been verified, but signer name `%s` does not match `%s`", signerName, identity.name)
			}
		}

		if v.onMemoryCacheEnabled {
			// set the result to cache
			v.setResultToCache(resBundleRef, identity.path, verified, signerName, signedTimestamp, err)
		}

		if verified {
			return verified, signerName, signedTimestamp, err
		} else if err != nil {
			allErrs = append(allErrs, err.Error())
		}
	}
	return false, "", nil, NewSignatureVerificationError(fmt.Errorf("signature verification failed: %s", strings.Join(allErrs, "; ")))
}

func (v *ImageSignatureVerifier) getResultFromCache(resBundleRef, pubkey string) (bool, bool, string, *int64, error) {
	key := fmt.Sprintf("cache/verify-image/%s/%s", resBundleRef, pubkey)
	resultNum := 4
	result, err := k8smnfutil.GetCache(key)
	if err != nil {
		// OnMemoryCache.Get() returns an error only when the key was not found
		return false, false, "", nil, nil
	}
	if len(result) != resultNum {
		return false, false, "", nil, fmt.Errorf("cache returns inconsistent data: a length of verify image result must be %v, but got %v", resultNum, len(result))
	}
	verified := false
	signerName := ""
	var signedTimestamp *int64
	if result[0] != nil {
		verified = result[0].(bool)
	}
	if result[1] != nil {
		signerName = result[1].(string)
	}
	if result[2] != nil {
		signedTimestamp = result[2].(*int64)
	}
	if result[3] != nil {
		err = result[3].(error)
	}
	return true, verified, signerName, signedTimestamp, err
}

func (v *ImageSignatureVerifier) setResultToCache(resBundleRef, pubkey string, verified bool, signerName string, signedTimestamp *int64, err error) {
	key := fmt.Sprintf("cache/verify-image/%s/%s", resBundleRef, pubkey)
	setErr := k8smnfutil.SetCache(key, verified, signerName, signedTimestamp, err)
	if setErr != nil {
		log.Warn("cache set error: ", setErr.Error())
	}
}

type BlobSignatureVerifier struct {
	annotations      map[string]string
	resourceRef      string
	annotationConfig AnnotationConfig
	identityList     []verificationIdentity

	CosignVerifyConfig
}

func (v *BlobSignatureVerifier) Verify() (bool, string, *int64, error) {
	sigSets, err := v.getSignatureSets()
	if err != nil {
		return false, "", nil, NewSignatureNotFoundError(errors.Wrap(err, "failed to get signature"))
	}
	if len(sigSets) == 0 {
		return false, "", nil, NewSignatureNotFoundError(nil)
	}

	var verified bool
	var signer string
	allErrs := []string{}
	for i := range v.identityList {
		identity := v.identityList[i]
		var pubkeyPtr *string
		if identity.path != "" {
			pubkeyPtr = &identity.path
		}
		sigType := sigtypes.GetSignatureTypeFromPublicKey(pubkeyPtr)
		if sigType == sigtypes.SigTypeUnknown {
			return false, "", nil, errors.New("failed to judge signature type from public key configuration")
		}
		for j, sigMap := range sigSets {
			sigMapBytes, _ := json.Marshal(sigMap)
			log.Debugf("verifying %v/%v signature set: %s", j+1, len(sigSets), string(sigMapBytes))
			var msgBytes, sigBytes, certBytes, bundleBytes []byte
			if msg, ok := sigMap[defaultMessageAnnotationBaseName]; ok && msg != "" {
				msgBytes = []byte(msg)
			}
			if sig, ok := sigMap[defaultSignatureAnnotationBaseName]; ok && sig != "" {
				sigBytes = []byte(sig)
			}
			if cert, ok := sigMap[defaultCertificateAnnotationBaseName]; ok && cert != "" {
				certBytes = []byte(cert)
			}
			if bundle, ok := sigMap[defaultBundleAnnotationBaseName]; ok && bundle != "" {
				bundleBytes = []byte(bundle)
			}
			switch sigType {
			case sigtypes.SigTypeCosign:
				verified, signer, _, err = k8smnfcosign.VerifyBlob(msgBytes, sigBytes, certBytes, bundleBytes, pubkeyPtr, v.CertRef, v.CertChain, v.RekorURL, v.OIDCIssuer, nil)
			case sigtypes.SigTypePGP:
				verified, signer, _, err = pgp.VerifyBlob(msgBytes, sigBytes, pubkeyPtr)
			case sigtypes.SigTypeX509:
				verified, signer, _, err = x509.VerifyBlob(msgBytes, sigBytes, certBytes, pubkeyPtr)
			}
			// cosign keyless & x509 returns signerName, so check if it matches the verificationIdentity
			if verified && identity.name != "" {
				if signer != identity.name {
					verified = false
					err = fmt.Errorf("signature has been verified, but signer name `%s` does not match `%s`", signer, identity.name)
				}
			}
			if verified {
				// if verified, return the result here
				return verified, signer, nil, err
			} else {
				// otherwise, keep the returned error and try the next signature
				identityName := ""
				if identity.path != "" {
					identityName = fmt.Sprintf("publickey %v/%v", i+1, len(v.identityList))
				} else if identity.name != "" {
					identityName = fmt.Sprintf("signer %v/%v", i+1, len(v.identityList))
				}
				signaturename := fmt.Sprintf("signature %v/%v", j+1, len(sigSets))
				errStr := "verification failed without error"
				if err != nil {
					errStr = err.Error()
				}
				allErrs = append(allErrs, fmt.Sprintf("[%s] [%s] error: %s", identityName, signaturename, errStr))
			}
		}
	}
	allErrsBytes, _ := json.Marshal(allErrs)
	return false, "", nil, NewSignatureVerificationError(fmt.Errorf("verification failed for %v signature. all trials: %s", len(sigSets), string(allErrsBytes)))
}

func (v *BlobSignatureVerifier) getSignatureSets() ([]map[string]string, error) {
	sigSets := []map[string]string{}
	if v.resourceRef != "" {
		cmRef := v.resourceRef
		cm, err := GetConfigMapFromK8sObjectRef(cmRef)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get a configmap")
		}
		msg, ok := cm.Data[defaultMessageAnnotationBaseName]
		if !ok {
			return nil, fmt.Errorf("`%s` is not found in the configmap %s", defaultMessageAnnotationBaseName, cmRef)
		}
		sig, ok := cm.Data[defaultSignatureAnnotationBaseName]
		if !ok {
			return nil, fmt.Errorf("`%s` is not found in the configmap %s", defaultSignatureAnnotationBaseName, cmRef)
		}
		cert := cm.Data[defaultCertificateAnnotationBaseName]
		bundle := cm.Data[defaultBundleAnnotationBaseName]

		sigMap := map[string]string{}
		sigMap[defaultMessageAnnotationBaseName] = msg
		sigMap[defaultSignatureAnnotationBaseName] = sig
		sigMap[defaultCertificateAnnotationBaseName] = cert
		sigMap[defaultBundleAnnotationBaseName] = bundle
		sigSets = append(sigSets, sigMap)
	} else {
		sigSets = v.annotationConfig.GetAllSignatureSets(v.annotations)
	}
	return sigSets, nil
}

// This is an interface for fetching YAML manifest
// a function Fetch() fetches a YAML manifest which matches the input object's kind, name and so on
type ManifestFetcher interface {
	Fetch(objYAMLBytes []byte) ([][]byte, string, error)
}

// return a manifest fetcher.
// `resBundleRef` is used for judging if manifest is inside an image or not.
// `annotationConfig` is used for annotation domain config like "cosign.sigstore.dev".
// `ignoreFields` and `maxResourceManifestNum` are used inside manifest detection logic.
func NewManifestFetcher(resBundleRef, resourceRef string, annotationConfig AnnotationConfig, ignoreFields []string, maxResourceManifestNum int, allowInsecure bool) ManifestFetcher {
	if resBundleRef != "" {
		return &ImageManifestFetcher{resBundleRefString: resBundleRef, AnnotationConfig: annotationConfig, ignoreFields: ignoreFields, maxResourceManifestNum: maxResourceManifestNum, cacheEnabled: true, allowInsecure: allowInsecure}
	} else {
		return &BlobManifestFetcher{AnnotationConfig: annotationConfig, resourceRefString: resourceRef, ignoreFields: ignoreFields, maxResourceManifestNum: maxResourceManifestNum}
	}
}

// ImageManifestFetcher is a fetcher implementation for image reference
type ImageManifestFetcher struct {
	resBundleRefString     string
	AnnotationConfig       AnnotationConfig
	ignoreFields           []string // used by ManifestSearchByValue()
	maxResourceManifestNum int      // used by ManifestSearchByValue()
	cacheEnabled           bool
	allowInsecure          bool
}

func (f *ImageManifestFetcher) Fetch(objYAMLBytes []byte) ([][]byte, string, error) {
	resBundleRefString := f.resBundleRefString
	resBundleRefAnnotationKey := f.AnnotationConfig.ResourceBundleRefAnnotationKey()
	if resBundleRefString == "" {
		annotations := k8smnfutil.GetAnnotationsInYAML(objYAMLBytes)
		if annoResBundleRef, ok := annotations[resBundleRefAnnotationKey]; ok {
			resBundleRefString = annoResBundleRef
		}
	}
	if resBundleRefString == "" {
		return nil, "", NewMessageNotFoundError(errors.New("no image reference is found"))
	}

	var maxResourceManifestNumPtr *int
	if f.maxResourceManifestNum > 0 {
		maxResourceManifestNumPtr = &f.maxResourceManifestNum
	}

	resBundleRefList := k8smnfutil.SplitCommaSeparatedString(resBundleRefString)
	for _, resBundleRef := range resBundleRefList {
		concatYAMLbytes, err := f.fetchManifestInSingleImage(resBundleRef)
		if err != nil {
			return nil, "", err
		}
		found, resourceManifests := k8smnfutil.FindManifestYAML(concatYAMLbytes, objYAMLBytes, maxResourceManifestNumPtr, f.ignoreFields)
		if found {
			return resourceManifests, resBundleRef, nil
		}
	}
	return nil, "", NewMessageNotFoundError(errors.New("failed to find a YAML manifest in the image"))
}

func (f *ImageManifestFetcher) fetchManifestInSingleImage(singleResourceBundleRef string) ([]byte, error) {
	var concatYAMLbytes []byte
	var err error
	if f.cacheEnabled {
		cacheFound := false
		// try getting YAML manifests from cache
		cacheFound, concatYAMLbytes, err = f.getManifestFromCache(singleResourceBundleRef)
		// if cache not found, do fetch and set the result to cache
		if !cacheFound {
			log.Debug("image manifest cache not found")
			// fetch YAML manifests from actual image
			concatYAMLbytes, err = f.getConcatYAMLFromResourceBundleRef(singleResourceBundleRef)
			if err == nil {
				// set the result to cache
				f.setManifestToCache(singleResourceBundleRef, concatYAMLbytes, err)
			}
		}
	} else {
		// fetch YAML manifests from actual image
		concatYAMLbytes, err = f.getConcatYAMLFromResourceBundleRef(singleResourceBundleRef)
	}
	if err != nil {
		return nil, errors.Wrap(err, "failed to get YAMLs in the image")
	}
	return concatYAMLbytes, nil
}

func (f *ImageManifestFetcher) FetchAll() ([][]byte, error) {
	resBundleRefString := f.resBundleRefString
	resBundleRefList := k8smnfutil.SplitCommaSeparatedString(resBundleRefString)

	yamls := [][]byte{}
	for _, resBundleRef := range resBundleRefList {
		concatYAMLbytes, err := f.fetchManifestInSingleImage(resBundleRef)
		if err != nil {
			return nil, err
		}
		yamlsInImage := k8smnfutil.SplitConcatYAMLs(concatYAMLbytes)
		yamls = append(yamls, yamlsInImage...)
	}
	return yamls, nil
}

func (f *ImageManifestFetcher) getConcatYAMLFromResourceBundleRef(resBundleRef string) ([]byte, error) {
	image, err := k8smnfutil.PullImage(resBundleRef, f.allowInsecure)
	if err != nil {
		return nil, err
	}
	concatYAMLbytes, err := k8smnfutil.GenerateConcatYAMLsFromImage(image)
	if err != nil {
		return nil, err
	}
	return concatYAMLbytes, nil
}

func (f *ImageManifestFetcher) getManifestFromCache(resBundleRef string) (bool, []byte, error) {
	key := fmt.Sprintf("cache/fetch-manifest/%s", resBundleRef)
	resultNum := 2
	result, err := k8smnfutil.GetCache(key)
	if err != nil {
		// OnMemoryCache.Get() returns an error only when the key was not found
		return false, nil, nil
	}
	if len(result) != resultNum {
		return false, nil, fmt.Errorf("cache returns inconsistent data: a length of fetch manifest result must be %v, but got %v", resultNum, len(result))
	}
	var concatYAMLbytes []byte
	if result[0] != nil {
		var ok bool
		if concatYAMLbytes, ok = result[0].([]byte); !ok {
			concatYAMLStr := result[0].(string)
			if tmpYAMLbytes, err := base64.StdEncoding.DecodeString(concatYAMLStr); err == nil {
				concatYAMLbytes = tmpYAMLbytes
			}
		}
	}
	if result[1] != nil {
		err = result[1].(error)
	}
	return true, concatYAMLbytes, err
}

func (f *ImageManifestFetcher) setManifestToCache(resBundleRef string, concatYAMLbytes []byte, err error) {
	key := fmt.Sprintf("cache/fetch-manifest/%s", resBundleRef)
	setErr := k8smnfutil.SetCache(key, concatYAMLbytes, err)
	if setErr != nil {
		log.Warn("cache set error: ", setErr.Error())
	}
}

type BlobManifestFetcher struct {
	AnnotationConfig       AnnotationConfig
	resourceRefString      string
	ignoreFields           []string // used by ManifestSearchByValue()
	maxResourceManifestNum int      // used by ManifestSearchByValue()
}

func (f *BlobManifestFetcher) Fetch(objYAMLBytes []byte) ([][]byte, string, error) {
	if f.resourceRefString != "" {
		return f.fetchManifestFromResource(objYAMLBytes)
	}

	annotations := k8smnfutil.GetAnnotationsInYAML(objYAMLBytes)

	messageAnnotationKey := f.AnnotationConfig.MessageAnnotationKey()
	base64Msg, messageFound := annotations[messageAnnotationKey]
	if !messageFound {
		return nil, "", NewMessageNotFoundError(nil)
	}
	gzipMsg, err := base64.StdEncoding.DecodeString(base64Msg)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to decode base64 message in the annotation")
	}
	// `gzipMsg` is a gzip compressed .tar.gz file, so get a tar ball by decompressing it
	gzipTarBall := k8smnfutil.GzipDecompress(gzipMsg)

	yamls, err := k8smnfutil.GetYAMLsInArtifact(gzipTarBall)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to read YAMLs in the gzipped message")
	}

	concatYAMLbytes := k8smnfutil.ConcatenateYAMLs(yamls)

	var maxResourceManifestNumPtr *int
	if f.maxResourceManifestNum > 0 {
		maxResourceManifestNumPtr = &f.maxResourceManifestNum
	}

	found, resourceManifests := k8smnfutil.FindManifestYAML(concatYAMLbytes, objYAMLBytes, maxResourceManifestNumPtr, f.ignoreFields)
	if !found {
		return nil, "", NewMessageNotFoundError(errors.New("failed to find a YAML manifest in the gzipped message"))
	}
	return resourceManifests, SigRefEmbeddedInAnnotation, nil
}

func (f *BlobManifestFetcher) fetchManifestFromResource(objYAMLBytes []byte) ([][]byte, string, error) {
	resourceRefString := f.resourceRefString
	if resourceRefString == "" {
		return nil, "", errors.New("no signature resource reference is specified")
	}

	var maxResourceManifestNumPtr *int
	if f.maxResourceManifestNum > 0 {
		maxResourceManifestNumPtr = &f.maxResourceManifestNum
	}

	resourceRefList := k8smnfutil.SplitCommaSeparatedString(resourceRefString)
	for _, resourceRef := range resourceRefList {
		concatYAMLbytes, err := f.fetchManifestInSingleConfigMap(resourceRef)
		if err != nil {
			return nil, "", err
		}
		found, resourceManifests := k8smnfutil.FindManifestYAML(concatYAMLbytes, objYAMLBytes, maxResourceManifestNumPtr, f.ignoreFields)
		if found {
			return resourceManifests, resourceRef, nil
		}
	}
	return nil, "", errors.New("failed to find a YAML manifest in the specified signature configmaps")
}

func (f *BlobManifestFetcher) fetchManifestInSingleConfigMap(singleCMRef string) ([]byte, error) {
	cm, err := GetConfigMapFromK8sObjectRef(singleCMRef)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get a configmap")
	}
	base64Msg, messageFound := cm.Data[defaultMessageAnnotationBaseName]
	if !messageFound {
		return nil, fmt.Errorf("failed to find `%s` in a configmap %s", defaultMessageAnnotationBaseName, cm.GetName())
	}
	gzipMsg, err := base64.StdEncoding.DecodeString(base64Msg)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode base64 message in the configmap")
	}
	// `gzipMsg` is a gzip compressed .tar.gz file, so get a tar ball by decompressing it
	gzipTarBall := k8smnfutil.GzipDecompress(gzipMsg)

	yamls, err := k8smnfutil.GetYAMLsInArtifact(gzipTarBall)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read YAMLs in the gzipped message")
	}
	concatYAMLbytes := k8smnfutil.ConcatenateYAMLs(yamls)
	return concatYAMLbytes, nil
}

type VerifyResult struct {
	Verified bool                `json:"verified"`
	Signer   string              `json:"signer"`
	Diff     *mapnode.DiffResult `json:"diff"`
}

func (r *VerifyResult) String() string {
	rB, _ := json.Marshal(r)
	return string(rB)
}

func GetConfigMapFromK8sObjectRef(objRef string) (*corev1.ConfigMap, error) {
	kind, ns, name, err := kubeutil.ParseObjectRefInClusterWithKind(objRef)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse a configmap reference")
	}
	if kind != "ConfigMap" && kind != "configmaps" && kind != "cm" {
		return nil, fmt.Errorf("configmap reference must be \"k8s://ConfigMap/[NAMESPACE]/[NAME]\", but got %s", objRef)
	}
	cmObj, err := kubeutil.GetResource("", kind, ns, name)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get a configmap")
	}
	cmBytes, err := json.Marshal(cmObj.Object)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal a configmap")
	}
	var cm *corev1.ConfigMap
	err = json.Unmarshal(cmBytes, &cm)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal a configmap bytes")
	}
	return cm, nil
}
