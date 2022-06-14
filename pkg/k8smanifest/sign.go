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
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/sigstore/cosign/pkg/cosign"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	k8scosign "github.com/sigstore/k8s-manifest-sigstore/pkg/cosign"
	k8ssigutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
)

const DefaultAnnotationKeyDomain = "cosign.sigstore.dev"

const (
	defaultMessageAnnotationBaseName           = "message"
	defaultSignatureAnnotationBaseName         = "signature"
	defaultCertificateAnnotationBaseName       = "certificate"
	defaultBundleAnnotationBaseName            = "bundle"
	defaultResourceBundleRefAnnotationBaseName = "resourceBundleRef"
)

func Sign(inputDir string, so *SignOption) ([]byte, error) {

	defaultTarballOption := true // this will be `false` in v0.5.0
	if so.Tarball == nil {
		so.Tarball = &defaultTarballOption
	}
	makeTarball := *(so.Tarball)
	if makeTarball {
		log.Warn("[DEPRECATED] The current signing method which makes a tarball for signing is deprecated in v0.3.1+, and will be unavailable in v0.5.0. You can use the new method by `--tarball=no` from CLI or `Tarball: &(false)` in SignOption from codes.")
	}

	output := ""
	if so.UpdateAnnotation {
		output = so.Output
	}

	signedBytes, err := NewSigner(so.ImageRef, so.KeyPath, so.CertPath, output, so.AppendSignature, so.ApplySigConfigMap, makeTarball, so.AnnotationConfig, so.PassFunc).Sign(inputDir, output, so.ImageAnnotations)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign the specified content")
	}

	return signedBytes, nil
}

type Signer interface {
	Sign(inputDir, output string, imageAnnotations map[string]interface{}) ([]byte, error)
}

func NewSigner(imageRef, keyPath, certPath, output string, appendSig, doApply, tarball bool, AnnotationConfig AnnotationConfig, pf cosign.PassFunc) Signer {
	var prikeyPath *string
	if keyPath != "" {
		prikeyPath = &keyPath
	}
	var certPathP *string
	if certPath != "" {
		certPathP = &certPath
	}
	createSigConfigMap := false
	if strings.HasPrefix(output, kubeutil.InClusterObjectPrefix) {
		createSigConfigMap = true
	}
	if imageRef != "" {
		return &ImageSigner{AnnotationConfig: AnnotationConfig, imageRef: imageRef, tarball: tarball, prikeyPath: prikeyPath, certPath: certPathP, passFunc: pf}
	} else {
		return &BlobSigner{AnnotationConfig: AnnotationConfig, createSigConfigMap: createSigConfigMap, appendSig: appendSig, doApply: doApply, tarball: tarball, prikeyPath: prikeyPath, certPath: certPathP, passFunc: pf}
	}
}

type ImageSigner struct {
	AnnotationConfig AnnotationConfig
	tarball          bool
	imageRef         string
	prikeyPath       *string
	certPath         *string
	passFunc         cosign.PassFunc
}

func (s *ImageSigner) Sign(inputDir, output string, imageAnnotations map[string]interface{}) ([]byte, error) {
	var inputDataBuffer bytes.Buffer
	var moClean, moImage *k8ssigutil.MutateOptions
	moClean = getMutationOptionForClean(s.AnnotationConfig)
	if len(imageAnnotations) > 0 {
		moImage = &k8ssigutil.MutateOptions{AW: embedAnnotation, Annotations: imageAnnotations}
	}
	var err error
	if s.tarball {
		err = k8ssigutil.TarGzCompress(inputDir, &inputDataBuffer, mo)
		if err != nil {
			return nil, errors.Wrap(err, "failed to compress an input file/dir")
		}
	} else {
		err = makeMessageYAML(inputDir, &inputDataBuffer, mo)
		if err != nil {
			return nil, errors.Wrap(err, "failed to make a message YAML from the input file/dir")
		}
	}
	var signedBytes []byte
	// upload files as image
	err = uploadFileToRegistry(inputDataBuffer.Bytes(), s.imageRef)
	if err != nil {
		return nil, errors.Wrap(err, "failed to upload image with manifest")
	}
	// sign the image
	err = k8scosign.SignImage(s.imageRef, s.prikeyPath, s.certPath, s.passFunc, imageAnnotations)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign image")
	}
	if output != "" {
		// generate a signed YAML file
		signedBytes, err = generateSignedYAMLManifest(inputDir, s.imageRef, nil, false, imageAnnotations, s.AnnotationConfig)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate a signed YAML")
		}
		err = ioutil.WriteFile(output, signedBytes, 0644)
		if err != nil {
			return nil, errors.Wrap(err, "failed to write a signed YAML into")
		}
	}
	return signedBytes, nil
}

type BlobSigner struct {
	AnnotationConfig   AnnotationConfig
	createSigConfigMap bool
	appendSig          bool
	doApply            bool
	tarball            bool
	prikeyPath         *string
	certPath           *string
	passFunc           cosign.PassFunc
}

func (s *BlobSigner) Sign(inputDir, output string, imageAnnotations map[string]interface{}) ([]byte, error) {
	var inputDataBuffer bytes.Buffer
	dir, err := ioutil.TempDir("", "kubectl-sigstore-temp-dir")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a temporary directory for signing")
	}
	defer os.RemoveAll(dir)
	tmpBlobFile := filepath.Join(dir, "tmp-blob-file")

	var moClean, moImage *k8ssigutil.MutateOptions
	moClean = getMutationOptionForClean(s.AnnotationConfig)
	if len(imageAnnotations) > 0 {
		moImage = &k8ssigutil.MutateOptions{AW: embedAnnotation, Annotations: imageAnnotations}
	}

	if s.tarball {
		err = k8ssigutil.TarGzCompress(inputDir, &inputDataBuffer, mo)
		if err != nil {
			return nil, errors.Wrap(err, "failed to compress an input file/dir")
		}
	} else {
		err = makeMessageYAML(inputDir, &inputDataBuffer, mo)
		if err != nil {
			return nil, errors.Wrap(err, "failed to make a message YAML from the input file/dir")
		}
	}
	var signedBytes []byte
	var sigMaps map[string][]byte
	err = ioutil.WriteFile(tmpBlobFile, inputDataBuffer.Bytes(), 0777)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create a temporary blob file")
	}
	sigMaps, err = k8scosign.SignBlob(tmpBlobFile, s.prikeyPath, s.certPath, s.passFunc)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign a blob file")
	}
	if s.createSigConfigMap {
		cm, err := generateSignatureConfigMap(output, sigMaps)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate a signature configmap")
		}
		if s.doApply {
			signedBytes, err = applySignatureConfigMap(output, cm)
			if err != nil {
				return nil, errors.Wrap(err, "failed to apply a signature configmap")
			}
		} else {
			signedBytes, err = yaml.Marshal(cm)
			if err != nil {
				return nil, errors.Wrap(err, "failed to marshal a signature configmap")
			}
			sigResOutput := K8sResourceRef2FileName(output)
			err = ioutil.WriteFile(sigResOutput, signedBytes, 0644)
			if err != nil {
				return nil, errors.Wrap(err, "failed to create a signature configmap YAML")
			}
		}
	} else {
		// generate a signed YAML file
		signedBytes, err = generateSignedYAMLManifest(inputDir, "", sigMaps, s.appendSig, imageAnnotations, s.AnnotationConfig)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate a signed YAML")
		}
		err = ioutil.WriteFile(output, signedBytes, 0644)
		if err != nil {
			return nil, errors.Wrap(err, "failed to write a signed YAML into")
		}
	}
	return signedBytes, nil
}

// load the input dir/file, remove signature annotations and generate a single yaml with all the resources
func makeMessageYAML(inputDir string, outBuffer *bytes.Buffer, moList ...*k8ssigutil.MutateOptions) error {
	yamls, err := k8ssigutil.LoadYAMLsInDirWithMutationOptions(inputDir, moList...)
	if err != nil {
		return errors.Wrap(err, "failed to load an input file/dir")
	}
	singleYAML := k8ssigutil.ConcatenateYAMLs(yamls)
	_, err = outBuffer.Write(singleYAML)
	if err != nil {
		return errors.Wrap(err, "failed to write loaded yaml into buffer")
	}
	return nil
}

func uploadFileToRegistry(inputData []byte, imageRef string) error {
	dir, err := ioutil.TempDir("", "kubectl-sigstore-temp-dir")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	fpath := filepath.Join(dir, "manifest.yaml")
	err = ioutil.WriteFile(fpath, inputData, 0644)
	if err != nil {
		return err
	}

	files := []cremote.File{cremote.FileFromFlag(fpath)}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	mediaTypeGetter := cremote.DefaultMediaTypeGetter
	remoteAuthOption := remote.WithAuthFromKeychain(authn.DefaultKeychain)
	remoteContextOption := remote.WithContext(context.Background())
	_, err = cremote.UploadFiles(ref, files, mediaTypeGetter, remoteAuthOption, remoteContextOption)
	if err != nil {
		return err
	}
	return nil
}

func generateSignatureConfigMap(sigResRef string, sigMaps map[string][]byte) (*corev1.ConfigMap, error) {
	kind, ns, name, err := kubeutil.ParseObjectRefInClusterWithKind(sigResRef)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse a signature configmap reference `%s`", sigResRef)
	}
	if kind != "ConfigMap" && kind != "configmaps" && kind != "cm" {
		return nil, errors.Wrapf(err, "output k8s reference must be k8s://ConfigMap/[NAMESPACE]/[NAME], but got `%s`", sigResRef)
	}
	sigData := map[string]string{}
	for k, v := range sigMaps {
		sigData[k] = string(v)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
		},
		Data: sigData,
	}
	return cm, nil
}

func generateSignedYAMLManifest(inputDir, imageRef string, sigMaps map[string][]byte, appendSig bool, imageAnnotations map[string]interface{}, AnnotationConfig AnnotationConfig) ([]byte, error) {
	if imageRef == "" && len(sigMaps) == 0 {
		return nil, errors.New("either image ref or signature infos are required for generating a signed YAML")
	}

	yamls, err := k8ssigutil.FindYAMLsInDir(inputDir)
	if err != nil {
		return nil, err
	}
	// convert any type of YAMLs into a list of single resource YAMLs
	tmpYAMLs := [][]byte{}
	for _, singleYAML := range yamls {
		if k8ssigutil.IsConcatYAMLs(singleYAML) {
			yamlsInSingle := k8ssigutil.SplitConcatYAMLs(singleYAML)
			tmpYAMLs = append(tmpYAMLs, yamlsInSingle...)
		} else {
			tmpYAMLs = append(tmpYAMLs, singleYAML)
		}
	}
	yamls = tmpYAMLs

	commonAnnotationMap := map[string]interface{}{}
	if imageRef != "" {
		resBundleRefAnnotationKey := AnnotationConfig.ResourceBundleRefAnnotationKey()
		commonAnnotationMap[resBundleRefAnnotationKey] = imageRef
	}
	for k, v := range imageAnnotations {
		commonAnnotationMap[k] = v
	}
	// if appendSig is false, then signature is embedded into a fixed annotation `<DOMAIN>/signature`
	if !appendSig {
		annotationKeyMap := AnnotationConfig.AnnotationKeyMap(0)
		for k, v := range sigMaps {
			if annoKey, ok := annotationKeyMap[k]; ok {
				commonAnnotationMap[annoKey] = string(v)
			}
		}
	}

	signedYAMLs := [][]byte{}
	sumErr := []string{}
	for _, yaml := range yamls {
		annotationMap := map[string]interface{}{}
		for k, v := range commonAnnotationMap {
			annotationMap[k] = v
		}
		// if appendSig is true, then signature is appended like `<DOMAIN>/signature_1` on top of current sigs
		if appendSig {
			annotations := k8ssigutil.GetAnnotationsInYAML(yaml)
			sigSets := AnnotationConfig.GetAllSignatureSets(annotations)
			annotationKeyMap := AnnotationConfig.AnnotationKeyMap(len(sigSets))
			for k, v := range sigMaps {
				if annoKey, ok := annotationKeyMap[k]; ok {
					annotationMap[annoKey] = string(v)
				}
			}
		}

		signedYAML, err := embedAnnotation(yaml, annotationMap)
		if err != nil {
			sumErr = append(sumErr, err.Error())
			continue
		}
		signedYAMLs = append(signedYAMLs, signedYAML)
	}
	if len(signedYAMLs) == 0 && len(sumErr) > 0 {
		return nil, errors.New(fmt.Sprintf("failed to embed annotation to YAMLs; %s", strings.Join(sumErr, "; ")))
	}
	signedConcatYAML := k8ssigutil.ConcatenateYAMLs(signedYAMLs)
	return signedConcatYAML, nil
}

func embedAnnotation(yamlBytes []byte, annotationMap map[string]interface{}) ([]byte, error) {
	yamls := [][]byte{}
	if k8ssigutil.IsConcatYAMLs(yamlBytes) {
		yamls = k8ssigutil.SplitConcatYAMLs(yamlBytes)
	} else {
		yamls = append(yamls, yamlBytes)
	}

	embedYAMLs := [][]byte{}
	for _, yaml := range yamls {
		orgNode, err := mapnode.NewFromYamlBytes(yaml)
		if err != nil {
			return nil, err
		}
		metadataMap := map[string]interface{}{
			"metadata": map[string]interface{}{
				"annotations": annotationMap,
			},
		}
		annotationNode, err := mapnode.NewFromMap(metadataMap)
		if err != nil {
			return nil, err
		}
		embedNode, err := orgNode.Merge(annotationNode)
		if err != nil {
			return nil, err
		}
		embedYamlBytes := embedNode.ToYaml()
		embedYAMLs = append(embedYAMLs, []byte(embedYamlBytes))
	}
	embedConcatYAMLs := k8ssigutil.ConcatenateYAMLs(embedYAMLs)

	return embedConcatYAMLs, nil
}

// this mutation option removes signature annotations in the original YAML manifest
// when generating message which will be signed later
func getMutationOptionForClean(annoCfg AnnotationConfig) *k8ssigutil.MutateOptions {
	annotationMaskMap := map[string]interface{}{}
	for _, annotationFullKey := range annoCfg.AnnotationKeyMask() {
		// any value is fine because it is not used, so use true here
		annotationMaskMap[annotationFullKey] = true
	}
	return &k8ssigutil.MutateOptions{
		AW:          removeSignatureAnnotation,
		Annotations: annotationMaskMap,
	}
}

// signature annotations should be ignored when generating message data
// this function is used for this purpose
func removeSignatureAnnotation(yamlBytes []byte, annotationMap map[string]interface{}) ([]byte, error) {
	yamls := [][]byte{}
	if k8ssigutil.IsConcatYAMLs(yamlBytes) {
		yamls = k8ssigutil.SplitConcatYAMLs(yamlBytes)
	} else {
		yamls = append(yamls, yamlBytes)
	}

	maskedYAMLs := [][]byte{}
	for _, yaml := range yamls {
		orgNode, err := mapnode.NewFromYamlBytes(yaml)
		if err != nil {
			return nil, err
		}
		sigAnnotationMask := []string{}
		for k := range annotationMap {
			sigAnnotationMask = append(sigAnnotationMask, k)
		}
		maskedNode := orgNode.Mask(sigAnnotationMask)
		annotationNode, _ := maskedNode.GetNode("metadata.annotations")
		if annotationNode.Size() == 0 {
			maskedNode = maskedNode.Mask([]string{"metadata.annotations"})
		}
		maskedYamlBytes := maskedNode.ToYaml()
		maskedYAMLs = append(maskedYAMLs, []byte(maskedYamlBytes))
	}
	maskedConcatYAMLs := k8ssigutil.ConcatenateYAMLs(maskedYAMLs)
	return maskedConcatYAMLs, nil
}

func applySignatureConfigMap(configMapRef string, newCM *corev1.ConfigMap) ([]byte, error) {
	create := false
	currentCM, _ := GetConfigMapFromK8sObjectRef(configMapRef)
	if currentCM == nil {
		create = true
	}
	namespace := newCM.GetNamespace()
	kcfg, err := kubeutil.GetKubeConfig()
	if err != nil {
		return nil, err
	}
	v1client, err := corev1client.NewForConfig(kcfg)
	if err != nil {
		return nil, err
	}
	var applied *corev1.ConfigMap
	if create {
		applied, err = v1client.ConfigMaps(namespace).Create(context.Background(), newCM, metav1.CreateOptions{})
	} else {
		currentCM.Data = newCM.Data
		updatedCM := currentCM
		applied, err = v1client.ConfigMaps(namespace).Update(context.Background(), updatedCM, metav1.UpdateOptions{})
	}
	if err != nil {
		return nil, err
	}
	appliedBytes, err := yaml.Marshal(applied)
	if err != nil {
		return nil, err
	}
	return appliedBytes, nil
}

// sanitize resrouce ref as a filename
// e.g.) k8s://ConfigMap/sample-ns/sample-cm --> k8s_ConfigMap_sample-ns_sample-cm.yaml
func K8sResourceRef2FileName(resRef string) string {
	return strings.ReplaceAll(strings.ReplaceAll(resRef, kubeutil.InClusterObjectPrefix, "k8s/"), "/", "_") + ".yaml"
}
