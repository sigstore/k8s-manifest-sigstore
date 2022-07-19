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

package cli

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/ghodss/yaml"
	gkmatch "github.com/open-policy-agent/gatekeeper/pkg/mutation/match"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8ssigutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metatable "k8s.io/apimachinery/pkg/api/meta/table"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

const (
	resultAPIVersion = "cosign.sigstore.dev/v1alpha1" // use this only for output result as json/yaml
	resultKind       = "VerifyResourceResult"         // use this only for output result as json/yaml
)

const (
	configTypeFile       = "file"
	configTypeConstraint = "constraint"
	configTypeConfigMap  = "configmap"
)

const (
	defaultConfigKindForConfigMap  = "ConfigMap"
	defaultConfigKindForConstraint = "ManifestIntegrityConstraint"
)

const (
	defaultConfigFieldPathConstraint = "spec.parameters"
	defaultConfigFieldPathConfigMap  = "data.\"config.yaml\""

	defaultMatchFieldPathConstraint                  = "spec.match"
	defaultInScopeObjectParameterFieldPathConstraint = "spec.parameters.inScopeObjects"
)

const (
	defaultManifetBundleNamespace = "manifest-bundles"
)

var supportedOutputFormat = map[string]bool{"json": true, "yaml": true}

var OSExit = os.Exit

func NewCmdVerifyResource() *cobra.Command {

	var filename string
	var resBundleRef string
	var sigResRef string
	var keyPath string
	var configPath string
	var configType string
	var configKind string
	var configName string
	var configNamespace string
	var configField string
	var outputFormat string
	var manifestYAMLs [][]byte
	var disableDefaultConfig bool
	var provenance bool
	var provResRef string
	var manifestBundleResRef string
	var concurrencyNum int64
	var certRef string
	var certChain string
	var rekorURL string
	var oidcIssuer string
	cmd := &cobra.Command{
		Use:   "verify-resource (RESOURCE/NAME | -f FILENAME | -i IMAGE)",
		Short: "A command to verify Kubernetes manifests of resources on cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			kubeGetArgs := args
			err = KOptions.InitGet(cmd)
			if err != nil {
				log.Fatalf("error occurred during verify-resource initialization: %s", err.Error())
			}

			if filename != "" && filename != "-" {
				manifestYAMLs, err = readManifestYAMLFile(filename)
				if err != nil {
					log.Fatalf("error occurred during reading manifest YAML file: %s", err.Error())
				}
			} else if filename == "-" {
				manifestYAMLs, err = readStdinAsYAMLs()
				if err != nil {
					log.Fatalf("error occurred during reading manifest YAML from stdin: %s", err.Error())
				}
			}

			configPath, configField = getConfigPathFromConfigFlags(configPath, configType, configKind, configName, configNamespace, configField)

			if manifestBundleResRef != "" {
				sigResRef = manifestBundleResRef
				provResRef = manifestBundleResRef
			}

			allVerified, err := verifyResource(manifestYAMLs, kubeGetArgs, resBundleRef, sigResRef, keyPath, configPath, configField, configType, disableDefaultConfig, provenance, provResRef, certRef, certChain, rekorURL, oidcIssuer, outputFormat, concurrencyNum)
			if err != nil {
				log.Fatalf("error occurred during verify-resource: %s", err.Error())
			}
			if !allVerified {
				OSExit(1)
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&filename, "filename", "f", "", "manifest filename (this can be \"-\", then read a file from stdin)")
	cmd.PersistentFlags().StringVarP(&resBundleRef, "image", "i", "", "a comma-separated list of signed image names that contains YAML manifests")
	cmd.PersistentFlags().StringVar(&sigResRef, "signature-resource", "", "a comma-separated list of configmaps that contains message, signature and some others")
	cmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "a comma-separated list of paths to public keys or environment variable names start with \"env://\" (if empty, do key-less verification)")
	cmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "path to verification config YAML file or k8s object identifier like k8s://[KIND]/[NAMESPACE]/[NAME]")
	cmd.PersistentFlags().StringVar(&configType, "config-type", "file", "a type of config, one of the following: \"file\", \"constraint\" or \"configmap\"")
	cmd.PersistentFlags().StringVar(&configKind, "config-kind", "", "a kind of config resource in a cluster, only valid when --config-type is \"constraint\" or \"configmap\"")
	cmd.PersistentFlags().StringVar(&configName, "config-name", "", "a name of config resource in a cluster, only valid when --config-type is \"constraint\" or \"configmap\"")
	cmd.PersistentFlags().StringVar(&configNamespace, "config-namespace", "", "a namespace of config resource in a cluster, only valid when --config-type is \"constraint\" or \"configmap\"")
	cmd.PersistentFlags().StringVar(&configField, "config-field", "", "field of config data (e.g. `data.\"config.yaml\"` in a ConfigMap, `spec.parameters` in a constraint)")
	cmd.PersistentFlags().BoolVar(&disableDefaultConfig, "disable-default-config", false, "if true, disable default ignore fields configuration (default to false)")
	cmd.PersistentFlags().Int64Var(&concurrencyNum, "max-concurrency", 4, "number of concurrency for verifying multiple resources. If negative, use num of CPU cores.")
	cmd.PersistentFlags().BoolVar(&provenance, "provenance", false, "if true, show provenance data (default to false)")
	cmd.PersistentFlags().StringVar(&provResRef, "provenance-resource", "", "a comma-separated list of configmaps that contains attestation, sbom")
	cmd.PersistentFlags().StringVar(&manifestBundleResRef, "manifest-bundle-resource", "", "a comma-separated list of configmaps that contains signature, message, attestation, sbom")
	cmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "", "output format string, either \"json\" or \"yaml\" (if empty, a result is shown as a table)")

	// the following flags are based on cosign verify command
	cmd.PersistentFlags().StringVar(&certRef, "certificate", "", "path to the public certificate")
	cmd.PersistentFlags().StringVar(&certChain, "certificate-chain", "", "path to a list of CA certificates in PEM format which will be needed when building the certificate chain for the signing certificate. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate")
	cmd.PersistentFlags().StringVar(&rekorURL, "rekor-url", "https://rekor.sigstore.dev", "URL of rekor STL server (default \"https://rekor.sigstore.dev\")")
	cmd.PersistentFlags().StringVar(&oidcIssuer, "oidc-issuer", "", "the OIDC issuer expected in a valid Fulcio certificate, e.g. https://token.actions.githubusercontent.com or https://oauth2.sigstore.dev/auth")

	KOptions.ConfigFlags.AddFlags(cmd.PersistentFlags())
	return cmd
}

func verifyResource(yamls [][]byte, kubeGetArgs []string, resBundleRef, sigResRef, keyPath, configPath, configField, configType string, disableDefaultConfig, provenance bool, provResRef, certRef, certChain, rekorURL, oidcIssuer, outputFormat string, concurrencyNum int64) (bool, error) {
	var err error
	start := time.Now().UTC()
	if outputFormat != "" {
		if !supportedOutputFormat[outputFormat] {
			return false, fmt.Errorf("output format `%s` is not supported", outputFormat)
		}
	}

	var vo *k8smanifest.VerifyResourceOption
	if configPath == "" && disableDefaultConfig {
		vo = &k8smanifest.VerifyResourceOption{}
	} else if configPath == "" {
		vo = k8smanifest.LoadDefaultConfig()
	} else if strings.HasPrefix(configPath, kubeutil.InClusterObjectPrefix) {
		vo, err = k8smanifest.LoadVerifyResourceConfigFromResource(configPath, configField)
		if err != nil {
			return false, errors.Wrapf(err, "failed to load verify-resource config from resource %s", configPath)
		}
		if !disableDefaultConfig {
			vo = k8smanifest.AddDefaultConfig(vo)
		}
	} else {
		vo, err = k8smanifest.LoadVerifyResourceConfig(configPath)
		if err != nil {
			return false, errors.Wrapf(err, "failed to load verify-resource config from %s", configPath)
		}
		if !disableDefaultConfig {
			vo = k8smanifest.AddDefaultConfig(vo)
		}
	}
	// add signature/message/others annotations to ignore fields
	vo.SetAnnotationIgnoreFields()

	if outputFormat == "" {
		log.Info("identifying target resources.")
	}
	objs := []unstructured.Unstructured{}
	if configType == configTypeConstraint {
		objs, err = getObjsByConstraintWithCache(configPath, defaultMatchFieldPathConstraint, defaultInScopeObjectParameterFieldPathConstraint, concurrencyNum)
	} else if len(kubeGetArgs) > 0 {
		objs, err = KOptions.Get(kubeGetArgs, "")
	} else if yamls != nil {
		objs, err = getObjsFromManifests(yamls, vo.IgnoreFields)
	} else if resBundleRef != "" {
		manifestFetcher := k8smanifest.NewManifestFetcher(resBundleRef, "", vo.AnnotationConfig, nil, vo.MaxResourceManifestNum)
		imageManifestFetcher := manifestFetcher.(*k8smanifest.ImageManifestFetcher)
		var yamlsInImage [][]byte
		if yamlsInImage, err = imageManifestFetcher.FetchAll(); err == nil {
			objs, err = getObjsFromManifests(yamlsInImage, vo.IgnoreFields)
		}
	}
	if err != nil {
		return false, errors.Wrap(err, "failed to get objects in cluster")
	}

	if resBundleRef != "" {
		vo.ResourceBundleRef = resBundleRef
	}
	if sigResRef != "" {
		vo.SignatureResourceRef = validateConfigMapRef(sigResRef)
	}
	if keyPath != "" {
		vo.KeyPath = keyPath
	}
	if provenance {
		vo.Provenance = true
	}
	if provResRef != "" {
		vo.ProvenanceResourceRef = validateConfigMapRef(provResRef)
	}
	vo.Certificate = certRef
	vo.CertificateChain = certChain
	vo.RekorURL = rekorURL
	vo.OIDCIssuer = oidcIssuer

	imagesToBeused := getAllImagesToBeUsed(vo.ResourceBundleRef, objs, vo.AnnotationConfig, vo.Provenance)

	if outputFormat == "" {
		log.Info("loading some required data.")
	}
	// register functions to connect remote registry or server
	prepareFuncs := []reflect.Value{}
	for i := range imagesToBeused {
		img := imagesToBeused[i]
		// manifest fetch functions
		if img.imageType == k8smanifest.ArtifactManifestImage {
			manifestFetcher := k8smanifest.NewManifestFetcher(img.ResourceBundleRef, "", vo.AnnotationConfig, nil, 0)
			if fetcher, ok := manifestFetcher.(*k8smanifest.ImageManifestFetcher); ok {
				prepareFuncs = append(prepareFuncs, reflect.ValueOf(fetcher.FetchAll))
			}
		}

		var keyPath *string
		if vo.KeyPath != "" {
			keyPath = &(vo.KeyPath)
		}
		var signers []string
		if len(vo.Signers) > 0 {
			signers = vo.Signers
		}
		// signature verification functions
		cosignVerifyConfig := k8smanifest.CosignVerifyConfig{
			CertRef:    certRef,
			CertChain:  certChain,
			RekorURL:   rekorURL,
			OIDCIssuer: oidcIssuer,
		}
		sigVerifier := k8smanifest.NewSignatureVerifier(nil, img.ResourceBundleRef, keyPath, signers, cosignVerifyConfig, vo.AnnotationConfig)
		if verifier, ok := sigVerifier.(*k8smanifest.ImageSignatureVerifier); ok {
			prepareFuncs = append(prepareFuncs, reflect.ValueOf(verifier.Verify))
		}

		if vo.Provenance {
			// provenance functions
			provGetter := k8smanifest.NewProvenanceGetter(nil, img.ResourceBundleRef, img.Digest, "")
			if getter, ok := provGetter.(*k8smanifest.ImageProvenanceGetter); ok {
				prepareFuncs = append(prepareFuncs, reflect.ValueOf(getter.Get))
			}
		}
	}

	// execute image pull and prepate cache for them
	eg1 := errgroup.Group{}
	if concurrencyNum < 1 {
		concurrencyNum = int64(runtime.NumCPU())
	}
	sem := semaphore.NewWeighted(concurrencyNum)
	for i := range prepareFuncs {
		pf := prepareFuncs[i]
		_ = sem.Acquire(context.Background(), 1)
		eg1.Go(func() error {
			if pf.Type().Kind() != reflect.Func {
				return fmt.Errorf("failed to call preparation function; this is not a function, but %s", pf.Type().Kind().String())
			}
			_ = pf.Call(nil)
			sem.Release(1)
			return nil
		})
	}
	if err = eg1.Wait(); err != nil {
		return false, errors.Wrap(err, "error in executing preparaction for verify-resource")
	}

	if outputFormat == "" {
		log.Info("verifying the resources.")
	}
	// execute verify-resource by using prepared cache
	preVerifyResource := time.Now().UTC()
	eg2 := errgroup.Group{}
	mutex := sync.Mutex{}
	results := []resourceResult{}
	for i := range objs {
		obj := objs[i]
		_ = sem.Acquire(context.Background(), 1)
		eg2.Go(func() error {
			log.Debug("checking kind: ", obj.GetKind(), ", name: ", obj.GetName())
			vResult, err := k8smanifest.VerifyResource(obj, vo)
			r := resourceResult{
				Object: obj,
			}
			if err == nil {
				r.Result = vResult
			} else {
				r.Error = err
			}
			log.Debug("result: ", r)
			mutex.Lock()
			results = append(results, r)
			mutex.Unlock()

			sem.Release(1)
			return nil
		})

	}
	if err = eg2.Wait(); err != nil {
		return false, errors.Wrap(err, "error in executing verify-resource")
	}
	postVerifyResource := time.Now().UTC()

	var resultBytes []byte
	summarizedResult := NewVerifyResourceResult(results, vo.Provenance)
	if outputFormat == "" {
		resultBytes = makeResultTable(summarizedResult, vo.Provenance)
	} else if outputFormat == "json" {
		resultBytes, _ = json.MarshalIndent(summarizedResult, "", "    ") // pretty print json as well as kubectl get -o json
	} else if outputFormat == "yaml" {
		resultBytes, _ = yaml.Marshal(summarizedResult)
	}

	fmt.Println(string(resultBytes))

	allVerified := summarizedResult.Summary.Total == summarizedResult.Summary.Valid
	finish := time.Now().UTC()

	if outputFormat == "" {
		log.Infof("Total elapsed time: %vs (initialize: %vs, verify: %vs, print: %vs)", finish.Sub(start).Seconds(), preVerifyResource.Sub(start).Seconds(), postVerifyResource.Sub(preVerifyResource).Seconds(), finish.Sub(postVerifyResource).Seconds())
	}
	return allVerified, nil
}

func readManifestYAMLFile(fpath string) ([][]byte, error) {
	var yamls [][]byte
	content, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	yamls = k8ssigutil.SplitConcatYAMLs(content)
	return yamls, nil
}

func readStdinAsYAMLs() ([][]byte, error) {
	stdinBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}

	yamls := [][]byte{}
	if k8ssigutil.IsConcatYAMLs(stdinBytes) {
		yamls = k8ssigutil.SplitConcatYAMLs(stdinBytes)
	} else {
		var tmpObj unstructured.Unstructured
		err = yaml.Unmarshal(stdinBytes, &tmpObj)
		if err != nil {
			return nil, err
		}

		if tmpObj.IsList() {
			objList, _ := tmpObj.ToList()
			for _, obj := range objList.Items {
				objYAML, _ := yaml.Marshal(obj.Object)
				yamls = append(yamls, objYAML)
			}
		} else {
			yamls = append(yamls, stdinBytes)
		}
	}

	if len(yamls) == 0 {
		return nil, nil
	}
	return yamls, nil
}

// By checking `yamls`, try finding the corresponding resources on a cluster.
// This returns a list of existing K8s resources that will be verified with VerifyResource().
func getObjsFromManifests(yamls [][]byte, ignoreFieldConfig k8smanifest.ObjectFieldBindingList) ([]unstructured.Unstructured, error) {
	sumErr := []string{}
	manifestObjs := []unstructured.Unstructured{}
	for _, objyaml := range yamls {
		var tmpObj unstructured.Unstructured
		tmpErr := yaml.Unmarshal(objyaml, &tmpObj)
		if tmpErr != nil {
			sumErr = append(sumErr, tmpErr.Error())
		}
		manifestObjs = append(manifestObjs, tmpObj)
	}
	if len(manifestObjs) == 0 && len(sumErr) > 0 {
		return nil, fmt.Errorf("failed to read stdin data as resource YAMLs: %s", strings.Join(sumErr, "; "))
	}

	objs := []unstructured.Unstructured{}
	allErrs := []string{}
	objsInClusterByKindAndNamespace := map[string][]unstructured.Unstructured{}
	for _, mnfobj := range manifestObjs {
		kind := mnfobj.GetKind()
		namespaceInManifest := mnfobj.GetNamespace()
		key := fmt.Sprintf("%s/%s", namespaceInManifest, kind)
		objsInCluster, ok := objsInClusterByKindAndNamespace[key]
		if !ok {
			args := []string{kind}
			// if ns is empty, use a namespace of kubeconfig context
			tmpObjs, err := KOptions.Get(args, namespaceInManifest)
			if err != nil {
				allErrs = append(allErrs, err.Error())
				continue
			}
			objsInCluster = tmpObjs
			objsInClusterByKindAndNamespace[key] = objsInCluster
		}

		_, ignoreFields := ignoreFieldConfig.Match(mnfobj)
		concatYAML := objsToConcatYAML(objsInCluster)
		mnfBytes, _ := yaml.Marshal(mnfobj.Object)
		// log.Debugf("concatYAML: %s", string(concatYAML))
		log.Debugf("mnfBytes: %s", string(mnfBytes))
		found, resourceManifests := k8ssigutil.FindManifestYAML(concatYAML, mnfBytes, nil, ignoreFields)
		if !found {
			allErrs = append(allErrs, fmt.Sprintf("failed to find a resource: kind: %s, namespace: %s, name: %s", mnfobj.GetKind(), mnfobj.GetNamespace(), mnfobj.GetName()))
			continue
		}
		foundObjBytes := resourceManifests[0]
		var foundObj unstructured.Unstructured
		err := yaml.Unmarshal(foundObjBytes, &foundObj)
		if err != nil {
			allErrs = append(allErrs, errors.Wrap(err, "failed to Unmarshal a found object").Error())
			continue
		}
		objs = append(objs, foundObj)
	}
	if len(allErrs) > 0 {
		log.Debugf("error in getObjsFromManifests() for manifests: %s", strings.Join(allErrs, "; "))
	}
	if len(objs) == 0 && len(allErrs) > 0 {
		return nil, fmt.Errorf("error occurred during getting resources: %s", strings.Join(allErrs, "; "))
	}
	return objs, nil
}

// By checking constraint match conditions, try finding the matched resources on a cluster.
// This returns a list of existing K8s resources that will be verified with VerifyResource().
// [Detail Steps]
// 1. get Constraint resource from cluster and extract its gatekeeper match condition and `inScopeObjects` in parameters
// 2. list kinds in the match condition and check its scope
// 3. get all namespaces in a cluster and extract some of them that match the match condition
// 4. check ExcludeNamespace conditions if exist
// 5. list existing resources by kind in a namespace. do this for all selected kinds and namespaces
// 6. check inScopeOpject condition if exists
func getObjsByConstraint(constraintRef, matchField, inscopeField string, concurrencyNum int64) ([]unstructured.Unstructured, error) {
	// step 1
	// get Constraint resource from cluster and extract its gatekeeper match condition and `inScopeObjects` in parameters
	constraintMatch, inScopeObjectCondition, err := k8smanifest.GetMatchConditionFromConfigResource(constraintRef, matchField, inscopeField)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get a match condition from config resource `%s`", constraintRef)
	}
	apiResources, err := kubeutil.GetAPIResources()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get api resources")
	}
	// step 2
	// list kinds in the match condition and check its scope
	kinds := map[string]metav1.APIResource{}
	for _, ck := range constraintMatch.Kinds {
		matchAllKindsInGroup := false
		if len(ck.Kinds) == 1 && ck.Kinds[0] == "*" {
			matchAllKindsInGroup = true
		}
		if matchAllKindsInGroup {
			for _, g := range ck.APIGroups {
				for _, apiResource := range apiResources {
					if g == apiResource.Group {
						kinds[apiResource.Kind] = apiResource
					}
				}
			}
		} else {
			for _, k := range ck.Kinds {
				for _, apiResource := range apiResources {
					if k == apiResource.Kind {
						kinds[apiResource.Kind] = apiResource
					}
				}
			}
		}
	}
	// step 3
	// get all namespaces in a cluster and extract some of them that match the match condition
	namespaces := map[string]*corev1.Namespace{}
	allNamespaces, err := kubeutil.GetNamespaces()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get namespaces")
	}
	if len(constraintMatch.Namespaces) > 0 {
		for _, nsNamePattern := range constraintMatch.Namespaces {
			for _, nsObj := range allNamespaces {
				if k8ssigutil.MatchSinglePattern(nsNamePattern, nsObj.GetName()) {
					nsName := nsObj.GetName()
					namespaces[nsName] = nsObj
				}
			}
		}
	} else if constraintMatch.NamespaceSelector != nil {
		selector, err := metav1.LabelSelectorAsSelector(constraintMatch.NamespaceSelector)
		if err != nil {
			return nil, errors.Wrap(err, "failed to convert *metav1.LabelSelector to labels.Selector")
		}
		for _, nsObj := range allNamespaces {
			if selector.Matches(labels.Set(nsObj.Labels)) {
				nsName := nsObj.GetName()
				namespaces[nsName] = nsObj
			}
		}
	}
	// step 4
	// check ExcludeNamespace conditions if exist
	if len(constraintMatch.ExcludedNamespaces) > 0 {
		tmpNamespaces := map[string]*corev1.Namespace{}
		for nsName, nsObj := range namespaces {
			if !k8ssigutil.ExactMatchWithPatternArray(nsName, constraintMatch.ExcludedNamespaces) {
				tmpNamespaces[nsName] = nsObj
			}
		}
		namespaces = tmpNamespaces
	}

	type objData struct {
		obj       *unstructured.Unstructured
		kind      metav1.APIResource
		namespace *corev1.Namespace
	}
	// step 5
	// list existing resources by kind in a namespace. do this for all selected kinds and namespaces
	eg1 := errgroup.Group{}
	if concurrencyNum < 1 {
		concurrencyNum = int64(runtime.NumCPU())
	}
	sem := semaphore.NewWeighted(concurrencyNum)
	mutex := sync.Mutex{}
	objDataList := []objData{}
	kindNamespaces := [][2]string{}
	for kindName := range kinds {
		for nsName := range namespaces {
			kindNamespaces = append(kindNamespaces, [2]string{kindName, nsName})
		}
	}
	for i := range kindNamespaces {
		kindName := kindNamespaces[i][0]
		nsName := kindNamespaces[i][1]
		kindResource := kinds[kindName]
		nsObj := namespaces[nsName]
		_ = sem.Acquire(context.Background(), 1)
		eg1.Go(func() error {
			tmpObjList, err := kubeutil.ListResources("", kindName, nsName)
			if err != nil {
				return errors.Wrapf(err, "failed to list %s in %s namespace", kindName, nsName)
			}
			if len(tmpObjList) > 0 {
				var nsForThis *corev1.Namespace
				if kindResource.Namespaced {
					nsForThis = nsObj
				}
				tmpObjDataList := []objData{}
				for _, obj := range tmpObjList {

					tmpObjDataList = append(tmpObjDataList, objData{
						obj:       obj,
						kind:      kindResource,
						namespace: nsForThis, // must be nil for cluster scope resource
					})
				}
				mutex.Lock()
				objDataList = append(objDataList, tmpObjDataList...)
				mutex.Unlock()
			}
			sem.Release(1)
			return nil
		})
	}

	if err = eg1.Wait(); err != nil {
		return nil, errors.Wrap(err, "error in listing object by kind and namespace in constraint")
	}

	objs := []unstructured.Unstructured{}
	for _, od := range objDataList {
		matched, err := gkmatch.Matches(constraintMatch, od.obj, od.namespace)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to check if the constraint matches this object %s %s", od.kind.Kind, od.obj.GetName())
		}
		if matched {
			objs = append(objs, *od.obj)
		}
	}
	// step 6
	// check inScopeOpject condition if exists
	if inScopeObjectCondition != nil {
		tmpObjs := []unstructured.Unstructured{}
		for _, obj := range objs {
			if inScopeObjectCondition.Match(obj) {
				tmpObjs = append(tmpObjs, obj)
			}
		}
		objs = tmpObjs
	}

	return objs, nil
}

func getObjsByConstraintWithCache(constraintRef, matchField, inscopeField string, concurrencyNum int64) ([]unstructured.Unstructured, error) {
	var objs []unstructured.Unstructured
	var err error
	cacheKey := fmt.Sprintf("getObjsByConstraint/%s", constraintRef)
	resultNum := 2
	results, err := k8ssigutil.GetCache(cacheKey)
	cacheFound := false
	if err == nil {
		if len(results) != resultNum {
			return nil, fmt.Errorf("cache has inconsistent data: a length of results must be %v, but got %v", resultNum, len(results))
		}
		if results[0] != nil {
			var ok bool
			if objs, ok = results[0].([]unstructured.Unstructured); !ok {
				objsBytes, _ := json.Marshal(results[0])
				var tmpObjs []unstructured.Unstructured
				if err = json.Unmarshal(objsBytes, &tmpObjs); err == nil {
					objs = tmpObjs
				} else {
					log.Warnf("failed to unmarshal target object cache: %s", err.Error())
				}
			}
		}
		if results[1] != nil {
			err = results[1].(error)
		}
		if objs != nil || err != nil {
			cacheFound = true
		}
	}
	if cacheFound {
		return objs, err
	} else {
		objs, err = getObjsByConstraint(constraintRef, matchField, inscopeField, concurrencyNum)
		cErr := k8ssigutil.SetCache(cacheKey, objs, err)
		if cErr != nil {
			log.Warnf("failed to save cache: %s", cErr.Error())
		}
		return objs, err
	}
}

// generate result bytes in a table which will be shown in output
func makeResultTable(result VerifyResourceResult, provenanceEnabled bool) []byte {
	if result.Summary.Total == 0 {
		return []byte("No resources found")
	}
	summaryTable := makeSummaryResultTable(result)
	sigRefFound := len(result.Manifests) > 0
	var manifestTable []byte
	if sigRefFound {
		manifestTable = makeManifestResultTable(result, provenanceEnabled)
	}
	resourceTable := makeResourceResultTable(result, provenanceEnabled)

	var provenanceTable []byte
	if provenanceEnabled {
		provenanceTable = makeProvenanceResultTable(result)
	}

	var resultTable string
	if sigRefFound {
		resultTable = fmt.Sprintf("[SUMMARY]\n%s\n[MANIFESTS]\n%s\n[RESOURCES]\n%s", string(summaryTable), string(manifestTable), string(resourceTable))
	} else {
		resultTable = fmt.Sprintf("[SUMMARY]\n%s\n[RESOURCES]\n%s", string(summaryTable), string(resourceTable))
	}
	if provenanceEnabled {
		resultTable = fmt.Sprintf("%s\n%s", resultTable, string(provenanceTable))
	}
	return []byte(resultTable)
}

// generate summary of result table which will be shown in output
func makeSummaryResultTable(result VerifyResourceResult) []byte {
	var tableResult string
	tableResult = "TOTAL\tVALID\tINVALID\t\n"
	tableResult += fmt.Sprintf("%v\t%v\t%v\t\n", result.Summary.Total, result.Summary.Valid, result.Summary.Invalid)
	writer := new(bytes.Buffer)
	w := tabwriter.NewWriter(writer, 0, 3, 3, ' ', 0)
	_, _ = w.Write([]byte(tableResult))
	w.Flush()
	tableBytes := writer.Bytes()
	return tableBytes
}

// generate manifest result table which will be shown in output
func makeManifestResultTable(result VerifyResourceResult, provenanceEnabled bool) []byte {
	var tableResult string
	if provenanceEnabled {
		tableResult = "NAME\tSIGNED\tSIGNER\tATTESTATION\tSBOM\t\n"
	} else {
		tableResult = "NAME\tSIGNED\tSIGNER\t\n"
	}
	for i := range result.Manifests {
		manifestResult := result.Manifests[i]
		// sigAge := ""
		// if manifestResult.SignedTime != nil {
		// 	t := manifestResult.SignedTime
		// 	sigAge = getAge(metav1.Time{Time: *t})
		// }

		// currently manifest table is showing only signed manifest, so `signed` is always true
		// TODO: update this to show all related manifests even if the one is not signed
		signed := true
		signedStr := strconv.FormatBool(signed)

		signer := ""
		if signed {
			if manifestResult.Signer == "" {
				signer = "N/A"
			} else {
				signer = manifestResult.Signer
			}
		}

		if provenanceEnabled {
			attestationFoundStr := "-"
			sbomFoundStr := "-"
			for _, prov := range result.Provenance.Items {
				isProvForManifestImage := (prov.ArtifactType == k8smanifest.ArtifactManifestImage)
				isProvForManifestResource := (prov.ArtifactType == k8smanifest.ArtifactManifestResource)
				if !isProvForManifestImage && !isProvForManifestResource {
					continue
				}
				if prov.RawAttestation != "" {
					attestationFoundStr = "found"
				}
				if prov.SBOMRef != "" {
					sbomFoundStr = "found"
				}
				break
			}
			tableResult += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t\n", manifestResult.Name, signedStr, signer, attestationFoundStr, sbomFoundStr)
		} else {
			tableResult += fmt.Sprintf("%s\t%s\t%s\t\n", manifestResult.Name, signedStr, signer)
		}

	}
	writer := new(bytes.Buffer)
	w := tabwriter.NewWriter(writer, 0, 3, 3, ' ', 0)
	_, _ = w.Write([]byte(tableResult))
	w.Flush()
	tableBytes := writer.Bytes()
	return tableBytes
}

// generate resource result table which will be shown in output
func makeResourceResultTable(result VerifyResourceResult, provenanceEnabled bool) []byte {
	mutipleManifestsFound := len(result.Manifests) >= 2

	var resourceTableResult string
	if mutipleManifestsFound {
		resourceTableResult = "KIND\tNAME\tVALID\tSIG_REF\tERROR\tAGE\t\n"
	} else {
		resourceTableResult = "KIND\tNAME\tVALID\tERROR\tAGE\t\n"
	}

	containerImages := []kubeutil.ImageObject{}
	for _, r := range result.Resources {
		// if it is out of scope (=skipped by config), skip to show it too
		inscope := true
		if r.Result != nil {
			inscope = r.Result.InScope
		}
		if !inscope {
			continue
		}

		// object
		obj := r.Object
		resName := obj.GetName()
		resKind := obj.GetKind()
		resTime := obj.GetCreationTimestamp()
		resAge := getAge(resTime)
		// verify result
		valid := "false"

		sigRef := ""
		if r.Result != nil {
			valid = strconv.FormatBool(r.Result.Verified)
			sigRef = r.Result.SigRef
		}
		// failure reason
		reason := ""
		if r.Error != nil {
			reason = r.Error.Error()
			reason = strings.Split(reason, ":")[0]
		} else if r.Result.Diff != nil && r.Result.Diff.Size() > 0 {
			reason = fmt.Sprintf("diff: %s", r.Result.Diff)
		}
		// make a row string
		var line string
		if mutipleManifestsFound {
			line = fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t\n", resKind, resName, valid, sigRef, reason, resAge)
		} else {
			line = fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t\n", resKind, resName, valid, reason, resAge)
		}
		resourceTableResult = fmt.Sprintf("%s%s", resourceTableResult, line)

		if r.Result != nil {
			containerImages = append(containerImages, r.Result.ContainerImages...)
		}
	}
	writer := new(bytes.Buffer)
	w := tabwriter.NewWriter(writer, 0, 3, 3, ' ', 0)
	_, _ = w.Write([]byte(resourceTableResult))
	w.Flush()
	tableBytes := writer.Bytes()

	if len(containerImages) > 0 {
		var podTableResult string
		if provenanceEnabled {
			podTableResult = "POD\tCONTAINER\tIMAGE ID\tATTESTATION\tSBOM\t\n"
		} else {
			podTableResult = "POD\tCONTAINER\tIMAGE ID\t\n"
		}

		for _, ci := range containerImages {
			var line string
			if provenanceEnabled {
				attestationFoundStr := "-"
				sbomFoundStr := "-"
				for _, prov := range result.Provenance.Items {
					if prov.Artifact != ci.ResourceBundleRef {
						continue
					}
					if prov.RawAttestation != "" {
						attestationFoundStr = "found"
					}
					if prov.SBOMRef != "" {
						sbomFoundStr = "found"
					}
					break
				}
				line = fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t\n", ci.PodName, ci.ContainerName, ci.ImageID, attestationFoundStr, sbomFoundStr)
			} else {
				line = fmt.Sprintf("%s\t%s\t%s\t\n", ci.PodName, ci.ContainerName, ci.ImageID)
			}
			podTableResult = fmt.Sprintf("%s%s", podTableResult, line)
		}
		writer2 := new(bytes.Buffer)
		w2 := tabwriter.NewWriter(writer2, 0, 3, 3, ' ', 0)
		_, _ = w2.Write([]byte(podTableResult))
		w2.Flush()
		podTableBytes := writer2.Bytes()
		tmpTableStr := fmt.Sprintf("%s\n[RESOURCES - PODS/CONTAINERS]\n%s", string(tableBytes), string(podTableBytes))
		tableBytes = []byte(tmpTableStr)
	}

	return tableBytes
}

// generate provenance result table which will be shown in output
func makeProvenanceResultTable(result VerifyResourceResult) []byte {
	provResult := result.Provenance
	// provTableResult := "ARTIFACT\tTYPE\tATTESTATION FOUND\tSBOM FOUND\t\n"
	attestationExists := false
	sbomExists := false
	for _, p := range provResult.Items {
		// artifact := p.Artifact
		// aType := p.ArtifactType
		// atteFound := strconv.FormatBool(p.Attestation != "")
		if p.RawAttestation != "" {
			attestationExists = true
		}
		// sbomFound := strconv.FormatBool(p.SBOM != "")
		if p.SBOMRef != "" {
			sbomExists = true
		}
		// line := fmt.Sprintf("%s\t%s\t%s\t%s\t\n", artifact, aType, atteFound, sbomFound)
		// provTableResult = fmt.Sprintf("%s%s", provTableResult, line)
	}
	// writer1 := new(bytes.Buffer)
	// w1 := tabwriter.NewWriter(writer1, 0, 3, 3, ' ', 0)
	// _, _ = w1.Write([]byte(provTableResult))
	// w1.Flush()
	// tableBytes := writer1.Bytes()
	tableBytes := []byte{}

	if attestationExists {
		attestationTableResult := ""
		for _, p := range provResult.Items {
			if p.RawAttestation == "" {
				continue
			}
			attestationSingleTableResult := ""
			artifact := p.Artifact
			line1 := fmt.Sprintf("ARTIFACT\t\t%s\t\n", artifact)
			line2 := ""
			for i, m := range p.AttestationMaterials {
				materialLabel := fmt.Sprintf("MATERIALS %v", i+1)
				line2 = fmt.Sprintf("%s%s\tURI\t%s\t\n", line2, materialLabel, m.URI)
				for k, v := range m.Digest {
					digestLabel := strings.ToUpper(k)
					line2 = fmt.Sprintf("%s\t%s\t%s\t\n", line2, digestLabel, v)
				}
			}

			attestationSingleTableResult = fmt.Sprintf("%s%s%s", attestationSingleTableResult, line1, line2)
			writer2 := new(bytes.Buffer)
			w2 := tabwriter.NewWriter(writer2, 0, 3, 3, ' ', 0)
			_, _ = w2.Write([]byte(attestationSingleTableResult))
			w2.Flush()
			singleAttestationTableStr := writer2.String()
			if p.AttestationLogIndex != nil {
				attestationLogIndex := *(p.AttestationLogIndex)
				curlCmd := k8smanifest.GenerateIntotoAttestationCurlCommand(attestationLogIndex)
				singleAttestationTableStr = fmt.Sprintf("%sTo get this attestation: %s\n\n", singleAttestationTableStr, curlCmd)
			} else if p.ConfigMapRef != "" {
				curlCmd := k8smanifest.GenerateIntotoAttestationKubectlCommand(p.ConfigMapRef)
				singleAttestationTableStr = fmt.Sprintf("%sTo get this attestation: %s\n\n", singleAttestationTableStr, curlCmd)
			}
			attestationTableResult = fmt.Sprintf("%s%s", attestationTableResult, singleAttestationTableStr)

		}
		tmpTableStr := fmt.Sprintf("[PROVENANCES - ATTESTATIONS]\n%s", attestationTableResult)
		tableBytes = []byte(tmpTableStr)
	}

	if sbomExists {
		sbomTableResult := ""
		for _, p := range provResult.Items {
			if p.SBOMRef == "" {
				continue
			}
			artifact := p.Artifact
			line1 := fmt.Sprintf("ARTIFACT\t%s\t\n", artifact)
			line2 := fmt.Sprintf("SBOM NAME\t%s\t\n", p.SBOMRef)
			tmpSBOMTableStr := fmt.Sprintf("%s%s", line1, line2)
			writer3 := new(bytes.Buffer)
			w3 := tabwriter.NewWriter(writer3, 0, 3, 3, ' ', 0)
			_, _ = w3.Write([]byte(tmpSBOMTableStr))
			w3.Flush()
			tmpTableStr := writer3.String()
			if p.SBOMRef != "" {
				sbomCmd := k8smanifest.GenerateSBOMDownloadCommand(artifact)
				tmpTableStr = fmt.Sprintf("%sTo download SBOM: %s\n\n", tmpTableStr, sbomCmd)
			} else if p.ConfigMapRef != "" {
				sbomCmd := k8smanifest.GenerateSBOMDownloadCommand(p.ConfigMapRef)
				tmpTableStr = fmt.Sprintf("%sTo download SBOM: %s\n\n", tmpTableStr, sbomCmd)
			}
			sbomTableResult = fmt.Sprintf("%s%s", sbomTableResult, tmpTableStr)
		}
		tmpTableStr := fmt.Sprintf("%s\n[PROVENANCES - SBOMs]\n%s", string(tableBytes), sbomTableResult)
		tableBytes = []byte(tmpTableStr)
	}

	return tableBytes
}

// convert the timestamp info to human readable string
func getAge(t metav1.Time) string {
	return metatable.ConvertToHumanReadableDateType(t)
}

type summary struct {
	Total   int `json:"total"`
	Valid   int `json:"valid"`
	Invalid int `json:"invalid"`
}

type manifestResult struct {
	Name       string     `json:"name"`
	Signer     string     `json:"signer"`
	SignedTime *time.Time `json:"signedTime"`
}

type resourceResult struct {
	Object unstructured.Unstructured         `json:"-"`
	Result *k8smanifest.VerifyResourceResult `json:"result"`
	Error  error                             `json:"-"`
}

type provenanceSummary struct {
	Total     int      `json:"total"`
	Artifacts []string `json:"artifacts"`
}

type provenanceResult struct {
	Summary provenanceSummary        `json:"summary"`
	Items   []k8smanifest.Provenance `json:"items"`
}

type VerifyResourceResult struct {
	metav1.TypeMeta `json:""`
	Summary         summary           `json:"summary"`
	Manifests       []manifestResult  `json:"manifests"`
	Resources       []resourceResult  `json:"resources"`
	Provenance      *provenanceResult `json:"provenance,omitempty"`
}

// SingleResult contains a target object itself, but it is too much to show result.
// So only corev1.ObjectReference will be shown in an output.
func (r resourceResult) MarshalJSON() ([]byte, error) {
	objRef := obj2ref(r.Object)
	errStr := ""
	if r.Error != nil {
		errStr = r.Error.Error()
	}
	return json.Marshal(&struct {
		Object corev1.ObjectReference            `json:"object"`
		Result *k8smanifest.VerifyResourceResult `json:"result"`
		Error  string                            `json:"error"`
	}{
		Object: objRef,
		Result: r.Result,
		Error:  errStr,
	})
}

// SingleResult contains a target object itself, but it is too much to show result.
// So only corev1.ObjectReference will be shown in an output.
func (r resourceResult) MarshalYAML() ([]byte, error) {
	objRef := obj2ref(r.Object)
	errStr := ""
	if r.Error != nil {
		errStr = r.Error.Error()
	}
	return yaml.Marshal(&struct {
		Object corev1.ObjectReference            `json:"object"`
		Result *k8smanifest.VerifyResourceResult `json:"result"`
		Error  string                            `json:"error"`
	}{
		Object: objRef,
		Result: r.Result,
		Error:  errStr,
	})
}

func NewVerifyResourceResult(results []resourceResult, provenanceEnabled bool) VerifyResourceResult {
	summ := summary{}
	manifests := []manifestResult{}
	resources := []resourceResult{}
	totalCount := 0
	validCount := 0
	invalidCount := 0
	manifestMap := map[string]bool{}
	provenanceCount := 0
	provenanceArtifactMap := map[string]bool{}
	provenances := []k8smanifest.Provenance{}
	for i := range results {
		result := results[i]
		if result.Result != nil && !result.Result.InScope {
			continue
		}
		if result.Result != nil && result.Result.Verified {
			validCount += 1
		} else {
			invalidCount += 1
		}
		totalCount += 1

		if result.Result != nil && result.Result.SigRef != "" && result.Result.SigRef != k8smanifest.SigRefEmbeddedInAnnotation {
			manifestRef := result.Result.SigRef
			if !manifestMap[manifestRef] {
				manifests = append(manifests, manifestResult{
					Name:       manifestRef,
					Signer:     result.Result.Signer,
					SignedTime: result.Result.SignedTime,
				})
				manifestMap[manifestRef] = true
			}
		}

		if result.Result != nil && result.Result.Provenances != nil {
			if provenanceEnabled {
				for _, prov := range result.Result.Provenances {
					artifact := prov.Artifact
					if !provenanceArtifactMap[artifact] {
						provenanceCount += 1
						provenances = append(provenances, *prov)
						provenanceArtifactMap[artifact] = true
					}
				}
			}

			// provenance will be displayed as a provenance result, and removed from a resource result
			result.Result.Provenances = nil
		}

		resources = append(resources, result)
	}
	summ.Total = totalCount
	summ.Valid = validCount
	summ.Invalid = invalidCount
	vrr := VerifyResourceResult{
		TypeMeta: metav1.TypeMeta{
			APIVersion: resultAPIVersion,
			Kind:       resultKind,
		},
		Summary:   summ,
		Manifests: manifests,
		Resources: resources,
	}
	if provenanceEnabled {
		provenanceArtifacts := []string{}
		for artfct := range provenanceArtifactMap {
			provenanceArtifacts = append(provenanceArtifacts, artfct)
		}
		vrr.Provenance = &provenanceResult{
			Summary: provenanceSummary{
				Total:     provenanceCount,
				Artifacts: provenanceArtifacts,
			},
			Items: provenances,
		}
	}
	return vrr
}

func obj2ref(obj unstructured.Unstructured) corev1.ObjectReference {
	return corev1.ObjectReference{
		Kind:            obj.GetKind(),
		Namespace:       obj.GetNamespace(),
		Name:            obj.GetName(),
		UID:             obj.GetUID(),
		APIVersion:      obj.GetAPIVersion(),
		ResourceVersion: obj.GetResourceVersion(),
	}
}

func getConfigPathFromConfigFlags(path, ctype, kind, name, namespace, field string) (string, string) {
	if path != "" {
		return path, field
	}

	if ctype == configTypeFile {
		return path, field
	}
	if kind == "" {
		if ctype == configTypeConstraint {
			kind = defaultConfigKindForConstraint
		} else if ctype == configTypeConfigMap {
			kind = defaultConfigKindForConfigMap
		}
	}
	newPath := ""
	if namespace == "" {
		newPath = fmt.Sprintf("%s%s/%s", kubeutil.InClusterObjectPrefix, kind, name)
	} else {
		newPath = fmt.Sprintf("%s%s/%s/%s", kubeutil.InClusterObjectPrefix, kind, namespace, name)
	}
	if field == "" {
		if ctype == configTypeConstraint {
			field = defaultConfigFieldPathConstraint
		} else if ctype == configTypeConfigMap {
			field = defaultConfigFieldPathConfigMap
		}
	}
	return newPath, field
}

// convert resources to a concatenated YAML manifest
func objsToConcatYAML(objs []unstructured.Unstructured) []byte {
	yamls := [][]byte{}
	for _, obj := range objs {
		yml, _ := yaml.Marshal(obj.Object)
		yamls = append(yamls, yml)
	}
	concatYAMl := k8ssigutil.ConcatenateYAMLs(yamls)
	return concatYAMl
}

func validateConfigMapRef(cmRefString string) string {
	parts := k8ssigutil.SplitCommaSeparatedString(cmRefString)
	validatedParts := []string{}
	for _, p := range parts {
		var validP string
		if strings.HasPrefix(p, kubeutil.InClusterObjectPrefix) {
			validP = p
		} else {
			validP = fmt.Sprintf("%s%s/%s/%s", kubeutil.InClusterObjectPrefix, "ConfigMap", defaultManifetBundleNamespace, p)
		}
		validatedParts = append(validatedParts, validP)
	}
	return strings.Join(validatedParts, ",")
}

type imageToBeUsed struct {
	kubeutil.ImageObject
	imageType k8smanifest.ArtifactType
}

// list all images to be used for manifest matching, signature verification and provenance search
func getAllImagesToBeUsed(resBundleRef string, objs []unstructured.Unstructured, annotationConfig k8smanifest.AnnotationConfig, provenanceEnabled bool) []imageToBeUsed {
	images := []imageToBeUsed{}
	if resBundleRef == "" {
		resBundleRefAnnotationKey := annotationConfig.ResourceBundleRefAnnotationKey()
		for _, obj := range objs {
			annt := obj.GetAnnotations()
			if img, ok := annt[resBundleRefAnnotationKey]; ok {
				images = append(images, imageToBeUsed{imageType: k8smanifest.ArtifactManifestImage, ImageObject: kubeutil.ImageObject{ResourceBundleRef: img}})
			}
		}
	} else {
		resBundleRefList := k8ssigutil.SplitCommaSeparatedString(resBundleRef)
		for _, img := range resBundleRefList {
			images = append(images, imageToBeUsed{imageType: k8smanifest.ArtifactManifestImage, ImageObject: kubeutil.ImageObject{ResourceBundleRef: img}})
		}
	}

	if provenanceEnabled {
		for i := range objs {
			obj := objs[i]
			imageObjects, err := kubeutil.GetAllImagesFromObject(&obj)
			if err != nil {
				log.Warn(err)
				continue
			}
			for _, img := range imageObjects {
				images = append(images, imageToBeUsed{imageType: k8smanifest.ArtifactContainerImage, ImageObject: img})
			}
		}
	}
	return images
}
