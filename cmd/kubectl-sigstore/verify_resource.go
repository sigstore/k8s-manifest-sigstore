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

package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/ghodss/yaml"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8ssigutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metatable "k8s.io/apimachinery/pkg/api/meta/table"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
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
)

// This is common ignore fields for changes by k8s system
//go:embed resources/default-config.yaml
var defaultConfigBytes []byte

var supportedOutputFormat = map[string]bool{"json": true, "yaml": true}

func NewCmdVerifyResource() *cobra.Command {

	var filename string
	var imageRef string
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
	cmd := &cobra.Command{
		Use:   "verify-resource (RESOURCE/NAME | -f FILENAME | -i IMAGE)",
		Short: "A command to verify Kubernetes manifests of resources on cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			kubeGetArgs := args
			err = kubectlOptions.initGet(cmd)
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

			allVerified, err := verifyResource(manifestYAMLs, kubeGetArgs, imageRef, sigResRef, keyPath, configPath, configField, disableDefaultConfig, provenance, outputFormat)
			if err != nil {
				log.Fatalf("error occurred during verify-resource: %s", err.Error())
			}
			if !allVerified {
				os.Exit(1)
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&filename, "filename", "f", "", "manifest filename (this can be \"-\", then read a file from stdin)")
	cmd.PersistentFlags().StringVarP(&imageRef, "image", "i", "", "a comma-separated list of signed image names that contains YAML manifests")
	cmd.PersistentFlags().StringVar(&sigResRef, "signature-resource", "", "a comma-separated list of configmaps that contains message, signature and some others")
	cmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "a comma-separated list of paths to public keys (if empty, do key-less verification)")
	cmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "path to verification config YAML file or k8s object identifier like k8s://[KIND]/[NAMESPACE]/[NAME]")
	cmd.PersistentFlags().StringVar(&configType, "config-type", "file", "a type of config, one of the following: \"file\", \"constraint\" or \"configmap\"")
	cmd.PersistentFlags().StringVar(&configKind, "config-kind", "", "a kind of config resource in a cluster, only valid when --config-type is \"constraint\" or \"configmap\"")
	cmd.PersistentFlags().StringVar(&configName, "config-name", "", "a name of config resource in a cluster, only valid when --config-type is \"constraint\" or \"configmap\"")
	cmd.PersistentFlags().StringVar(&configNamespace, "config-namespace", "", "a namespace of config resource in a cluster, only valid when --config-type is \"constraint\" or \"configmap\"")
	cmd.PersistentFlags().StringVar(&configField, "config-field", "", "field of config data (e.g. `data.\"config.yaml\"` in a ConfigMap, `spec.parameters` in a constraint)")
	cmd.PersistentFlags().BoolVar(&disableDefaultConfig, "disable-default-config", false, "if true, disable default ignore fields configuration (default to false)")
	cmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "", "output format string, either \"json\" or \"yaml\" (if empty, a result is shown as a table)")
	cmd.PersistentFlags().BoolVar(&provenance, "provenance", false, "if true, show provenance data (default to false)")

	return cmd
}

func verifyResource(yamls [][]byte, kubeGetArgs []string, imageRef, sigResRef, keyPath, configPath, configField string, disableDefaultConfig, provenance bool, outputFormat string) (bool, error) {
	var err error
	if outputFormat != "" {
		if !supportedOutputFormat[outputFormat] {
			return false, fmt.Errorf("output format `%s` is not supported", outputFormat)
		}
	}

	var vo *k8smanifest.VerifyResourceOption
	if configPath == "" && disableDefaultConfig {
		vo = &k8smanifest.VerifyResourceOption{}
	} else if configPath == "" {
		vo = loadDefaultConfig()
	} else if strings.HasPrefix(configPath, k8smanifest.InClusterObjectPrefix) {
		vo, err = k8smanifest.LoadVerifyResourceConfigFromResource(configPath, configField)
		if err != nil {
			return false, errors.Wrapf(err, "failed to load verify-resource config from resource %s", configPath)
		}
		if !disableDefaultConfig {
			vo = addDefaultConfig(vo)
		}
	} else {
		vo, err = k8smanifest.LoadVerifyResourceConfig(configPath)
		if err != nil {
			return false, errors.Wrapf(err, "failed to load verify-resource config from %s", configPath)
		}
		if !disableDefaultConfig {
			vo = addDefaultConfig(vo)
		}
	}
	// add signature/message/others annotations to ignore fields
	vo.SetAnnotationIgnoreFields()

	objs := []unstructured.Unstructured{}
	if len(kubeGetArgs) > 0 {
		objs, err = kubectlOptions.Get(kubeGetArgs, "")
	} else if yamls != nil {
		objs, err = getObjsFromManifests(yamls, vo.IgnoreFields)
	} else if imageRef != "" {
		manifestFetcher := k8smanifest.NewManifestFetcher(imageRef, "", vo.AnnotationConfig, nil, vo.MaxResourceManifestNum)
		imageManifestFetcher := manifestFetcher.(*k8smanifest.ImageManifestFetcher)
		var yamlsInImage [][]byte
		if yamlsInImage, err = imageManifestFetcher.FetchAll(); err == nil {
			objs, err = getObjsFromManifests(yamlsInImage, vo.IgnoreFields)
		}
	}
	if err != nil {
		return false, errors.Wrap(err, "failed to get objects in cluster")
	}

	if imageRef != "" {
		vo.ImageRef = imageRef
	}
	if sigResRef != "" {
		vo.SignatureResourceRef = sigResRef
	}
	if keyPath != "" {
		vo.KeyPath = keyPath
	}
	if provenance {
		vo.Provenance = true
	}

	results := []resourceResult{}
	for _, obj := range objs {
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
		results = append(results, r)
	}

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
			tmpObjs, err := kubectlOptions.Get(args, namespaceInManifest)
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

// generate result bytes in a table which will be shown in output
func makeResultTable(result VerifyResourceResult, provenanceEnabled bool) []byte {
	if result.Summary.Total == 0 {
		return []byte("No resources found")
	}
	summaryTable := makeSummaryResultTable(result)
	imageRefFound := len(result.Images) > 0
	var imageTable []byte
	if imageRefFound {
		imageTable = makeImageResultTable(result, provenanceEnabled)
	}
	resourceTable := makeResourceResultTable(result, provenanceEnabled)

	var provenanceTable []byte
	if provenanceEnabled {
		provenanceTable = makeProvenanceResultTable(result)
	}

	var resultTable string
	if imageRefFound {
		resultTable = fmt.Sprintf("[SUMMARY]\n%s\n[MANIFESTS]\n%s\n[RESOURCES]\n%s", string(summaryTable), string(imageTable), string(resourceTable))
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

// generate image result table which will be shown in output
func makeImageResultTable(result VerifyResourceResult, provenanceEnabled bool) []byte {
	var tableResult string
	if provenanceEnabled {
		tableResult = "NAME\tSIGNED\tSIGNER\tATTESTATION\tSBOM\t\n"
	} else {
		tableResult = "NAME\tSIGNED\tSIGNER\t\n"
	}
	for i := range result.Images {
		imgResult := result.Images[i]
		// sigAge := ""
		// if imgResult.SignedTime != nil {
		// 	t := imgResult.SignedTime
		// 	sigAge = getAge(metav1.Time{Time: *t})
		// }

		// currently image table is showing only signed images, so `signed` is always true
		// TODO: update this to show all related images even if the one is not signed
		signed := true
		signedStr := strconv.FormatBool(signed)

		signer := ""
		if signed {
			if imgResult.Signer == "" {
				signer = "N/A"
			} else {
				signer = imgResult.Signer
			}
		}

		if provenanceEnabled {
			attestationFoundStr := "-"
			sbomFoundStr := "-"
			for _, prov := range result.Provenance.Items {
				if prov.Artifact != imgResult.Name {
					continue
				}
				if prov.Attestation != "" {
					attestationFoundStr = "found"
				}
				if prov.SBOM != "" {
					sbomFoundStr = "found"
				}
				break
			}
			tableResult += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t\n", imgResult.Name, signedStr, signer, attestationFoundStr, sbomFoundStr)
		} else {
			tableResult += fmt.Sprintf("%s\t%s\t%s\t\n", imgResult.Name, signedStr, signer)
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
	mutipleImagesFound := len(result.Images) >= 2

	var resourceTableResult string
	if mutipleImagesFound {
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
		if mutipleImagesFound {
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
					if prov.Artifact != ci.ImageRef {
						continue
					}
					if prov.Attestation != "" {
						attestationFoundStr = "found"
					}
					if prov.SBOM != "" {
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
		if p.Attestation != "" {
			attestationExists = true
		}
		// sbomFound := strconv.FormatBool(p.SBOM != "")
		if p.SBOM != "" {
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
			if p.Attestation == "" {
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
			singleAttestationTableStr := string(writer2.Bytes())

			curlCmd := k8smanifest.GenerateIntotoAttestationCurlCommand(p.AttestationLogIndex)
			singleAttestationTableStr = fmt.Sprintf("%sTo get this attestation: %s\n\n", singleAttestationTableStr, curlCmd)
			attestationTableResult = fmt.Sprintf("%s%s", attestationTableResult, singleAttestationTableStr)
		}
		tmpTableStr := fmt.Sprintf("[PROVENANCES - ATTESTATIONS]\n%s", attestationTableResult)
		tableBytes = []byte(tmpTableStr)
	}

	if sbomExists {
		sbomTableResult := ""
		for _, p := range provResult.Items {
			if p.SBOM == "" {
				continue
			}
			artifact := p.Artifact
			line1 := fmt.Sprintf("ARTIFACT\t%s\t\n", artifact)
			line2 := fmt.Sprintf("SBOM NAME\t%s\t\n", p.SBOM)
			tmpSBOMTableStr := fmt.Sprintf("%s%s", line1, line2)
			writer3 := new(bytes.Buffer)
			w3 := tabwriter.NewWriter(writer3, 0, 3, 3, ' ', 0)
			_, _ = w3.Write([]byte(tmpSBOMTableStr))
			w3.Flush()
			tmpTableStr := string(writer3.Bytes())
			sbomCmd := k8smanifest.GenerateSBOMDownloadCommand(artifact)
			tmpTableResult := fmt.Sprintf("%sTo download SBOM: %s\n\n", tmpTableStr, sbomCmd)
			sbomTableResult = fmt.Sprintf("%s%s", sbomTableResult, tmpTableResult)
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

type imageResult struct {
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
	Images          []imageResult     `json:"images"`
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
	images := []imageResult{}
	resources := []resourceResult{}
	totalCount := 0
	validCount := 0
	invalidCount := 0
	imageMap := map[string]bool{}
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
			imageRef := result.Result.SigRef
			if !imageMap[imageRef] {
				images = append(images, imageResult{
					Name:       imageRef,
					Signer:     result.Result.Signer,
					SignedTime: result.Result.SignedTime,
				})
				imageMap[imageRef] = true
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
		Images:    images,
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

func loadDefaultConfig() *k8smanifest.VerifyResourceOption {
	var defaultConfig *k8smanifest.VerifyResourceOption
	err := yaml.Unmarshal(defaultConfigBytes, &defaultConfig)
	if err != nil {
		return nil
	}
	return defaultConfig
}

func addDefaultConfig(vo *k8smanifest.VerifyResourceOption) *k8smanifest.VerifyResourceOption {
	dvo := loadDefaultConfig()
	return vo.AddDefaultConfig(dvo)
}

func getConfigPathFromConfigFlags(path, ctype, kind, name, namespace, field string) (string, string) {
	if path != "" {
		return path, field
	}

	if ctype == configTypeFile {
		return path, field
	}
<<<<<<< HEAD
	if kind == "" {
		if ctype == configTypeConstraint {
			kind = defaultConfigKindForConstraint
		} else if ctype == configTypeConfigMap {
			kind = defaultConfigKindForConfigMap
		}
	}
=======
>>>>>>> 551a90f (resolve conflict)
	newPath := ""
	if namespace == "" {
		newPath = fmt.Sprintf("%s%s/%s", k8smanifest.InClusterObjectPrefix, kind, name)
	} else {
		newPath = fmt.Sprintf("%s%s/%s/%s", k8smanifest.InClusterObjectPrefix, kind, namespace, name)
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
