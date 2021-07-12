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

const embeddedSigRef = "<embedded>"

// This is common ignore fields for changes by k8s system
//go:embed resources/default-config.yaml
var defaultConfigBytes []byte

var supportedOutputFormat = map[string]bool{"json": true, "yaml": true}

func NewCmdVerifyResource() *cobra.Command {

	var filename string
	var imageRef string
	var keyPath string
	var configPath string
	var outputFormat string
	var manifestYAMLs [][]byte
	var disableDefaultConfig bool
	cmd := &cobra.Command{
		Use:   "verify-resource (RESOURCE/NAME | -f FILENAME | -i IMAGE)",
		Short: "A command to verify Kubernetes manifests of resources on cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			kubeGetArgs := args
			err = kubectlOptions.initGet(cmd)
			if err != nil {
				return errors.Wrap(err, "failed to initialize a configuration for kubectl get command")
			}

			if filename != "" && filename != "-" {
				manifestYAMLs, err = readManifestYAMLFile(filename)
				if err != nil {
					return errors.Wrap(err, "failed to read manifest YAML file")
				}
			} else if filename == "-" {
				manifestYAMLs, err = readStdinAsYAMLs()
				if err != nil {
					return errors.Wrap(err, "failed to read stdin as resource YAMLs")
				}
			}

			err = verifyResource(manifestYAMLs, kubeGetArgs, imageRef, keyPath, configPath, disableDefaultConfig, outputFormat)
			if err != nil {
				return errors.Wrap(err, "failed to verify resource")
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&filename, "filename", "f", "", "manifest filename (this can be \"-\", then read a file from stdin)")
	cmd.PersistentFlags().StringVarP(&imageRef, "image", "i", "", "a comma-separated list of signed image names that contains YAML manifests")
	cmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "a comma-separated list of paths to public keys (if empty, do key-less verification)")
	cmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "path to verification config YAML file (for advanced verification)")
	cmd.PersistentFlags().BoolVar(&disableDefaultConfig, "disable-default-config", false, "if true, disable default ignore fields configuration (default to false)")
	cmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "", "output format string, either \"json\" or \"yaml\" (if empty, a result is shown as a table)")

	return cmd
}

func verifyResource(yamls [][]byte, kubeGetArgs []string, imageRef, keyPath, configPath string, disableDefaultConfig bool, outputFormat string) error {
	var err error
	if outputFormat != "" {
		if !supportedOutputFormat[outputFormat] {
			return fmt.Errorf("output format `%s` is not supported", outputFormat)
		}
	}

	if len(kubeGetArgs) == 0 && yamls == nil && imageRef == "" {
		return errors.New("at least one of the following is required: `--image` option, resource kind or stdin YAML manifests")
	}

	objs := []unstructured.Unstructured{}
	if len(kubeGetArgs) > 0 {
		objs, err = kubectlOptions.Get(kubeGetArgs, "")
	} else if yamls != nil {
		objs, err = getObjsFromManifests(yamls)
	} else if imageRef != "" {
		manifestFetcher := k8smanifest.NewManifestFetcher(imageRef)
		imageManifestFetcher := manifestFetcher.(*k8smanifest.ImageManifestFetcher)
		var yamlsInImage [][]byte
		if yamlsInImage, err = imageManifestFetcher.FetchAll(); err == nil {
			objs, err = getObjsFromManifests(yamlsInImage)
		}
	}
	if err != nil {
		return errors.Wrap(err, "failed to get objects in cluster")
	}
	var vo *k8smanifest.VerifyResourceOption
	if configPath == "" && disableDefaultConfig {
		vo = &k8smanifest.VerifyResourceOption{}
	} else if configPath == "" {
		vo = loadDefaultConfig()
	} else {
		vo, err = k8smanifest.LoadVerifyResourceConfig(configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return nil
		}
		if !disableDefaultConfig {
			vo = addDefaultConfig(vo)
		}
	}

	if imageRef != "" {
		vo.ImageRef = imageRef
	}
	if keyPath != "" {
		vo.KeyPath = keyPath
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
	summarizedResult := NewVerifyResourceResult(results)
	if outputFormat == "" {
		resultBytes = makeResultTable(summarizedResult)
	} else if outputFormat == "json" {
		resultBytes, _ = json.MarshalIndent(summarizedResult, "", "    ") // pretty print json as well as kubectl get -o json
	} else if outputFormat == "yaml" {
		resultBytes, _ = yaml.Marshal(summarizedResult)
	}

	fmt.Println(string(resultBytes))

	return nil
}

func readManifestYAMLFile(fpath string) ([][]byte, error) {
	yamls := [][]byte{}
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

func getObjsFromManifests(yamls [][]byte) ([]unstructured.Unstructured, error) {
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
	for _, mnfobj := range manifestObjs {
		args := []string{mnfobj.GetKind(), mnfobj.GetName()}
		namespaceInManifest := mnfobj.GetNamespace()
		tmpObjs, err := kubectlOptions.Get(args, namespaceInManifest)
		if err != nil {
			allErrs = append(allErrs, err.Error())
			continue
		}
		if len(tmpObjs) == 0 {
			allErrs = append(allErrs, fmt.Sprintf("failed to find a resource: kind: %s, namespace: %s, name: %s", mnfobj.GetKind(), mnfobj.GetNamespace(), mnfobj.GetName()))
			continue
		}
		objs = append(objs, tmpObjs[0])
	}
	if len(objs) == 0 && len(allErrs) > 0 {
		return nil, fmt.Errorf("error occurred during getting resources: %s", strings.Join(allErrs, "; "))
	}
	return objs, nil
}

// generate result bytes in a table which will be shown in output
func makeResultTable(result VerifyResourceResult) []byte {
	if result.Summary.Total == 0 {
		return []byte("No resources found")
	}
	summaryTable := makeSummaryResultTable(result)
	imageRefFound := len(result.Images) > 0
	var imageTable []byte
	if imageRefFound {
		imageTable = makeImageResultTable(result)
	}
	resourceTable := makeResourceResultTable(result)

	var resultTable string
	if imageRefFound {
		resultTable = fmt.Sprintf("[SUMMARY]\n%s\n[IMAGES]\n%s\n[RESOURCES]\n%s", string(summaryTable), string(imageTable), string(resourceTable))
	} else {
		resultTable = fmt.Sprintf("[SUMMARY]\n%s\n[RESOURCES]\n%s", string(summaryTable), string(resourceTable))
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
func makeImageResultTable(result VerifyResourceResult) []byte {
	var tableResult string
	tableResult = "IMAGE_NAME\tSIGNER\t\n"
	for i := range result.Images {
		imgResult := result.Images[i]
		// sigAge := ""
		// if imgResult.SignedTime != nil {
		// 	t := imgResult.SignedTime
		// 	sigAge = getAge(metav1.Time{Time: *t})
		// }
		tableResult += fmt.Sprintf("%s\t%s\t\n", imgResult.Name, imgResult.Signer)
	}
	writer := new(bytes.Buffer)
	w := tabwriter.NewWriter(writer, 0, 3, 3, ' ', 0)
	_, _ = w.Write([]byte(tableResult))
	w.Flush()
	tableBytes := writer.Bytes()
	return tableBytes
}

// generate resource result table which will be shown in output
func makeResourceResultTable(result VerifyResourceResult) []byte {
	mutipleImagesFound := len(result.Images) >= 2

	var resourceTableResult string
	if mutipleImagesFound {
		resourceTableResult = "KIND\tNAME\tVALID\tSIG_REF\tERROR\tAGE\t\n"
	} else {
		resourceTableResult = "KIND\tNAME\tVALID\tERROR\tAGE\t\n"
	}

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
	}
	writer := new(bytes.Buffer)
	w := tabwriter.NewWriter(writer, 0, 3, 3, ' ', 0)
	_, _ = w.Write([]byte(resourceTableResult))
	w.Flush()
	tableBytes := writer.Bytes()
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

type VerifyResourceResult struct {
	Summary   summary          `json:"summary"`
	Images    []imageResult    `json:"images"`
	Resources []resourceResult `json:"resources"`
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

func NewVerifyResourceResult(results []resourceResult) VerifyResourceResult {
	summ := summary{}
	images := []imageResult{}
	resources := []resourceResult{}
	totalCount := 0
	validCount := 0
	invalidCount := 0
	imageMap := map[string]bool{}
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

		if result.Result != nil && result.Result.SigRef != "" && result.Result.SigRef != embeddedSigRef {
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
		resources = append(resources, result)
	}
	summ.Total = totalCount
	summ.Valid = validCount
	summ.Invalid = invalidCount
	return VerifyResourceResult{
		Summary:   summ,
		Images:    images,
		Resources: resources,
	}
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
