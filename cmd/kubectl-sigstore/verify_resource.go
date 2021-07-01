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
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

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

var supportedOutputFormat = map[string]bool{"json": true, "yaml": true}

func NewCmdVerifyResource() *cobra.Command {

	var imageRef string
	var keyPath string
	var configPath string
	var outputFormat string
	cmd := &cobra.Command{
		Use:   "verify-resource -f <YAMLFILE> [-i <IMAGE>]",
		Short: "A command to verify Kubernetes manifests of resources on cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			fullArgs := getOriginalFullArgs("verify-resource")
			_, kubeGetArgs := splitArgs(fullArgs)

			err := verifyResource(kubeGetArgs, imageRef, keyPath, configPath, outputFormat)
			if err != nil {
				return err
			}
			return nil
		},
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
	}

	cmd.PersistentFlags().StringVarP(&imageRef, "image", "i", "", "signed image name which bundles yaml files")
	cmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "path to your signing key (if empty, do key-less signing)")
	cmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "path to verification config YAML file (for advanced verification)")
	cmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "", "output format string, either \"json\" or \"yaml\" (if empty, a result is shown as a table)")

	return cmd
}

func verifyResource(kubeGetArgs []string, imageRef, keyPath, configPath, outputFormat string) error {
	if outputFormat != "" {
		if !supportedOutputFormat[outputFormat] {
			return fmt.Errorf("`%s` is not supported output format", outputFormat)
		}
	}

	kArgs := []string{"get", "--output", "json"}
	kArgs = append(kArgs, kubeGetArgs...)
	log.Debug("kube get args", strings.Join(kArgs, " "))
	resultJSON, err := k8ssigutil.CmdExec("kubectl", kArgs...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return nil
	}
	var tmpObj unstructured.Unstructured
	err = json.Unmarshal([]byte(resultJSON), &tmpObj)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return nil
	}
	objs := []unstructured.Unstructured{}
	if tmpObj.IsList() {
		tmpList, _ := tmpObj.ToList()
		objs = append(objs, tmpList.Items...)
	} else {
		objs = append(objs, tmpObj)
	}

	vo := &k8smanifest.VerifyResourceOption{}
	if configPath != "" {
		vo, err = k8smanifest.LoadVerifyResourceConfig(configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return nil
		}
	}

	if imageRef != "" {
		vo.ImageRef = imageRef
	}
	if keyPath != "" {
		vo.KeyPath = keyPath
	}

	results := []SingleResult{}
	for _, obj := range objs {
		log.Debug("checking kind: ", obj.GetKind(), ", name: ", obj.GetName())
		vResult, err := k8smanifest.VerifyResource(obj, vo)
		r := SingleResult{
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
	if outputFormat == "" {
		resultBytes = makeResourceResultTable(results)
	} else if outputFormat == "json" {
		resultBytes, _ = json.MarshalIndent(VerifyResourceResult(results), "", "    ") // pretty print json as well as kubectl get -o json
	} else if outputFormat == "yaml" {
		resultBytes, _ = yaml.Marshal(VerifyResourceResult(results))
	}

	fmt.Println(string(resultBytes))

	return nil
}

func splitArgs(args []string) ([]string, []string) {
	mainArgs := []string{}
	kubectlArgs := []string{}
	mainArgsConditionSingle := map[string]bool{}
	mainArgsConditionDouble := map[string]bool{
		"--image":  true,
		"-i":       true,
		"--key":    true,
		"-k":       true,
		"--config": true,
		"-c":       true,
		"--output": true,
		"-o":       true,
	}
	skipIndex := map[int]bool{}
	for i, s := range args {
		if skipIndex[i] {
			continue
		}
		if mainArgsConditionSingle[s] {
			mainArgs = append(mainArgs, args[i])
		} else if mainArgsConditionDouble[s] {
			mainArgs = append(mainArgs, args[i])
			mainArgs = append(mainArgs, args[i+1])
			skipIndex[i+1] = true
		} else {
			kubectlArgs = append(kubectlArgs, args[i])
		}
	}
	return mainArgs, kubectlArgs
}

// generate result bytes in a table which will be shown in output
func makeResourceResultTable(results []SingleResult) []byte {
	tableResult := "NAME\tVALID\tSIGNER\tSIG_REF\tERROR\tAGE\t\n"
	for _, r := range results {
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
		resTime := obj.GetCreationTimestamp()
		resAge := getAge(resTime)
		// verify result
		valid := "false"

		signer := ""
		sigRef := ""
		if r.Result != nil {
			valid = strconv.FormatBool(r.Result.Verified)
			signer = r.Result.Signer
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
		line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t\n", resName, valid, signer, sigRef, reason, resAge)
		tableResult = fmt.Sprintf("%s%s", tableResult, line)
	}
	writer := new(bytes.Buffer)
	w := tabwriter.NewWriter(writer, 0, 3, 3, ' ', 0)
	_, _ = w.Write([]byte(tableResult))
	w.Flush()
	result := writer.Bytes()
	return result
}

// convert the timestamp info to human readable string
func getAge(t metav1.Time) string {
	return metatable.ConvertToHumanReadableDateType(t)
}

type SingleResult struct {
	Object unstructured.Unstructured         `json:"-"`
	Result *k8smanifest.VerifyResourceResult `json:"result"`
	Error  error                             `json:"-"`
}

type VerifyResourceResult []SingleResult

// SingleResult contains a target object itself, but it is too much to show result.
// So only corev1.ObjectReference will be shown in an output.
func (r SingleResult) MarshalJSON() ([]byte, error) {
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
func (r SingleResult) MarshalYAML() ([]byte, error) {
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

// VerifyResourceResult is a wrapper for list of SingleResult,
// and it will be output as a k8s resource for consistency with kubectl get xxxx -o json
func (r VerifyResourceResult) MarshalJSON() ([]byte, error) {
	results := []SingleResult{}
	for _, sr := range r {
		results = append(results, sr)
	}
	return json.Marshal(&struct {
		APIVersion string         `json:"apiVersion"`
		Kind       string         `json:"kind"`
		Results    []SingleResult `json:"results"`
	}{
		APIVersion: resultAPIVersion,
		Kind:       resultKind,
		Results:    results,
	})
}

// VerifyResourceResult is a wrapper for list of SingleResult,
// and it will be output as a k8s resource for consistency with kubectl get xxxx -o yaml
func (r VerifyResourceResult) MarshalYAML() ([]byte, error) {
	results := []SingleResult{}
	for _, sr := range r {
		results = append(results, sr)
	}
	return yaml.Marshal(&struct {
		APIVersion string         `json:"apiVersion"`
		Kind       string         `json:"kind"`
		Results    []SingleResult `json:"results"`
	}{
		APIVersion: resultAPIVersion,
		Kind:       resultKind,
		Results:    results,
	})
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
