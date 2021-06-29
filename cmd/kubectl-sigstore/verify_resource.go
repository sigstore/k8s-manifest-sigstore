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
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8ssigutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func NewCmdVerifyResource() *cobra.Command {

	var imageRef string
	var keyPath string
	var configPath string
	cmd := &cobra.Command{
		Use:   "verify-resource -f <YAMLFILE> [-i <IMAGE>]",
		Short: "A command to verify Kubernetes manifests of resources on cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			fullArgs := getOriginalFullArgs("verify-resource")
			_, kubeGetArgs := splitArgs(fullArgs)

			err := verifyResource(kubeGetArgs, imageRef, keyPath, configPath)
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

	return cmd
}

func verifyResource(kubeGetArgs []string, imageRef, keyPath, configPath string) error {
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

	vo := &k8smanifest.VerifyOption{}
	if configPath != "" {
		vo, err = k8smanifest.LoadVerifyConfig(configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return nil
		}
	}

	results := []SingleResult{}
	for _, obj := range objs {
		log.Debug("checking kind: ", obj.GetKind(), ", name: ", obj.GetName())
		vResult, err := k8smanifest.VerifyResource(obj, imageRef, keyPath, vo)
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

	resultTable := makeResourceResultTable(results)
	fmt.Println(string(resultTable))

	return nil
}

type SingleResult struct {
	Object unstructured.Unstructured         `json:"obj"`
	Result *k8smanifest.VerifyResourceResult `json:"result"`
	Error  error                             `json:"err"`
}

func splitArgs(args []string) ([]string, []string) {
	mainArgs := []string{}
	kubectlArgs := []string{}
	mainArgsCondition := map[string]bool{
		"--image":  true,
		"-i":       true,
		"--key":    true,
		"-k":       true,
		"--config": true,
		"-c":       true,
	}
	skipIndex := map[int]bool{}
	for i, s := range args {
		if skipIndex[i] {
			continue
		}
		if mainArgsCondition[s] {
			mainArgs = append(mainArgs, args[i])
			mainArgs = append(mainArgs, args[i+1])
			skipIndex[i+1] = true
		} else {
			kubectlArgs = append(kubectlArgs, args[i])
		}
	}
	return mainArgs, kubectlArgs
}

func makeResourceResultTable(results []SingleResult) []byte {
	tableResult := "NAME\tINSCOPE\tVERIFIED\tSIGNER\tERROR\tAGE\t\n"
	for _, r := range results {
		// object
		obj := r.Object
		resName := obj.GetName()
		resTime := obj.GetCreationTimestamp()
		resAge := getAge(resTime)
		// verify result
		verified := "false"
		inscope := "true"
		signer := ""
		if r.Result != nil {
			verified = strconv.FormatBool(r.Result.Verified)
			inscope = strconv.FormatBool(r.Result.InScope)
			signer = r.Result.Signer
		}
		// error
		errStr := ""
		if r.Error != nil {
			errStr = r.Error.Error()
		}
		// make a row string
		line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t\n", resName, inscope, verified, signer, errStr, resAge)
		tableResult = fmt.Sprintf("%s%s", tableResult, line)
	}
	writer := new(bytes.Buffer)
	w := tabwriter.NewWriter(writer, 0, 3, 3, ' ', 0)
	_, _ = w.Write([]byte(tableResult))
	w.Flush()
	result := writer.Bytes()
	return result
}

func getAge(t metav1.Time) string {
	ut := t.Time.UTC()
	dur := time.Now().UTC().Sub(ut)
	durStrBase := strings.Split(dur.String(), ".")[0] + "s"
	re := regexp.MustCompile(`\d+[a-z]`)
	age := re.FindString(durStrBase)
	return age
}
