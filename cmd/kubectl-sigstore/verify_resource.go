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

	"github.com/spf13/cobra"
	"github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/k8smanifest"
	k8ssigutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
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

	results := []*k8smanifest.VerifyResourceResult{}
	for _, obj := range objs {
		result, err := k8smanifest.VerifyResource(obj, imageRef, keyPath, vo)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return nil
		}
		log.Debug("kind: ", obj.GetKind(), ", name: ", obj.GetName(), ", result: ", result)
		results = append(results, result)
	}

	resultTable := makeResourceResultTable(results)
	fmt.Println(string(resultTable))

	return nil
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

func makeResourceResultTable(results []*k8smanifest.VerifyResourceResult) []byte {
	tableResult := "NAME\tINSCOPE\tVERIFIED\tSIGNER\tAGE\t\n"
	for _, r := range results {
		obj := r.Object
		verified := strconv.FormatBool(r.Verified)
		resName := obj.GetName()
		resTime := obj.GetCreationTimestamp()
		resAge := getAge(resTime)
		inscope := strconv.FormatBool(r.InScope)
		signer := r.Signer
		line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t\n", resName, inscope, verified, signer, resAge)
		tableResult = fmt.Sprintf("%s%s", tableResult, line)
	}
	writer := new(bytes.Buffer)
	w := tabwriter.NewWriter(writer, 0, 3, 3, ' ', 0)
	w.Write([]byte(tableResult))
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
