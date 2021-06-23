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
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/k8smanifest"
	k8ssigutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
)

func NewCmdApplyAfterVerify() *cobra.Command {

	var imageRef string
	var filename string
	var keyPath string
	cmd := &cobra.Command{
		Use:   "apply-after-verify -f <YAMLFILE> [-i <IMAGE>]",
		Short: "A command to apply Kubernetes YAML manifests only after verifying signature",
		RunE: func(cmd *cobra.Command, args []string) error {
			fullArgs := getOriginalFullArgs("apply-after-verify") // TODO: find a better way get all args
			_, kubeApplyArgs := splitApplyArgs(fullArgs)
			if filename != "" {
				kubeApplyArgs = append(kubeApplyArgs, []string{"--filename", filename}...)
			}
			err := applyAfterVerify(filename, imageRef, keyPath, kubeApplyArgs)
			if err != nil {
				return err
			}
			return nil
		},
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
	}

	cmd.PersistentFlags().StringVarP(&filename, "filename", "f", "", "file name which will be signed (if dir, all YAMLs inside it will be signed)")
	cmd.PersistentFlags().StringVarP(&imageRef, "image", "i", "", "signed image name which bundles yaml files")
	cmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "path to your signing key (if empty, do key-less signing)")

	return cmd
}

func applyAfterVerify(filename, imageRef, keyPath string, kubeApplyArgs []string) error {
	manifest, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return nil
	}

	annotations := k8ssigutil.GetAnnotationsInYAML(manifest)
	annoImageRef, annoImageRefFound := annotations[k8smanifest.ImageRefAnnotationKey]
	if imageRef == "" && annoImageRefFound {
		imageRef = annoImageRef
	}
	log.Debug("annotations", annotations)
	log.Debug("imageRef", imageRef)

	result, err := k8smanifest.Verify(manifest, imageRef, keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return nil
	}
	if result.Verified {
		log.Info("verify result:", result)
		kArgs := []string{"apply"}
		kArgs = append(kArgs, kubeApplyArgs...)
		log.Debug("kube apply args", strings.Join(kArgs, " "))
		applyResult, err := k8ssigutil.CmdExec("kubectl", kArgs...)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return nil
		}
		fmt.Println(applyResult)
	} else {
		log.Error("verify result:", result)
	}

	return nil
}

func getOriginalFullArgs(separator string) []string {
	afterSeparator := false
	args := []string{}
	for _, arg := range os.Args {
		if afterSeparator {
			args = append(args, arg)
		}

		if arg == separator {
			afterSeparator = true
		}
	}
	return args
}

func splitApplyArgs(args []string) ([]string, []string) {
	mainArgs := []string{}
	kubectlArgs := []string{}
	mainArgsCondition := map[string]bool{
		"--filename": true,
		"-f":         true,
		"--image":    true,
		"-i":         true,
		"--key":      true,
		"-k":         true,
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
