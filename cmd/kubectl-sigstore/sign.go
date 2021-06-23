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
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/k8smanifest"
)

func NewCmdSign() *cobra.Command {

	var imageRef string
	var inputDir string
	var keyPath string
	var output string
	var updateAnnotation bool
	cmd := &cobra.Command{
		Use:   "sign -f <YAMLFILE> [-i <IMAGE>]",
		Short: "A command to sign Kubernetes YAML manifests",
		RunE: func(cmd *cobra.Command, args []string) error {

			err := sign(inputDir, imageRef, keyPath, output, updateAnnotation)
			if err != nil {
				return err
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&inputDir, "filename", "f", "", "file name which will be signed (if dir, all YAMLs inside it will be signed)")
	cmd.PersistentFlags().StringVarP(&imageRef, "image", "i", "", "signed image name which bundles yaml files")
	cmd.PersistentFlags().StringVarP(&output, "output", "o", "", "output file name (if empty, use `<input>.signed`)")
	cmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "path to your signing key (if empty, do key-less signing)")
	cmd.PersistentFlags().BoolVarP(&updateAnnotation, "annotation", "a", true, "whether to update annotation and generate signed yaml file")

	return cmd
}

func sign(inputDir, imageRef, keyPath, output string, updateAnnotation bool) error {
	if output == "" {
		output = inputDir + ".signed"
	}

	_, err := k8smanifest.Sign(inputDir, imageRef, keyPath, output, updateAnnotation)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return nil
	}
	log.Info("signed manifest generated at ", output)
	return nil
}
