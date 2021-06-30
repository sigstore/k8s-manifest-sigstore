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

	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8ssigutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewCmdVerify() *cobra.Command {

	var imageRef string
	var filename string
	var keyPath string
	var configPath string
	cmd := &cobra.Command{
		Use:   "verify -f <YAMLFILE> [-i <IMAGE>]",
		Short: "A command to verify Kubernetes YAML manifests",
		RunE: func(cmd *cobra.Command, args []string) error {

			err := verify(filename, imageRef, keyPath, configPath)
			if err != nil {
				return err
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&filename, "filename", "f", "", "file name which will be signed (if dir, all YAMLs inside it will be signed)")
	cmd.PersistentFlags().StringVarP(&imageRef, "image", "i", "", "signed image name which bundles yaml files")
	cmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "path to your signing key (if empty, do key-less signing)")
	cmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "path to verification config YAML file (for advanced verification)")

	return cmd
}

func verify(filename, imageRef, keyPath, configPath string) error {
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

	vo := &k8smanifest.VerifyManifestOption{}
	if configPath != "" {
		vo, err = k8smanifest.LoadVerifyManifestConfig(configPath)
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

	result, err := k8smanifest.VerifyManifest(manifest, vo)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return nil
	}
	if result.Verified {
		log.Info("verify result:", result)
	} else {
		log.Error("verify result:", result)
	}

	return nil
}
