//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"time"

	"github.com/pkg/errors"
	kustbuildutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/manifestbuild/kustomize"
	"github.com/spf13/cobra"
)

func NewCmdManifestBuild() *cobra.Command {

	var baseDir string
	var imageRef string
	var keyPath string
	var outputPath string
	var provenancePath string
	var kustomizeMode bool
	var signProvenance bool
	cmd := &cobra.Command{
		Use:   "manifest-build --kustomize -d BASE_DIR -o MANIFEST_OUTPUT --provenance PROVENANCE_OUTPUT",
		Short: "A command to build a Kubernetes YAML manifest with provenance",
		RunE: func(cmd *cobra.Command, args []string) error {

			err := buildManifest(baseDir, outputPath, provenancePath, imageRef, keyPath, kustomizeMode, signProvenance)
			if err != nil {
				return err
			}
			return nil
		},
	}

	cmd.PersistentFlags().BoolVar(&kustomizeMode, "kustomize", false, "enable kustomize mode")
	cmd.PersistentFlags().BoolVar(&signProvenance, "sign", false, "whether to sign a generated provenance for uploading it to rekor")
	cmd.PersistentFlags().StringVarP(&baseDir, "dir", "d", "", "kustomize base dir")
	cmd.PersistentFlags().StringVarP(&outputPath, "output", "o", "", "path to output manifest file")
	cmd.PersistentFlags().StringVarP(&provenancePath, "provenance", "p", "", "path to output provenance file")
	cmd.PersistentFlags().StringVarP(&imageRef, "image", "i", "", "image reference in which a generated manifest is stored")
	cmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "path to your signing key")
	return cmd
}

func buildManifest(baseDir, outputPath, provenancePath, imageRef, keyPath string, kustomizeMode, signProvenance bool) error {
	startTime := time.Now().UTC()
	wd, err := os.Getwd()
	if err != nil {
		return errors.Wrap(err, "failed to get current working directory")
	}
	// baseDir = filepath.Clean(filepath.Join(wd, baseDir))
	// TODO: support additinoal args for kustomize command
	manifest, err := kustbuildutil.KustomizeExec(wd, "build", baseDir)
	if err != nil {
		return errors.Wrap(err, "failed to execute kustomize build")
	}
	manifestFile := outputPath
	err = ioutil.WriteFile(manifestFile, []byte(manifest), 0644)
	if err != nil {
		return errors.Wrap(err, "failed to create a manifest file")
	}
	digest, err := kustbuildutil.GetDigestOfArtifact(manifestFile)
	if err != nil {
		return errors.Wrap(err, "failed to get a digest of a generated manifest file")
	}

	finishTime := time.Now().UTC()
	recipeCmds := []string{"kubectl", "sigstore"}
	recipeCmds = append(recipeCmds, os.Args[1:]...)
	prov, err := kustbuildutil.GenerateProvenance(provenancePath, digest, baseDir, startTime, finishTime, recipeCmds)
	if err != nil {
		return errors.Wrap(err, "failed to generate a provenance")
	}
	provBytes, err := json.Marshal(prov)
	if err != nil {
		return errors.Wrap(err, "failed to marshal provenance")
	}
	tmpProvFile := "./provenance.json"
	err = ioutil.WriteFile(tmpProvFile, provBytes, 0644)
	if err != nil {
		return errors.Wrap(err, "failed to create a provenance file")
	}

	if signProvenance && keyPath != "" {
		attestation, err := kustbuildutil.GenerateAttestation(tmpProvFile, keyPath)
		if err != nil {
			return errors.Wrap(err, "failed to generate an attestation data")
		}
		attestationBytes, err := json.Marshal(attestation)
		if err != nil {
			return errors.Wrap(err, "failed to marshal an attestation data")
		}
		tmpAttestationFile := "./attestation.json"
		err = ioutil.WriteFile(tmpAttestationFile, attestationBytes, 0644)
		if err != nil {
			return errors.Wrap(err, "failed to create an attestation file")
		}
	}

	return nil
}
