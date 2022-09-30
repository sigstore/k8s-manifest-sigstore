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
	"fmt"
	"os"
	"strconv"

	"github.com/ghodss/yaml"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8ssigutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func NewCmdVerify() *cobra.Command {

	var resBundleRef string
	var filename string
	var keyPath string
	var configPath string
	var certRef string
	var certChain string
	var rekorURL string
	var oidcIssuer string
	var allowInsecure bool
	cmd := &cobra.Command{
		Use:   "verify -f FILENAME [-i IMAGE]",
		Short: "A command to verify Kubernetes YAML manifests",
		RunE: func(cmd *cobra.Command, args []string) error {

			err := verify(filename, resBundleRef, keyPath, configPath, certRef, certChain, rekorURL, oidcIssuer, allowInsecure)
			if err != nil {
				return err
			}
			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&filename, "filename", "f", "", "file name which will be verified")
	cmd.PersistentFlags().StringVarP(&resBundleRef, "image", "i", "", "a comma-separated list of signed image names that contains YAML manifests")
	cmd.PersistentFlags().StringVarP(&keyPath, "key", "k", "", "a comma-separated list of paths to public keys or environment variable names start with \"env://\" (if empty, do key-less verification)")
	cmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "path to verification config YAML file (for advanced verification)")

	// the following flags are based on cosign verify command
	cmd.PersistentFlags().StringVar(&certRef, "certificate", "", "path to the public certificate")
	cmd.PersistentFlags().StringVar(&certChain, "certificate-chain", "", "path to a list of CA certificates in PEM format which will be needed when building the certificate chain for the signing certificate. Must start with the parent intermediate CA certificate of the signing certificate and end with the root certificate")
	cmd.PersistentFlags().StringVar(&rekorURL, "rekor-url", "https://rekor.sigstore.dev", "URL of rekor STL server (default \"https://rekor.sigstore.dev\")")
	cmd.PersistentFlags().StringVar(&oidcIssuer, "oidc-issuer", "", "the OIDC issuer expected in a valid Fulcio certificate, e.g. https://token.actions.githubusercontent.com or https://oauth2.sigstore.dev/auth")
	cmd.PersistentFlags().BoolVar(&allowInsecure, "allow-insecure-registry", false, "whether to allow insecure connections to registries. Don't use this for anything but testing")

	return cmd
}

func verify(filename, resBundleRef, keyPath, configPath, certRef, certChain, rekorURL, oidcIssuer string, allowInsecure bool) error {
	manifest, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return nil
	}

	vo := &k8smanifest.VerifyManifestOption{}
	if configPath != "" {
		vo, err = k8smanifest.LoadVerifyManifestConfig(configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return nil
		}
	}
	// add signature/message/others annotations to ignore fields
	vo.SetAnnotationIgnoreFields()

	annotations := k8ssigutil.GetAnnotationsInYAML(manifest)
	resBundleRefAnnotationKey := vo.AnnotationConfig.ResourceBundleRefAnnotationKey()
	if annoResBundleRef, annoResBundleRefFound := annotations[resBundleRefAnnotationKey]; annoResBundleRefFound {
		resBundleRef = annoResBundleRef
	}
	log.Debug("annotations", annotations)
	log.Debug("resourceBundleRef", resBundleRef)

	if resBundleRef != "" {
		vo.ResourceBundleRef = resBundleRef
	}
	if keyPath != "" {
		vo.KeyPath = keyPath
	}
	if allowInsecure {
		vo.AllowInsecure = true
	}
	vo.Certificate = certRef
	vo.CertificateChain = certChain
	vo.RekorURL = rekorURL
	vo.OIDCIssuer = oidcIssuer

	objManifests := k8ssigutil.SplitConcatYAMLs(manifest)
	verified := false
	verifiedCount := 0
	signerName := ""
	diffMsg := ""
	var reterr error
	for _, objManifest := range objManifests {
		result, verr := k8smanifest.VerifyManifest(objManifest, vo)
		if verr != nil {
			reterr = verr
			break
		}
		if result != nil {
			if result.Verified {
				signerName = result.Signer
				verifiedCount += 1
			} else if result.Diff != nil && result.Diff.Size() > 0 {
				var obj unstructured.Unstructured
				_ = yaml.Unmarshal(objManifest, &obj)
				kind := obj.GetKind()
				name := obj.GetName()
				diffMsg = fmt.Sprintf("Diff found in %s %s, diffs:%s", kind, name, result.Diff.String())
				break
			}
		}
	}
	if verifiedCount == len(objManifests) {
		verified = true
	}
	if verified {
		if signerName == "" {
			log.Infof("verified: %s", strconv.FormatBool(verified))
		} else {
			log.Infof("verified: %s, signerName: %s", strconv.FormatBool(verified), signerName)
		}
	} else {
		errMsg := ""
		if reterr != nil {
			errMsg = reterr.Error()
		} else {
			errMsg = diffMsg
		}
		log.Fatalf("verified: %s, error: %s", strconv.FormatBool(verified), errMsg)
	}

	return nil
}
