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

package k8smanifest

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	k8ssigutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
	mapnode "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util/mapnode"

	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

var EmbeddedAnnotationMaskKeys = []string{
	fmt.Sprintf("metadata.annotations.\"%s\"", ImageRefAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", SignatureAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", CertificateAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", MessageAnnotationKey),
	fmt.Sprintf("metadata.annotations.\"%s\"", BundleAnnotationKey),
}

type VerifyResult struct {
	Verified bool                `json:"verified"`
	Signer   string              `json:"signer"`
	Diff     *mapnode.DiffResult `json:"diff"`
}

func (r *VerifyResult) String() string {
	rB, _ := json.Marshal(r)
	return string(rB)
}

func Verify(manifest []byte, imageRef, keyPath string) (*VerifyResult, error) {
	if manifest == nil {
		return nil, errors.New("input YAML manifest must be non-empty")
	}

	verified := false
	signerName := ""

	// TODO: support directly attached annotation sigantures
	if imageRef != "" {
		image, err := k8ssigutil.PullImage(imageRef)
		if err != nil {
			return nil, errors.Wrap(err, "failed to pull image")
		}
		ok, tmpDiff, err := matchManifest(manifest, image)
		if err != nil {
			return nil, errors.Wrap(err, "failed to match manifest")
		}
		if !ok {
			return &VerifyResult{
				Verified: false,
				Signer:   "",
				Diff:     tmpDiff,
			}, nil
		}

		verified, signerName, err = imageVerify(imageRef, &keyPath)
		if err != nil {
			return nil, errors.Wrap(err, "failed to verify image")
		}
	}

	return &VerifyResult{
		Verified: verified,
		Signer:   signerName,
	}, nil

}

func imageVerify(imageRef string, pubkeyPath *string) (bool, string, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return false, "", fmt.Errorf("failed to parse image ref `%s`; %s", imageRef, err.Error())
	}

	co := &cosign.CheckOpts{
		Claims: true,
		Tlog:   true,
		Roots:  fulcio.Roots,
	}

	if pubkeyPath != nil && *pubkeyPath != "" {
		tmpPubkey, err := cosign.LoadPublicKey(context.Background(), *pubkeyPath)
		if err != nil {
			return false, "", fmt.Errorf("error loading public key; %s", err.Error())
		}
		co.PubKey = tmpPubkey
	}

	rekorSever := cli.TlogServer()
	verified, err := cosign.Verify(context.Background(), ref, co, rekorSever)
	if err != nil {
		return false, "", fmt.Errorf("error occured while verifying image `%s`; %s", imageRef, err.Error())
	}
	if len(verified) == 0 {
		return false, "", fmt.Errorf("no verified signatures in the image `%s`; %s", imageRef, err.Error())
	}
	var cert *x509.Certificate
	for _, vp := range verified {
		ss := payload.SimpleContainerImage{}
		err := json.Unmarshal(vp.Payload, &ss)
		if err != nil {
			continue
		}
		cert = vp.Cert
		break
	}

	signerName := "" // singerName could be empty in case of key-used verification
	if cert != nil {
		signerName = k8ssigutil.GetNameInfoFromCert(cert)
	}
	return true, signerName, nil
}

func matchManifest(manifest []byte, image v1.Image) (bool, *mapnode.DiffResult, error) {
	concatYAMLFromImage, err := k8ssigutil.GenerateConcatYAMLsFromImage(image)
	if err != nil {
		return false, nil, err
	}
	log.Debug("manifest:", string(manifest))
	log.Debug("manifest in image:", string(concatYAMLFromImage))
	inputFileNode, err := mapnode.NewFromYamlBytes(manifest)
	if err != nil {
		return false, nil, err
	}
	maskedInputNode := inputFileNode.Mask(EmbeddedAnnotationMaskKeys)

	var obj unstructured.Unstructured
	err = yaml.Unmarshal(manifest, &obj)
	if err != nil {
		return false, nil, err
	}
	apiVersion := obj.GetAPIVersion()
	kind := obj.GetKind()
	name := obj.GetName()
	namespace := obj.GetNamespace()
	found, foundBytes := k8ssigutil.FindSingleYaml(concatYAMLFromImage, apiVersion, kind, name, namespace)
	if !found {
		return false, nil, errors.New("failed to find the input file in image")
	}
	manifestNode, err := mapnode.NewFromYamlBytes(foundBytes)
	if err != nil {
		return false, nil, err
	}
	maskedManifestNode := manifestNode.Mask(EmbeddedAnnotationMaskKeys)
	diff := maskedInputNode.Diff(maskedManifestNode)
	if diff == nil || diff.Size() == 0 {
		return true, nil, nil
	}
	return false, diff, nil
}
