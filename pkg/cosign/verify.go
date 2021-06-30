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

package cosign

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

func VerifyImage(imageRef string, pubkeyPath *string) (bool, string, error) {
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
		signerName = k8smnfutil.GetNameInfoFromCert(cert)
	}
	return true, signerName, nil
}
