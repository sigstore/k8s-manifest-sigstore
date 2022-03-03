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

package sigtypes

import (
	"context"

	cosignsig "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/sigtypes/pgp"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/sigtypes/x509"
)

type SigType string

const (
	SigTypeUnknown = ""
	SigTypeCosign  = "cosign"
	SigTypePGP     = "pgp"
	SigTypeX509    = "x509"
)

func GetSignatureTypeFromPublicKey(keyPathPtr *string) SigType {
	// keyless
	if keyPathPtr == nil {
		return SigTypeCosign
	}

	// key-ed
	keyRef := *keyPathPtr

	// cosign public key
	if _, err := cosignsig.PublicKeyFromKeyRef(context.Background(), keyRef); err == nil {
		return SigTypeCosign
	}

	// pgp public key
	_, err := pgp.LoadPublicKey(keyRef)
	if err == nil {
		return SigTypePGP
	}

	// x509 ca cert
	_, err = x509.LoadCertificate(keyRef)
	if err == nil {
		return SigTypeX509
	}

	return SigTypeUnknown
}
