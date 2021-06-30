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

	cosigncli "github.com/sigstore/cosign/cmd/cosign/cli"
)

func SignImage(imageRef string, keyPath *string) error {
	// TODO: check usecase for yaml signing
	imageAnnotation := map[string]interface{}{}

	// TODO: check sk (security key) and idToken (identity token for cert from fulcio)
	sk := false
	idToken := ""

	// TODO: handle the case that COSIGN_EXPERIMENTAL env var is not set

	opt := cosigncli.SignOpts{
		Annotations: imageAnnotation,
		Sk:          sk,
		IDToken:     idToken,
	}

	if keyPath != nil {
		opt.KeyRef = *keyPath
		opt.Pf = cosigncli.GetPass
	}

	return cosigncli.SignCmd(context.Background(), opt, imageRef, true, "", false, false)
}
