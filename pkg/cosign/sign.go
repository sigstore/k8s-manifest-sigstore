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
	"github.com/sigstore/cosign/pkg/cosign"
)

func SignImage(imageRef string, keyPath, certPath *string, pf cosign.PassFunc, imageAnnotations map[string]interface{}) error {
	// TODO: check usecase for yaml signing

	// TODO: check sk (security key) and idToken (identity token for cert from fulcio)
	sk := false
	idToken := ""

	rekorSeverURL := getRekorServerURL()

	opt := cosigncli.KeyOpts{
		Sk:       sk,
		IDToken:  idToken,
		RekorURL: rekorSeverURL,
	}
	if pf != nil {
		opt.PassFunc = pf
	} else {
		opt.PassFunc = cosigncli.GetPass
	}

	if keyPath != nil {
		opt.KeyRef = *keyPath
	}
	certPathStr := ""
	if certPath != nil {
		certPathStr = *certPath
	}

	return cosigncli.SignCmd(context.Background(), opt, imageAnnotations, imageRef, certPathStr, true, "", false, false)
}
