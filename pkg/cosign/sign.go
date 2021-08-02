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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/pkg/errors"
	cosigncli "github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/pkg/cosign"
	fulcioclient "github.com/sigstore/fulcio/pkg/client"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
)

const (
	defaultOIDCIssuer   = "https://oauth2.sigstore.dev/auth"
	defaultOIDCClientID = "sigstore"
)

const certBeginByte = "-----BEGIN CERTIFICATE-----"
const certEndByte = "-----END CERTIFICATE-----"

func SignImage(imageRef string, keyPath, certPath *string, pf cosign.PassFunc, imageAnnotations map[string]interface{}) error {
	// TODO: check usecase for yaml signing

	// TODO: check sk (security key) and idToken (identity token for cert from fulcio)
	sk := false
	idToken := ""

	rekorSeverURL := getRekorServerURL()
	fulcioServerURL := fulcioclient.SigstorePublicServerURL

	opt := cosigncli.KeyOpts{
		Sk:           sk,
		IDToken:      idToken,
		RekorURL:     rekorSeverURL,
		FulcioURL:    fulcioServerURL,
		OIDCIssuer:   defaultOIDCIssuer,
		OIDCClientID: defaultOIDCClientID,
	}
	if pf == nil {
		opt.PassFunc = cosigncli.GetPass
	} else {
		opt.PassFunc = pf
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

func SignBlob(blobPath string, keyPath, certPath *string, pf cosign.PassFunc) (map[string][]byte, error) {
	// TODO: check sk (security key) and idToken (identity token for cert from fulcio)
	sk := false
	idToken := ""

	rekorSeverURL := GetRekorServerURL()
	fulcioServerURL := fulcioclient.SigstorePublicServerURL

	opt := cosigncli.KeyOpts{
		Sk:           sk,
		IDToken:      idToken,
		RekorURL:     rekorSeverURL,
		FulcioURL:    fulcioServerURL,
		OIDCIssuer:   defaultOIDCIssuer,
		OIDCClientID: defaultOIDCClientID,
	}

	if pf == nil {
		opt.PassFunc = cosigncli.GetPass
	} else {
		opt.PassFunc = pf
	}

	if keyPath != nil {
		opt.KeyRef = *keyPath
	}

	m := map[string][]byte{}
	rawMsg, err := ioutil.ReadFile(blobPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load a file to be signed")
	}
	base64Msg := []byte(base64.StdEncoding.EncodeToString(rawMsg))
	m["message"] = base64Msg

	returnValArray, stdoutAndErr := k8smnfutil.SilentExecFunc(cosigncli.SignBlobCmd, context.Background(), opt, blobPath, true, "")

	fmt.Println(stdoutAndErr) // show cosign.SignBlobCmd() logs

	if len(returnValArray) != 2 {
		return nil, fmt.Errorf("cosign.SignBlobCmd() must return 2 values as output, but got %v values", len(returnValArray))
	}
	var b64Sig []byte
	if returnValArray[0] != nil {
		b64Sig = returnValArray[0].([]byte)
	}
	if returnValArray[1] != nil {
		err = returnValArray[1].(error)
	}
	if err != nil {
		return nil, errors.Wrap(err, "cosign.SignBlobCmd() returned an error")
	}

	m["signature"] = b64Sig

	rawCert := extractCertFromStdoutAndErr(stdoutAndErr)
	gzipCert := k8smnfutil.GzipCompress(rawCert)
	base64Cert := []byte(base64.StdEncoding.EncodeToString(gzipCert))
	m["certificate"] = base64Cert

	return m, nil
}

func extractCertFromStdoutAndErr(stdoutAndErr string) []byte {
	re := regexp.MustCompile(fmt.Sprintf(`(?s)%s.*%s`, certBeginByte, certEndByte)) // `(?s)` is necessary for matching multi lines
	foundBlocks := re.FindAllString(stdoutAndErr, 1)
	if len(foundBlocks) == 0 {
		return nil
	}
	return []byte(foundBlocks[0])
}
