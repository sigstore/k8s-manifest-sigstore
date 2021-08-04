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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/pkg/cosign"
	cremote "github.com/sigstore/cosign/pkg/cosign/remote"
	fulcioclient "github.com/sigstore/fulcio/pkg/client"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

const (
	tmpMessageFile     = "k8s-manifest-sigstore-message"
	tmpCertificateFile = "k8s-manifest-sigstore-certificate"
	tmpSignatureFile   = "k8s-manifest-sigstore-signature"
)

func VerifyImage(imageRef string, pubkeyPath string) (bool, string, *int64, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return false, "", nil, fmt.Errorf("failed to parse image ref `%s`; %s", imageRef, err.Error())
	}

	rekorSeverURL := getRekorServerURL()

	co := &cosign.CheckOpts{
		ClaimVerifier: cosign.SimpleClaimVerifier,
		RegistryClientOpts: []remote.Option{
			remote.WithAuthFromKeychain(authn.DefaultKeychain),
			remote.WithContext(context.Background()),
		},
	}

	if pubkeyPath == "" {
		co.RekorURL = rekorSeverURL
		co.RootCerts = fulcio.Roots
	} else {
		pubkeyVerifier, err := cli.LoadPublicKey(context.Background(), pubkeyPath)
		if err != nil {
			return false, "", nil, fmt.Errorf("error loading public key; %s", err.Error())
		}
		co.SigVerifier = pubkeyVerifier
	}

	verified, err := cosign.Verify(context.Background(), ref, co)
	if err != nil {
		return false, "", nil, fmt.Errorf("error occured while verifying image `%s`; %s", imageRef, err.Error())
	}
	if len(verified) == 0 {
		return false, "", nil, fmt.Errorf("no verified signatures in the image `%s`; %s", imageRef, err.Error())
	}
	var cert *x509.Certificate
	var signedTimestamp *int64
	for _, vp := range verified {
		ss := payload.SimpleContainerImage{}
		err := json.Unmarshal(vp.Payload, &ss)
		if err != nil {
			continue
		}
		// if tstamp, err := getSignedTimestamp(rekorSever, vp, co); err == nil {
		// 	signedTimestamp = tstamp
		// }
		cert = vp.Cert
		break
	}
	signerName := "" // singerName could be empty in case of key-used verification
	if cert != nil {
		signerName = k8smnfutil.GetNameInfoFromCert(cert)
	}
	return true, signerName, signedTimestamp, nil
}

func VerifyBlob(msgBytes, sigBytes, certBytes, bundleBytes []byte, pubkeyPath *string) (bool, string, *int64, error) {
	dir, err := ioutil.TempDir("", "kubectl-sigstore-temp-dir")
	if err != nil {
		return false, "", nil, err
	}
	defer os.RemoveAll(dir)

	gzipMsg, _ := base64.StdEncoding.DecodeString(string(msgBytes))
	rawMsg := k8smnfutil.GzipDecompress(gzipMsg)
	msgFile := filepath.Join(dir, tmpMessageFile)
	_ = ioutil.WriteFile(msgFile, rawMsg, 0777)

	rawSig, _ := base64.StdEncoding.DecodeString(string(sigBytes))
	sigFile := filepath.Join(dir, tmpSignatureFile)
	_ = ioutil.WriteFile(sigFile, rawSig, 0777)

	var certFile string
	var rawCert []byte
	if certBytes != nil {
		gzipCert, _ := base64.StdEncoding.DecodeString(string(certBytes))
		rawCert = k8smnfutil.GzipDecompress(gzipCert)
		certFile = filepath.Join(dir, tmpCertificateFile)
		_ = ioutil.WriteFile(certFile, rawCert, 0777)
	}

	// if bundle is provided, try verifying it in offline first and return results if verified
	if bundleBytes != nil {
		gzipBundle, _ := base64.StdEncoding.DecodeString(string(bundleBytes))
		rawBundle := k8smnfutil.GzipDecompress(gzipBundle)
		verified, signerName, signedTimestamp, err := verifyBundle(rawMsg, sigBytes, rawCert, rawBundle)
		log.Debugf("verifyBundle() results: verified: %v, signerName: %s, err: %s", verified, signerName, err)
		if verified {
			log.Debug("Verified by bundle information")
			return verified, signerName, signedTimestamp, err
		}
	}
	// otherwise, use cosign.VerifyBundleCmd for verification

	// TODO: check sk (security key) and idToken (identity token for cert from fulcio)
	sk := false
	idToken := ""

	rekorSeverURL := GetRekorServerURL()
	fulcioServerURL := fulcioclient.SigstorePublicServerURL

	opt := cli.KeyOpts{
		Sk:           sk,
		IDToken:      idToken,
		RekorURL:     rekorSeverURL,
		FulcioURL:    fulcioServerURL,
		OIDCIssuer:   defaultOIDCIssuer,
		OIDCClientID: defaultOIDCClientID,
	}

	if pubkeyPath != nil {
		opt.KeyRef = *pubkeyPath
	}

	returnValNum := 1
	returnValArray, stdoutAndErr := k8smnfutil.SilentExecFunc(cli.VerifyBlobCmd, context.Background(), opt, certFile, sigFile, msgFile)

	log.Debug(stdoutAndErr) // show cosign.VerifyBlobCmd() logs

	if len(returnValArray) != returnValNum {
		return false, "", nil, fmt.Errorf("cosign.VerifyBlobCmd() must return %v values as output, but got %v values", returnValNum, len(returnValArray))
	}
	if returnValArray[0] != nil {
		err = returnValArray[0].(error)
	}
	if err != nil {
		err = fmt.Errorf("error: %s, detail logs during cosign.VerifyBlobCmd(): %s", err.Error(), stdoutAndErr)
		return false, "", nil, errors.Wrap(err, "cosign.VerifyBlobCmd() returned an error")
	}
	verified := false
	if err == nil {
		verified = true
	}

	var signerName string
	if rawCert != nil {
		cert, err := loadCertificate(rawCert)
		if err != nil {
			return false, "", nil, errors.Wrap(err, "failed to load certificate")
		}
		signerName = getNameInfoFromCert(cert)
	}

	return verified, signerName, nil, nil
}

func loadCertificate(pemBytes []byte) (*x509.Certificate, error) {
	p, _ := pem.Decode(pemBytes)
	if p == nil {
		return nil, errors.New("failed to decode PEM bytes")
	}
	return x509.ParseCertificate(p.Bytes)
}

func getNameInfoFromCert(cert *x509.Certificate) string {
	name := ""
	if len(cert.EmailAddresses) > 0 {
		name = cert.EmailAddresses[0]
	}
	return name
}

// func getSignedTimestamp(rekorServerURL string, sp cosign.SignedPayload, co *cosign.CheckOpts) (*int64, error) {
// 	if !co.Tlog {
// 		return nil, nil
// 	}

// 	rekorClient, err := app.GetRekorClient(rekorServerURL)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Get the right public key to use (key or cert)
// 	var pemBytes []byte
// 	if co.PubKey != nil {
// 		pemBytes, err = cosign.PublicKeyPem(context.Background(), co.PubKey)
// 		if err != nil {
// 			return nil, err
// 		}
// 	} else {
// 		pemBytes = cosign.CertToPem(sp.Cert)
// 	}

// 	// Find the uuid then the entry.
// 	uuid, _, err := sp.VerifyTlog(rekorClient, pemBytes)
// 	if err != nil {
// 		return nil, err
// 	}

// 	params := entries.NewGetLogEntryByUUIDParams()
// 	params.SetEntryUUID(uuid)
// 	resp, err := rekorClient.Entries.GetLogEntryByUUID(params)
// 	if err != nil {
// 		return nil, err
// 	}
// 	for _, e := range resp.Payload {
// 		return e.IntegratedTime, nil
// 	}
// 	return nil, errors.New("empty response")
// }

func verifyBundle(rawMsg, b64Sig, rawCert, rawBundle []byte) (bool, string, *int64, error) {
	cert, err := loadCertificate(rawCert)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "loading certificate")
	}
	var bundleObj *cremote.Bundle
	err = json.Unmarshal(rawBundle, &bundleObj)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "unmarshaling bundleObj")
	}
	sp := &cosign.SignedPayload{
		Base64Signature: string(b64Sig),
		Payload:         rawMsg, // not sure if this is correct, but payload is not used in VerifyBundle()
		Cert:            cert,
		Bundle:          bundleObj,
	}
	verified, err := sp.VerifyBundle()
	if err != nil {
		return false, "", nil, errors.Wrap(err, "verifying bundle")
	}
	var signerName string
	if verified {
		signerName = getNameInfoFromCert(cert)
	}
	return verified, signerName, nil, nil
}
