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
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	cliopt "github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	cliverify "github.com/sigstore/cosign/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/bundle"
	"github.com/sigstore/cosign/pkg/cosign/pkcs11key"
	sigs "github.com/sigstore/cosign/pkg/signature"
	fulcioapi "github.com/sigstore/fulcio/pkg/api"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	k8ssigx509 "github.com/sigstore/k8s-manifest-sigstore/pkg/util/sigtypes/x509"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
)

func VerifyImage(resBundleRef, pubkeyPath, certRef, certChain, rekorURL, oidcIssuer string, rootCerts *x509.CertPool, allowInsecure bool) (bool, string, *int64, error) {
	ref, err := name.ParseReference(resBundleRef)
	if err != nil {
		return false, "", nil, fmt.Errorf("failed to parse image ref `%s`; %s", resBundleRef, err.Error())
	}

	var rekorSeverURL string
	if rekorURL == "" {
		rekorSeverURL = GetRekorServerURL()
	} else {
		rekorSeverURL = rekorURL
	}

	regOpt := &cliopt.RegistryOptions{}
	if allowInsecure {
		regOpt.AllowInsecure = true
	}
	reqCliOpt, err := regOpt.ClientOpts(context.Background())
	if err != nil {
		return false, "", nil, fmt.Errorf("failed to get registry client option; %s", err.Error())
	}

	co := &cosign.CheckOpts{
		ClaimVerifier:      cosign.SimpleClaimVerifier,
		RegistryClientOpts: reqCliOpt,
	}

	if cliopt.EnableExperimental() {
		rekorClient, err := rekor.NewClient(rekorSeverURL)
		if err != nil {
			return false, "", nil, fmt.Errorf("failed to initialize rekor client; %s", err.Error())
		}
		co.RekorClient = rekorClient
		if rootCerts != nil {
			co.RootCerts = rootCerts
		} else {
			co.RootCerts, err = fulcio.GetRoots()
			if err != nil {
				return false, "", nil, fmt.Errorf("failed to get fulcio root; %s", err.Error())
			}
		}
		co.CertOidcIssuer = oidcIssuer
	}

	if pubkeyPath != "" {
		pubKeyVerifier, err := sigs.PublicKeyFromKeyRef(context.Background(), pubkeyPath)
		if err != nil {
			return false, "", nil, fmt.Errorf("failed to load public key; %s", err.Error())
		}
		pkcs11Key, ok := pubKeyVerifier.(*pkcs11key.Key)
		if ok {
			defer pkcs11Key.Close()
		}
		co.SigVerifier = pubKeyVerifier
	} else if certRef != "" {
		cert, err := k8ssigx509.LoadCertificate(certRef)
		if err != nil {
			return false, "", nil, fmt.Errorf("failed to load certificate; %s", err.Error())
		}
		var sigVerifier signature.Verifier
		if certChain == "" {
			err = cosign.CheckCertificatePolicy(cert, co)
			if err != nil {
				return false, "", nil, fmt.Errorf("certificate check failed; %s", err.Error())
			}
			sigVerifier, err = signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
			if err != nil {
				return false, "", nil, fmt.Errorf("failed to initialize signature verifier; %s", err.Error())
			}
		} else {
			// Verify certificate with chain
			chain, err := k8ssigx509.LoadCertificateChain(certChain)
			if err != nil {
				return false, "", nil, fmt.Errorf("failed to load certificate chain; %s", err.Error())
			}
			sigVerifier, err = cosign.ValidateAndUnpackCertWithChain(cert, chain, co)
			if err != nil {
				return false, "", nil, fmt.Errorf("certificate chain validation failed; %s", err.Error())
			}
		}
		co.SigVerifier = sigVerifier
	}

	checkedSigs, _, err := cosign.VerifyImageSignatures(context.Background(), ref, co)
	if err != nil {
		return false, "", nil, fmt.Errorf("error occured while verifying image `%s`; %s", resBundleRef, err.Error())
	}
	if len(checkedSigs) == 0 {
		return false, "", nil, fmt.Errorf("no verified signatures in the image `%s`; %s", resBundleRef, err.Error())
	}
	var cert *x509.Certificate
	var signedTimestamp *int64
	for _, s := range checkedSigs {
		payloadBytes, err := s.Payload()
		if err != nil {
			continue
		}
		ss := payload.SimpleContainerImage{}
		err = json.Unmarshal(payloadBytes, &ss)
		if err != nil {
			continue
		}
		// if tstamp, err := getSignedTimestamp(rekorSever, vp, co); err == nil {
		// 	signedTimestamp = tstamp
		// }
		cert, err = s.Cert()
		if err != nil {
			continue
		}
		break
	}
	signerName := "" // singerName could be empty in case of key-used verification
	if cert != nil {
		signerName = k8smnfutil.GetNameInfoFromCert(cert)
	}
	return true, signerName, signedTimestamp, nil
}

func VerifyBlob(msgBytes, sigBytes, certBytes, bundleBytes []byte, pubkeyPath *string, certRef, certChain, rekorURL, oidcIssuer string) (bool, string, *int64, error) {
	gzipMsg, _ := base64.StdEncoding.DecodeString(string(msgBytes))
	rawMsg := k8smnfutil.GzipDecompress(gzipMsg)
	b64Sig := sigBytes

	var rawCert []byte
	if certBytes != nil {
		gzipCert, _ := base64.StdEncoding.DecodeString(string(certBytes))
		rawCert = k8smnfutil.GzipDecompress(gzipCert)
	}

	// if bundle is provided, try verifying it in offline first and return results if verified
	if bundleBytes != nil {
		gzipBundle, _ := base64.StdEncoding.DecodeString(string(bundleBytes))
		rawBundle := k8smnfutil.GzipDecompress(gzipBundle)
		b64Bundle := base64.StdEncoding.EncodeToString(rawBundle)
		verified, signerName, signedTimestamp, err := verifyBundle(rawMsg, b64Sig, rawCert, []byte(b64Bundle))
		log.Debugf("verifyBundle() results: verified: %v, signerName: %s, err: %s", verified, signerName, err)
		if verified {
			log.Debug("Verified by bundle information")
			return verified, signerName, signedTimestamp, err
		}
	}
	// otherwise, use cosign.VerifyBundleCmd for verification

	// TODO: add support for sk (security key) and idToken (identity token for cert from fulcio)
	sk := false
	idToken := ""

	var rekorSeverURL string
	if rekorURL == "" {
		rekorSeverURL = GetRekorServerURL()
	} else {
		rekorSeverURL = rekorURL
	}
	fulcioServerURL := fulcioapi.SigstorePublicServerURL

	opt := cliopt.KeyOpts{
		Sk:        sk,
		IDToken:   idToken,
		RekorURL:  rekorSeverURL,
		FulcioURL: fulcioServerURL,
	}

	if pubkeyPath != nil {
		opt.KeyRef = *pubkeyPath
	}

	stdinReader, stdinWriter, err := os.Pipe()
	if err != nil {
		return false, "", nil, errors.Wrap(err, "failed to create a virtual standard input")
	}
	origStdin := os.Stdin
	os.Stdin = stdinReader
	_, err = stdinWriter.Write(rawMsg)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "failed to write a message data to virtual standard input")
	}
	_ = stdinWriter.Close()
	err = cliverify.VerifyBlobCmd(context.Background(), opt, certRef, "", "", oidcIssuer, certChain, string(b64Sig), "-", "", "", "", "", "", false)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "cosign.VerifyBlobCmd() returned an error")
	}
	os.Stdin = origStdin
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
		signerName = k8ssigx509.GetNameInfoFromX509Cert(cert)
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

func verifyBundle(rawMsg, b64Sig, rawCert, b64Bundle []byte) (bool, string, *int64, error) {
	sig := &cosignBundleSignature{
		message:         rawMsg,
		base64Signature: b64Sig,
		cert:            rawCert,
		base64Bundle:    b64Bundle,
	}
	rekorSeverURL := GetRekorServerURL()
	rClient, err := rekorclient.GetRekorClient(rekorSeverURL)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "failed to get rekor client")
	}
	verified, err := cosign.VerifyBundle(context.Background(), sig, rClient)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "verifying bundle")
	}
	var signerName string
	if verified {
		cert, _ := sig.Cert()
		signerName = k8ssigx509.GetNameInfoFromX509Cert(cert)
	}
	return verified, signerName, nil, nil
}

type cosignBundleSignature struct {
	v1.Layer
	message         []byte // message will be used as sig.Payload()
	base64Signature []byte
	cert            []byte
	base64Bundle    []byte
}

func (s *cosignBundleSignature) Annotations() (map[string]string, error) {
	return nil, errors.New("not implemented")
}

func (s *cosignBundleSignature) Payload() ([]byte, error) {
	return s.message, nil
}

func (s *cosignBundleSignature) Base64Signature() (string, error) {
	return string(s.base64Signature), nil
}

func (s *cosignBundleSignature) Cert() (*x509.Certificate, error) {
	return loadCertificate(s.cert)
}

func (s *cosignBundleSignature) Chain() ([]*x509.Certificate, error) {
	return nil, errors.New("not implemented")
}

func (s *cosignBundleSignature) Bundle() (*bundle.RekorBundle, error) {
	var b *bundle.RekorBundle
	bundleStr, err := base64.StdEncoding.DecodeString(string(s.base64Bundle))
	if err != nil {
		return nil, errors.Wrap(err, "failed to base64-decode the bundle")
	}
	err = json.Unmarshal([]byte(bundleStr), &b)
	if err != nil {
		return nil, errors.Wrap(err, "failed to Unamrshal() bundle")
	}
	return b, nil
}
