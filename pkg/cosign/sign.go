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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/pkg/errors"
	cligen "github.com/sigstore/cosign/cmd/cosign/cli/generate"
	cliopt "github.com/sigstore/cosign/cmd/cosign/cli/options"
	clisign "github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	fulcioclient "github.com/sigstore/fulcio/pkg/client"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	log "github.com/sirupsen/logrus"
)

const (
	rekorServerEnvKey        = "REKOR_SERVER"
	defaultRekorServerURL    = "https://rekor.sigstore.dev"
	defaultOIDCIssuer        = "https://oauth2.sigstore.dev/auth"
	defaultOIDCClientID      = "sigstore"
	cosignPasswordEnvKey     = "COSIGN_PASSWORD"
	defaultTlogUploadTimeout = 3
)

const signBlobTlogIndexLineIdentifier = "tlog entry created with index:"

func SignImage(imageRef string, keyPath, certPath *string, pf cosign.PassFunc, imageAnnotations map[string]interface{}) error {
	// TODO: add support for sk (security key) and idToken (identity token for cert from fulcio)
	sk := false
	idToken := ""

	rekorSeverURL := GetRekorServerURL()
	fulcioServerURL := fulcioclient.SigstorePublicServerURL

	opt := clisign.KeyOpts{
		Sk:           sk,
		IDToken:      idToken,
		RekorURL:     rekorSeverURL,
		FulcioURL:    fulcioServerURL,
		OIDCIssuer:   defaultOIDCIssuer,
		OIDCClientID: defaultOIDCClientID,
	}
	if pf == nil {
		opt.PassFunc = cligen.GetPass
	} else {
		opt.PassFunc = pf
	}

	if keyPath != nil {
		opt.KeyRef = *keyPath
	}

	regOpt := cliopt.RegistryOptions{}

	certPathStr := ""
	if certPath != nil {
		certPathStr = *certPath
	}

	return clisign.SignCmd(context.Background(), opt, regOpt, imageAnnotations, []string{imageRef}, certPathStr, true, "", false, false, "")
}

func SignBlob(blobPath string, keyPath, certPath *string, pf cosign.PassFunc) (map[string][]byte, error) {
	// TODO: add support for sk (security key) and idToken (identity token for cert from fulcio)
	sk := false
	idToken := ""

	rekorSeverURL := GetRekorServerURL()
	fulcioServerURL := fulcioclient.SigstorePublicServerURL

	opt := clisign.KeyOpts{
		Sk:           sk,
		IDToken:      idToken,
		RekorURL:     rekorSeverURL,
		FulcioURL:    fulcioServerURL,
		OIDCIssuer:   defaultOIDCIssuer,
		OIDCClientID: defaultOIDCClientID,
	}

	if pf == nil {
		opt.PassFunc = cligen.GetPass
	} else {
		opt.PassFunc = pf
	}

	if keyPath != nil {
		opt.KeyRef = *keyPath
	}

	// TODO: find a better way to call cosigncli.SignBlobCmd() with interactive stdin and captured stdout
	// might be better to make a PR to cosign so that SignBlobCmd() can reutrn not only signature but also tlog index and others
	if opt.KeyRef != "" && opt.PassFunc != nil {
		pw, err := opt.PassFunc(false)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read a password from input")
		}
		err = os.Setenv(cosignPasswordEnvKey, string(pw))
		if err != nil {
			return nil, errors.Wrap(err, "failed to set a password")
		}
	}

	regOpt := cliopt.RegistryOptions{}

	m := map[string][]byte{}
	rawMsg, err := ioutil.ReadFile(blobPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load a file to be signed")
	}
	gzipMsg := k8smnfutil.GzipCompress(rawMsg)
	base64Msg := []byte(base64.StdEncoding.EncodeToString(gzipMsg))
	m["message"] = base64Msg

	tlogUploadTimeout := defaultTlogUploadTimeout * time.Second

	rawSig, err := clisign.SignBlobCmd(context.Background(), opt, regOpt, blobPath, false, "", tlogUploadTimeout)
	if err != nil {
		return nil, errors.Wrap(err, "cosign.SignBlobCmd() returned an error")
	}

	b64Sig := []byte(base64.StdEncoding.EncodeToString(rawSig))
	m["signature"] = b64Sig

	uploadTlog := cliopt.EnableExperimental()

	var rawCert []byte
	var rawBundle []byte

	if uploadTlog && certPath == nil {
		rClient, err := rekorclient.GetRekorClient(opt.RekorURL)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get rekor client")
		}
		blobBytes, err := ioutil.ReadFile(blobPath)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read blob file")
		}
		uuids, err := cosign.FindTLogEntriesByPayload(rClient, blobBytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to find tlog entry")
		}
		if len(uuids) == 0 {
			return nil, errors.New("could not find a tlog entry for provided blob")
		}
		tlogEntry, err := cosign.GetTlogEntry(rClient, uuids[0])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to find transparency log entry with uuid %s", uuids[0])
		}
		bundleObj := clisign.Bundle(tlogEntry)
		rawBundle, err = json.Marshal(bundleObj)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create a bundle from a tlog entry with uuid %s", uuids[0])
		}

		var rekord *models.Rekord
		if b64EntryStr, ok := tlogEntry.Body.(string); ok {
			log.Debug("found entry: ", b64EntryStr)
			rawEntryBytes, err := base64.StdEncoding.DecodeString(b64EntryStr)
			if err != nil {
				return nil, errors.Wrap(err, "failed to base64 decode tlogEntry.Body")
			}
			err = json.Unmarshal(rawEntryBytes, &rekord)
			if err != nil {
				return nil, errors.Wrap(err, "failed to unmarshal tlogEntry.Body into *models.Rekord")
			}
		}
		if rekord == nil {
			return nil, fmt.Errorf("failed to parse transparency log")
		}

		rekordBytes, _ := json.Marshal(rekord)
		log.Debug("rekord object: ", string(rekordBytes))
		rekordSpecBytes, _ := json.Marshal(rekord.Spec)

		var rekordContent *models.RekordV001Schema
		err = json.Unmarshal(rekordSpecBytes, &rekordContent)
		if err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal rekord.Spec into *models.RekordV001Schema")
		}

		var b64SigInTlog string
		var b64CertStr string
		if rekordContent != nil {
			b64SigInTlog = rekordContent.Signature.Content.String()
			b64CertStr = rekordContent.Signature.PublicKey.Content.String()
		}
		if b64SigInTlog != string(b64Sig) {
			return nil, fmt.Errorf("signature found in tlog is different from original one; found: %s, original: %s", b64SigInTlog, string(b64Sig))
		}
		rawCert, err = base64.StdEncoding.DecodeString(b64CertStr)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode certificate string %s", b64CertStr)
		}
	} else if certPath != nil {
		certPathStr := *certPath
		certPem, err := ioutil.ReadFile(certPathStr)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load certificate at %s", certPathStr)
		}
		rawCert = certPem
	}

	if rawCert != nil {
		gzipCert := k8smnfutil.GzipCompress(rawCert)
		base64Cert := []byte(base64.StdEncoding.EncodeToString(gzipCert))
		m["certificate"] = base64Cert
	}

	if rawBundle != nil {
		gzipBundle := k8smnfutil.GzipCompress(rawBundle)
		base64Bundle := []byte(base64.StdEncoding.EncodeToString(gzipBundle))
		m["bundle"] = base64Bundle
	}

	return m, nil
}

func GetRekorServerURL() string {
	url := os.Getenv(rekorServerEnvKey)
	if url == "" {
		url = defaultRekorServerURL
	}
	return url
}
