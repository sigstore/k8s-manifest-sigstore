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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	cligen "github.com/sigstore/cosign/v2/cmd/cosign/cli/generate"
	cliopt "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	clisign "github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	fulcioapi "github.com/sigstore/fulcio/pkg/api"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"
	rekorgenclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	log "github.com/sirupsen/logrus"
	"github.com/transparency-dev/merkle/rfc6962"
)

const (
	rekorServerEnvKey        = "REKOR_SERVER"
	defaultRekorServerURL    = "https://rekor.sigstore.dev"
	defaultOIDCIssuer        = "https://oauth2.sigstore.dev/auth"
	defaultOIDCClientID      = "sigstore"
	cosignPasswordEnvKey     = "COSIGN_PASSWORD"
	defaultTlogUploadTimeout = 90 // set to 90s for keyless as cosign recommends it in the help message
)

const treeIDHexStringLen = 16
const uuidHexStringLen = 64
const entryIDHexStringLen = treeIDHexStringLen + uuidHexStringLen

func SignImage(resBundleRef string, keyPath, certPath *string, rekorURL string, tlogUpload, force bool, pf cosign.PassFunc, imageAnnotations map[string]interface{}, allowInsecure bool) error {

	var rekorSeverURL string
	if rekorURL == "" {
		rekorSeverURL = GetRekorServerURL()
	} else {
		rekorSeverURL = rekorURL
	}
	fulcioServerURL := fulcioapi.SigstorePublicServerURL

	rootOpt := &cliopt.RootOptions{Timeout: defaultTlogUploadTimeout * time.Second}
	opt := cliopt.KeyOpts{
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

	imageAnnotationList := []string{}
	for k, v := range imageAnnotations {
		kv := fmt.Sprintf("%s=%v", k, v)
		imageAnnotationList = append(imageAnnotationList, kv)
	}

	signOpt := cliopt.SignOptions{
		TlogUpload: tlogUpload,
		Upload:     true,
		Rekor: cliopt.RekorOptions{
			URL: rekorSeverURL,
		},
		Fulcio: cliopt.FulcioOptions{
			URL: fulcioServerURL,
		},
		OIDC: cliopt.OIDCOptions{
			Issuer:   defaultOIDCIssuer,
			ClientID: defaultOIDCClientID,
		},
		AnnotationOptions: cliopt.AnnotationOptions{
			Annotations: imageAnnotationList,
		},
	}

	regOpt := cliopt.RegistryOptions{}
	if allowInsecure {
		regOpt.AllowInsecure = true
	}
	signOpt.Registry = regOpt

	if certPath != nil {
		signOpt.Cert = *certPath
	}

	if keyPath != nil {
		opt.KeyRef = *keyPath
		signOpt.Key = *keyPath
	}

	if force {
		opt.SkipConfirmation = true
	}

	return clisign.SignCmd(rootOpt, opt, signOpt, []string{resBundleRef})
}

func SignBlob(blobPath string, keyPath, certPath *string, rekorURL string, tlogUpload, force bool, pf cosign.PassFunc) (map[string][]byte, error) {
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

	if force {
		opt.SkipConfirmation = true
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

	m := map[string][]byte{}
	rawMsg, err := os.ReadFile(blobPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load a file to be signed")
	}
	gzipMsg := k8smnfutil.GzipCompress(rawMsg)
	base64Msg := []byte(base64.StdEncoding.EncodeToString(gzipMsg))
	m["message"] = base64Msg

	timeout := defaultTlogUploadTimeout
	rootOpt := &cliopt.RootOptions{Timeout: time.Duration(timeout) * time.Second}
	outputSignaturePath := ""
	outputCertificatePath := ""
	rawSig, err := clisign.SignBlobCmd(rootOpt, opt, blobPath, false, outputSignaturePath, outputCertificatePath, tlogUpload)
	if err != nil {
		return nil, errors.Wrap(err, "cosign.SignBlobCmd() returned an error")
	}

	b64Sig := []byte(base64.StdEncoding.EncodeToString(rawSig))
	m["signature"] = b64Sig

	var rawCert []byte
	var rawBundle []byte

	// cosign.SignBlobCmd() does not return a rekor entry bundle as of v2.0.2, so find it here
	if tlogUpload && certPath == nil {
		rClient, err := rekorclient.GetRekorClient(opt.RekorURL)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get rekor client")
		}
		blobBytes := rawMsg
		// uuids, err := cosign.FindTLogEntriesByPayload(context.Background(), rClient, blobBytes)
		uuids, err := FindTLogEntriesByPayload(context.Background(), rClient, blobBytes)
		if err != nil {
			return nil, errors.Wrap(err, "failed to find tlog entry")
		}
		if len(uuids) == 0 {
			return nil, errors.New("could not find a tlog entry for provided blob")
		}
		// tlogEntry, err := cosign.GetTlogEntry(context.Background(), rClient, uuids[0])
		tlogEntry, err := GetTlogEntry(context.Background(), rClient, uuids[0])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to find transparency log entry with uuid %s", uuids[0])
		}
		bundleObj := &bundle.RekorBundle{
			SignedEntryTimestamp: tlogEntry.Verification.SignedEntryTimestamp,
			Payload: bundle.RekorPayload{
				Body:           tlogEntry.Body,
				IntegratedTime: *tlogEntry.IntegratedTime,
				LogIndex:       *tlogEntry.LogIndex,
				LogID:          *tlogEntry.LogID,
			},
		}
		rawBundle, err = json.Marshal(bundleObj)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to create a bundle from a tlog entry with uuid %s", uuids[0])
		}

		var rekord *models.Hashedrekord
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

		var rekordContent *models.HashedrekordV001Schema
		err = json.Unmarshal(rekordSpecBytes, &rekordContent)
		if err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal rekord.Spec into *models.HashedrekordV001Schema")
		}

		var b64CertStr string
		if rekordContent != nil {
			// this will be a certificate in keyless signing, and be a public key in keyed signing
			// and if this is a public key, we don't add it to the annotations
			b64CertStr = rekordContent.Signature.PublicKey.Content.String()
		}
		tmpRawCert, err := base64.StdEncoding.DecodeString(b64CertStr)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode certificate string %s", b64CertStr)
		}
		// rawCert is available only when the value is an actual certificate
		if _, err = loadCertificate(tmpRawCert); err == nil {
			rawCert = tmpRawCert
		}
	} else if certPath != nil {
		certPathStr := *certPath
		certPem, err := os.ReadFile(certPathStr)
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

// cosign has a bug in GetTlogEntry() function as of v1.12.1, so use this instead here
func GetTlogEntry(ctx context.Context, rekorClient *rekorgenclient.Rekor, uuid string) (*models.LogEntryAnon, error) {
	params := entries.NewGetLogEntryByUUIDParamsWithContext(ctx)
	params.SetEntryUUID(uuid)
	resp, err := rekorClient.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}
	for k, e := range resp.Payload {
		if err := verifyUUID(k, e); err != nil {
			return nil, err
		}
		return &e, nil
	}
	return nil, errors.New("empty response")
}

// FindTLogEntriesByPayload is removed in cosign v2.x, so we implement it here
func FindTLogEntriesByPayload(ctx context.Context, rekorClient *client.Rekor, payload []byte) (uuids []string, err error) {
	params := index.NewSearchIndexParamsWithContext(ctx)
	params.Query = &models.SearchIndex{}

	h := sha256.New()
	h.Write(payload)
	params.Query.Hash = fmt.Sprintf("sha256:%s", strings.ToLower(hex.EncodeToString(h.Sum(nil))))

	searchIndex, err := rekorClient.Index.SearchIndex(params)
	if err != nil {
		return nil, err
	}
	return searchIndex.GetPayload(), nil
}

func ComputeLeafHash(e *models.LogEntryAnon) ([]byte, error) {
	entryBytes, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}
	return rfc6962.DefaultHasher.HashLeaf(entryBytes), nil
}

func getUUID(entryUUID string) (string, error) {
	switch len(entryUUID) {
	case uuidHexStringLen:
		if _, err := hex.DecodeString(entryUUID); err != nil {
			return "", fmt.Errorf("uuid %v is not a valid hex string: %w", entryUUID, err)
		}
		return entryUUID, nil
	case entryIDHexStringLen:
		uid := entryUUID[len(entryUUID)-uuidHexStringLen:]
		return getUUID(uid)
	default:
		return "", fmt.Errorf("invalid ID len %v for %v", len(entryUUID), entryUUID)
	}
}

func verifyUUID(entryUUID string, e models.LogEntryAnon) error {
	// Verify and get the UUID.
	uid, err := getUUID(entryUUID)
	if err != nil {
		return err
	}
	uuid, _ := hex.DecodeString(uid)

	// Verify leaf hash matches hash of the entry body.
	computedLeafHash, err := ComputeLeafHash(&e)
	if err != nil {
		return err
	}
	if !bytes.Equal(computedLeafHash, uuid) {
		return fmt.Errorf("computed leaf hash did not match UUID")
	}
	return nil
}
