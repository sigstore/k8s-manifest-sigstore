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

package pgp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	// package golang.org/x/crypto/openpgp is deprecated: this package is unmaintained except for security fixes.
	// New applications should consider a more focused, modern alternative to OpenPGP for their specific task.
	// If you are required to interoperate with OpenPGP systems and need a maintained package, consider a community fork.
	// See https://golang.org/issue/44226.
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/pkg/errors"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
)

// Verify `sigBytes` and `msgBytes` with public key at `pubkeyPathString`.
func VerifyBlob(msgBytes, sigBytes []byte, pubkeyPathString *string) (bool, string, *int64, error) {
	keyPath := *(pubkeyPathString)
	keyRing, err := LoadPublicKey(keyPath)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "failed to load public key")
	}

	for _, entity := range keyRing {
		log.Debug("PGP keyring entities: ", entity.Identities)
	}

	gzipMsg, _ := base64.StdEncoding.DecodeString(string(msgBytes))
	rawMsg := k8smnfutil.GzipDecompress(gzipMsg)
	rawSig, _ := base64.StdEncoding.DecodeString(string(sigBytes))
	log.Debug("verifying this message: ", string(rawMsg))
	log.Debug("verifying this signature (base64): ", string(sigBytes))

	msgReader := bytes.NewReader(rawMsg)
	sigReader := bytes.NewReader(rawSig)
	signer, err := openpgp.CheckArmoredDetachedSignature(keyRing, msgReader, sigReader, nil)
	if signer == nil {
		if err != nil {
			return false, "", nil, errors.Wrap(err, "failed to verify signature")
		}
		return false, "", nil, nil
	} else {
		identity := GetFirstIdentity(signer)
		signerName := identity.UserId.Email
		log.Debugf("signature is verified successfully. signerName is %s", signerName)
		return true, signerName, nil, nil
	}
}

// Load public key at `keyPath`.
// Specifying a public key secret with `k8s://` prefix is supported.
// Both armored and non-armored ones are supported.
func LoadPublicKey(keyPath string) (openpgp.EntityList, error) {
	var keyRingReader io.Reader
	var err error

	if strings.HasPrefix(keyPath, kubeutil.InClusterObjectPrefix) {
		ns, name, err := kubeutil.ParseObjectRefInCluster(keyPath)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to parse secret keyRef `%s`", keyPath))
		}
		secret, err := kubeutil.GetSecret(ns, name)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load a kubernetes secret")
		}
		for _, val := range secret.Data {
			if val != nil {
				keyRingReader = bytes.NewBuffer(val)
				break
			}
		}
	} else {
		kpath := filepath.Clean(keyPath)
		keyRingReader, err = os.Open(kpath)
		if err != nil {
			return nil, errors.Wrap(err, "failed to open a public key")
		}
	}
	if keyRingReader == nil {
		return nil, errors.New("failed to get a keyRingReader")
	}

	entities := []*openpgp.Entity{}
	var tmpList openpgp.EntityList
	var err1, err2 error
	tmpList, err1 = openpgp.ReadKeyRing(keyRingReader)
	if err1 != nil {
		tmpList, err2 = openpgp.ReadArmoredKeyRing(keyRingReader)
	}
	if err1 != nil && err2 != nil {
		err = fmt.Errorf("failed to load public key; %s; %s", err1.Error(), err2.Error())
	} else if len(tmpList) > 0 {
		for _, tmp := range tmpList {
			entities = append(entities, tmp)
		}
	}
	if len(entities) == 0 {
		return nil, errors.New("no public key was found while reading a keyring")
	}
	return openpgp.EntityList(entities), err
}

func GetFirstIdentity(signer *openpgp.Entity) *openpgp.Identity {
	for _, idt := range signer.Identities {
		return idt
	}
	return nil
}
