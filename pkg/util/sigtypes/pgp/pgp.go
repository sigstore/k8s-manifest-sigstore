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
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/openpgp"
)

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
	signer, err := openpgp.CheckArmoredDetachedSignature(keyRing, msgReader, sigReader)
	if signer == nil {
		if err != nil {
			return false, "", nil, errors.Wrap(err, "failed to verify signature")
		}
		return false, "", nil, nil
	} else {
		identity := GetFirstIdentity(signer)
		signerName := identity.UserId.Email
		return true, signerName, nil, nil
	}
}

// Load public key at `keyPath`.
// Both armored and non-armored ones are supported.
func LoadPublicKey(keyPath string) (openpgp.EntityList, error) {
	entities := []*openpgp.Entity{}
	var retErr error
	kpath := filepath.Clean(keyPath)
	if keyRingReader, err := os.Open(kpath); err != nil {
		retErr = err
	} else {
		var tmpList openpgp.EntityList
		var err1, err2 error
		tmpList, err1 = openpgp.ReadKeyRing(keyRingReader)
		if err1 != nil {
			tmpList, err2 = openpgp.ReadArmoredKeyRing(keyRingReader)
		}
		if err1 != nil && err2 != nil {
			retErr = fmt.Errorf("failed to load public key; %s; %s", err1.Error(), err2.Error())
		} else if len(tmpList) > 0 {
			for _, tmp := range tmpList {
				entities = append(entities, tmp)
			}
		}
	}
	return openpgp.EntityList(entities), retErr
}

func GetFirstIdentity(signer *openpgp.Entity) *openpgp.Identity {
	for _, idt := range signer.Identities {
		return idt
	}
	return nil
}
