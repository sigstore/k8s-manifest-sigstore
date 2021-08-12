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

package x509

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/pkg/errors"

	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
)

const (
	PEMTypePrivateKey  string = "RSA PRIVATE KEY"
	PEMTypePublicKey   string = "PUBLIC KEY"
	PEMTypeCertificate string = "CERTIFICATE"
)

// Verify certificate with CA cert, then verify signature
func VerifyBlob(msgBytes, sigBytes, certBytes []byte, caCertPathString *string) (bool, string, *int64, error) {
	caCertPath := *(caCertPathString)

	// verify certificate
	gzipCert, _ := base64.StdEncoding.DecodeString(string(certBytes))
	rawCertPem := k8smnfutil.GzipDecompress(gzipCert)
	log.Debug("verifying this certificate: ", string(rawCertPem))
	rawCertBytes := PEMDecode(rawCertPem, PEMTypeCertificate)
	cert, err := x509.ParseCertificate(rawCertBytes)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "failed to load certificate")
	}

	roots := x509.NewCertPool()
	caCert, err := LoadCertificate(caCertPath)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "failed to load CA certificate")
	}
	if !caCert.Equal(cert) || isSelfSignedCert(cert) {
		roots.AddCert(caCert)
	}

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	_, err = cert.Verify(opts)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "failed to verify certificate")
	}

	// verify signature
	pubKeyBytes, err := GetPublicKeyFromCertificate(rawCertPem)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "failed to get public key from certificate")
	}
	gzipMsg, _ := base64.StdEncoding.DecodeString(string(msgBytes))
	rawMsg := k8smnfutil.GzipDecompress(gzipMsg)
	rawSig, _ := base64.StdEncoding.DecodeString(string(sigBytes))
	log.Debug("verifying this message: ", string(rawMsg))
	log.Debug("verifying this signature (base64): ", string(sigBytes))

	h := crypto.Hash.New(crypto.SHA256)
	_, _ = h.Write([]byte(rawMsg))
	msgHash := h.Sum(nil)
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "failed to parse public key")
	}
	err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, msgHash, rawSig)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "failed to verify signature")
	}
	signerName := ""
	if len(cert.EmailAddresses) > 0 {
		signerName = cert.EmailAddresses[0]
	}
	return true, signerName, nil, nil
}

// Load certificate at `certPath`
func LoadCertificate(certPath string) (*x509.Certificate, error) {
	cpath := filepath.Clean(certPath)
	certPemBytes, err := ioutil.ReadFile(cpath)
	if err != nil {
		return nil, fmt.Errorf("failed to load public key; %s", err.Error())
	}
	certBytes := PEMDecode(certPemBytes, PEMTypeCertificate)
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// Decode PEM bytes of x509 private key / public key / certificate
func PEMDecode(pemBytes []byte, mode string) []byte {
	if mode != PEMTypePrivateKey && mode != PEMTypePublicKey && mode != PEMTypeCertificate {
		return nil
	}
	p, _ := pem.Decode(pemBytes)
	if p == nil {
		return nil
	}
	return p.Bytes
}

// extract public key of certificate
func GetPublicKeyFromCertificate(certPemBytes []byte) ([]byte, error) {
	certBytes := PEMDecode(certPemBytes, PEMTypeCertificate)
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	return pubKeyBytes, nil
}

// whether the certificate is self signed or not
func isSelfSignedCert(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer)
}
