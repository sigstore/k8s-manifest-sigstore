//
// Copyright 2022 The Sigstore Authors.
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

package k8smanifest

import (
	"github.com/pkg/errors"
)

type K8sManifestError struct {
	error
	defaultMessage string
}

func (e *K8sManifestError) Error() string {
	if e.error == nil {
		return e.defaultMessage
	} else {
		return e.error.Error()
	}
}

type SignatureNotFoundError struct {
	*K8sManifestError
}

type MessageNotFoundError struct {
	*K8sManifestError
}

type SignatureVerificationError struct {
	*K8sManifestError
}

func NewSignatureNotFoundError(err error) *SignatureNotFoundError {
	return &SignatureNotFoundError{
		K8sManifestError: &K8sManifestError{
			error:          err,
			defaultMessage: "signature not found",
		},
	}
}

func NewMessageNotFoundError(err error) *MessageNotFoundError {
	return &MessageNotFoundError{
		K8sManifestError: &K8sManifestError{
			error:          err,
			defaultMessage: "message not found",
		},
	}
}

func NewSignatureVerificationError(err error) *SignatureVerificationError {
	return &SignatureVerificationError{
		K8sManifestError: &K8sManifestError{
			error:          err,
			defaultMessage: "signature verification error",
		},
	}
}

// errors.As checks if there is at least one error which matches the target in the error chain
// this works even if the input error is wraped like `errors.Wrap(SignatureNotFoundError, "wapper error")`.
func IsSignatureNotFoundError(err error) bool {
	var target *SignatureNotFoundError
	return errors.As(err, &target)
}

func IsMessageNotFoundError(err error) bool {
	var target *MessageNotFoundError
	return errors.As(err, &target)
}

func IsSignatureVerificationError(err error) bool {
	var target *SignatureVerificationError
	return errors.As(err, &target)
}
