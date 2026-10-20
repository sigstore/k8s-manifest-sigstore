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

package kustomize

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The key path comes from the --key flag, so a path that is missing or is not
// PEM has to be reported rather than dereferenced.
func TestGenerateAttestationBadKey(t *testing.T) {
	dir := t.TempDir()

	provPath := filepath.Join(dir, "prov.json")
	if err := os.WriteFile(provPath, []byte(`{"_type":"https://in-toto.io/Statement/v0.1"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	notPEMPath := filepath.Join(dir, "not-a-key.pem")
	if err := os.WriteFile(notPEMPath, []byte("this is not a PEM file"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name    string
		keyPath string
		wantErr string
	}{
		{
			name:    "missing key file",
			keyPath: filepath.Join(dir, "does-not-exist.pem"),
			wantErr: "no such file or directory",
		},
		{
			name:    "key file is not PEM",
			keyPath: notPEMPath,
			wantErr: "failed to decode PEM private key",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env, err := GenerateAttestation(provPath, tt.keyPath)
			if err == nil {
				t.Fatalf("expected an error, got envelope %v", env)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}
