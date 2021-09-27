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

package main

import (
	"os"
	"runtime/debug"

	"github.com/sigstore/k8s-manifest-sigstore/cmd/kubectl-sigstore/cli"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util"
)

func init() {
	// util.GitVersion is automatically set by `make build` command usually.
	// However, it will be a default value "develop" in case of `go install`,
	// so get values by debug.ReadBuildInfo() here.
	if util.GitVersion == "develop" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			util.GitVersion = bi.Main.Version
		}
	}
}

func main() {
	if err := cli.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
