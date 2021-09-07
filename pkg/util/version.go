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

package util

import (
	"fmt"
	"runtime"
	"strings"
)

var (
	gitVersion   = "develop" // major and minor version are obtained by parsing this (e.g. v1.2.3 -> major: 1, minor: 2)
	gitCommit    = "unknown"
	gitTreeState = "unknown"
	buildDate    = "unknown" // Build date in ISO8601 format by doing $(date -u +'%Y-%m-%dT%H:%M:%SZ')
)

type VersionInfo struct {
	Major        string `json:"Major"`
	Minor        string `json:"Minor"`
	GitVersion   string `json:"GitVersion"`
	GitCommit    string `json:"GitCommit"`
	GitTreeState string `json:"GitTreeState"`
	BuildDate    string `json:"BuildDate"`
	GoVersion    string `json:"GoVersion"`
	Compiler     string `json:"Compiler"`
	Platform     string `json:"Platform"`
}

func GetVersionInfo() *VersionInfo {
	gitMajor, gitMinor := parseGitVersion(gitVersion)
	return &VersionInfo{
		Major:        gitMajor,
		Minor:        gitMinor,
		GitVersion:   gitVersion,
		GitCommit:    gitCommit,
		GitTreeState: gitTreeState,
		BuildDate:    buildDate,
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

func parseGitVersion(gv string) (string, string) {
	major := ""
	minor := ""
	if !strings.HasPrefix(gv, "v") {
		return major, minor
	}
	tmp := strings.TrimPrefix(gv, "v")
	parts := strings.Split(tmp, ".")
	if len(parts) == 1 {
		major = parts[0]
	} else if len(parts) >= 2 {
		major = parts[0]
		minor = parts[1]
	}
	return major, minor
}
