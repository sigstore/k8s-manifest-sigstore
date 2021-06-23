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

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"

	"github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/k8smanifest"
	k8smnfutil "github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util"
	"github.com/yuji-watanabe-jp/k8s-manifest-sigstore/pkg/util/kubeutil"
	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

const configKeyInConfigMap = "config.yaml"

type ManifestIntegrityConfig struct {
	k8smanifest.VerifyOption `json:""`
	InScopeObjects           k8smanifest.ObjectReferenceList `json:"inScopeObjects,omitempty"`
	SkipUsers                ObjectUserBindingList           `json:"skipUsers,omitempty"`
	KeySecertName            string                          `json:"keySecretName,omitempty"`
	KeySecertNamespace       string                          `json:"keySecretNamespace,omitempty"`
	ImageRef                 string                          `json:"imageRef,omitempty"`
}

type ObjectUserBindingList []ObjectUserBinding

type ObjectUserBinding struct {
	Objects k8smanifest.ObjectReferenceList `json:"objects,omitempty"`
	Users   []string                        `json:"users,omitempty"`
}

func (l ObjectUserBindingList) Match(obj unstructured.Unstructured, username string) bool {
	if len(l) == 0 {
		return false
	}
	for _, u := range l {
		if u.Match(obj, username) {
			return true
		}
	}
	return false
}

func (u ObjectUserBinding) Match(obj unstructured.Unstructured, username string) bool {
	if u.Objects.Match(obj) {
		if k8smnfutil.MatchWithPatternArray(username, u.Users) {
			return true
		}
	}
	return false
}

func LoadConfig(namespace, name string) (*ManifestIntegrityConfig, error) {
	obj, err := kubeutil.GetResource("v1", "ConfigMap", namespace, name)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, errors.Wrap(err, fmt.Sprintf("failed to get a configmap `%s` in `%s` namespace", name, namespace))
	}
	objBytes, _ := json.Marshal(obj.Object)
	var cm v1.ConfigMap
	_ = json.Unmarshal(objBytes, &cm)
	cfgBytes, found := cm.Data[configKeyInConfigMap]
	if !found {
		return nil, errors.New(fmt.Sprintf("`%s` is not found in configmap", configKeyInConfigMap))
	}
	var conf *ManifestIntegrityConfig
	err = yaml.Unmarshal([]byte(cfgBytes), &conf)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("failed to unmarshal config.yaml into %T", conf))
	}
	return conf, nil
}

func (c *ManifestIntegrityConfig) LoadKeySecret() (string, error) {
	obj, err := kubeutil.GetResource("v1", "Secret", c.KeySecertNamespace, c.KeySecertName)
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("failed to get a secret `%s` in `%s` namespace", c.KeySecertName, c.KeySecertNamespace))
	}
	objBytes, _ := json.Marshal(obj.Object)
	var secret v1.Secret
	_ = json.Unmarshal(objBytes, &secret)
	keyDir := fmt.Sprintf("/tmp/%s/%s/", c.KeySecertNamespace, c.KeySecertName)
	sumErr := []string{}
	keyPath := ""
	for fname, keyData := range secret.Data {
		fpath := filepath.Join(keyDir, fname)
		err := ioutil.WriteFile(fpath, keyData, 0644)
		if err != nil {
			sumErr = append(sumErr, err.Error())
			continue
		}
		keyPath = fpath
		break
	}
	if keyPath == "" && len(sumErr) > 0 {
		return "", errors.New(fmt.Sprintf("failed to save secret data as a file; %s", strings.Join(sumErr, "; ")))
	}
	if keyPath == "" {
		return "", errors.New(fmt.Sprintf("no key files are found in the secret `%s` in `%s` namespace", c.KeySecertName, c.KeySecertNamespace))
	}

	return keyPath, nil
}
