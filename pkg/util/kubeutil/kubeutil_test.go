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

package kubeutil

import (
	"io/ioutil"
	"testing"

	"github.com/ghodss/yaml"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func TestKubeConfig(t *testing.T) {
	var err error
	var config *rest.Config
	config, err = GetInClusterConfig()
	t.Log("GetInClusterConfig(); ", err)

	// config, err = GetOutOfClusterConfig()
	// t.Log("GetOutOfClusterConfig(); ", err)

	config, err = GetKubeConfig()
	t.Log("GetKubeConfig(); ", err)

	SetKubeConfig(config)
}

func TestMatchLabels(t *testing.T) {
	testCmBytes, err := ioutil.ReadFile("testdata/sample_configmap.yaml")
	if err != nil {
		t.Error(err)
	}
	var cm *v1.ConfigMap
	err = yaml.Unmarshal(testCmBytes, &cm)
	if err != nil {
		t.Error(err)
	}
	testLabelMap := map[string]string{"testLabel": "testKey"}
	cm.SetLabels(testLabelMap)

	labelSelector := &metav1.LabelSelector{MatchLabels: testLabelMap}

	ok, err := MatchLabels(cm, labelSelector)
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Error("TestMatchLabels failed; label should be matched with the test object")
	}
}
