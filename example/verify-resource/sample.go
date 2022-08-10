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

package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/ghodss/yaml"
	"github.com/pkg/errors"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	sampleCMYAMLPath = "./sample-configmap.yaml.signed"
	sampleNS         = "sample-ns"
	sampleCMName     = "sample-cm"
	pubkeyPath       = "./cosign.pub"
)

type sandboxKubernetesCluster struct {
	Clientset *fake.Clientset
}

func main() {

	sandboxCluster := sandboxKubernetesCluster{}
	err := sandboxCluster.initClientset()
	if err != nil {
		log.Fatalf("failed to initialize a sandbox cluster; %s", err.Error())
	}

	opt := &k8smanifest.VerifyResourceOption{}

	// With this example config, k8s-manifest-sigstore will ignore 2 fields "metadata.labels.autoEmbeddedLabel"
	// and "data.changable" inside ConfigMaps in "sample-ns" namespace while VerifyResource().
	opt.IgnoreFields = []k8smanifest.ObjectFieldBinding{
		{
			Objects: k8smanifest.ObjectReferenceList([]k8smanifest.ObjectReference{
				{
					Kind:      "ConfigMap",
					Namespace: sampleNS,
				},
			}),
			Fields: []string{
				"metadata.labels.autoEmbeddedLabel",
				"data.changable",
			},
		},
	}
	opt.KeyPath = pubkeyPath
	opt = k8smanifest.AddDefaultConfig(opt)

	obj, err := sandboxCluster.getTargetResource()
	if err != nil {
		log.Fatalf("failed to get the resource; %s", err.Error())
	}

	result, err := k8smanifest.VerifyResource(obj, opt)
	if err != nil {
		log.Fatalf("error occurred while verifying the configmap; %s", err.Error())
	}

	resultBytes, _ := json.Marshal(result)
	if result.Verified {
		log.Infof("verification OK: %s", string(resultBytes))
	} else {
		log.Errorf("verification failed: %s", string(resultBytes))
	}
}

func (c *sandboxKubernetesCluster) initClientset() error {
	cmBytes, err := os.ReadFile(sampleCMYAMLPath)
	if err != nil {
		return err
	}
	var cm *corev1.ConfigMap
	_ = yaml.Unmarshal(cmBytes, &cm)
	c.Clientset = fake.NewSimpleClientset(cm)
	return nil
}

func (c *sandboxKubernetesCluster) getTargetResource() (unstructured.Unstructured, error) {
	cm, err := c.Clientset.CoreV1().ConfigMaps(sampleNS).Get(context.Background(), sampleCMName, metav1.GetOptions{})
	if err != nil {
		return unstructured.Unstructured{}, errors.Wrap(err, "failed to get the sample configmap")
	}

	// corev1 clientset possibly returns an object with empty TypeMeta, so embed it manually as a workaround
	if cm.TypeMeta.Kind == "" {
		cm.TypeMeta = metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		}
	}
	var obj unstructured.Unstructured
	cmBytes, _ := yaml.Marshal(cm)
	_ = yaml.Unmarshal(cmBytes, &obj)
	return obj, nil
}
