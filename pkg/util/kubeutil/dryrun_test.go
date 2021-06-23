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
	"path/filepath"
	"testing"

	"github.com/ghodss/yaml"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var k8sClient client.Client
var testEnv *envtest.Environment
var schemes *runtime.Scheme

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func(done Done) {
	logf.SetLogger(zap.New())

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "config", "crd", "bases")},
	}

	var err error
	cfg, err := testEnv.Start()
	Expect(err).ToNot(HaveOccurred())
	Expect(cfg).ToNot(BeNil())

	schemes = runtime.NewScheme()
	err = clientgoscheme.AddToScheme(schemes)

	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	SetKubeConfig(cfg)

	k8sClient, err = client.New(cfg, client.Options{Scheme: schemes})
	Expect(err).ToNot(HaveOccurred())
	Expect(k8sClient).ToNot(BeNil())

	close(done)
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())
})

var _ = Describe("Test Kubeutil Functions", func() {
	It("DryRunCreate Test", func() {
		var timeout int = 10
		Eventually(func() error {
			testObj, err := ioutil.ReadFile("testdata/sample_configmap.yaml")
			if err != nil {
				return err
			}
			_, err = DryRunCreate(testObj, "default")
			if err != nil {
				return err
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("StrategicMergePatch Test", func() {
		var timeout int = 10
		Eventually(func() error {
			testObj, err := ioutil.ReadFile("testdata/sample_configmap.yaml")
			if err != nil {
				return err
			}
			testJsonBytes, err := yaml.YAMLToJSON(testObj)
			if err != nil {
				return err
			}
			testObjOrg, err := ioutil.ReadFile("testdata/sample_configmap_after.yaml")
			if err != nil {
				return err
			}
			_, err = StrategicMergePatch(testJsonBytes, testObjOrg, "default")
			if err != nil {
				return err
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("GetApplyPatchBytes Test", func() {
		var timeout int = 20
		Eventually(func() error {
			testObj, err := ioutil.ReadFile("testdata/sample_configmap_after.yaml")
			if err != nil {
				return err
			}
			_, _, err = GetApplyPatchBytes(testObj, "default")
			if err != nil {
				return err
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
})
