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

package cli

import (
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghodss/yaml"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	kubeutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	k8serr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	// +kubebuilder:scaffold:imports
)

//
// before doing test with envtest, need to install binaries for it.
// "Envtest Binaries Manager" is a recommended way to manage these binaries.
// https://github.com/kubernetes-sigs/controller-runtime/tree/master/tools/setup-envtest
//

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var testTempDir string
var cfg *rest.Config
var k8sClient client.Client
var testEnv *envtest.Environment
var schemes *runtime.Scheme

//go:embed testdata/testpub
var b64EncodedTestPubKey []byte

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
}

func createTestResource(fname string, namespace string) error {
	var obj *unstructured.Unstructured
	var err error

	objBytes, err := os.ReadFile(fname)
	if err != nil {
		return errors.Wrap(err, "failed to read a testdata file")
	}

	err = yaml.Unmarshal(objBytes, &obj)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal")
	}

	apiResources, err := kubeutil.GetAPIResources()
	if err != nil {
		return errors.Wrap(err, "failed to get api resources")
	}

	gvStr := obj.GetAPIVersion()
	kindStr := obj.GetKind()

	gv, err := schema.ParseGroupVersion(gvStr)
	if err != nil {
		return errors.Wrap(err, "failed to parse group version")
	}
	var gvr schema.GroupVersionResource
	var namespaced bool
	for _, ar := range apiResources {
		gOk := ar.Group == gv.Group
		vOk := ar.Version == gv.Version
		kOk := ar.Kind == kindStr
		if gOk && vOk && kOk {
			gvr = schema.GroupVersionResource{
				Group:    ar.Group,
				Version:  ar.Version,
				Resource: ar.Name,
			}
			namespaced = ar.Namespaced
			break
		}
	}
	if gvr.Resource == "" {
		return errors.New("failed to find group version resource")
	}

	dyClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return errors.Wrap(err, "failed to create dynamic client")
	}

	if namespaced {
		_, err = dyClient.Resource(gvr).Namespace(namespace).Create(context.Background(), obj, metav1.CreateOptions{})
	} else {
		_, err = dyClient.Resource(gvr).Create(context.Background(), obj, metav1.CreateOptions{})
	}
	if err != nil {
		if !k8serr.IsAlreadyExists(err) {
			return errors.Wrap(err, "failed to create a resource")
		}
	}
	return nil
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New())

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).ToNot(HaveOccurred())
	Expect(cfg).ToNot(BeNil())

	testUser, err := testEnv.ControlPlane.AddUser(envtest.User{
		Name:   "envtest-admin",
		Groups: []string{"system:masters"},
	}, nil)
	Expect(err).ToNot(HaveOccurred())

	schemes = runtime.NewScheme()
	err = clientgoscheme.AddToScheme(schemes)

	Expect(err).NotTo(HaveOccurred())

	// +kubebuilder:scaffold:scheme

	kubeutil.SetKubeConfig(cfg)

	testTempDir, err = os.MkdirTemp("", "verify-resource-test")
	Expect(err).NotTo(HaveOccurred())

	kubeconfigBytes, err := testUser.KubeConfig()
	Expect(err).NotTo(HaveOccurred())
	fmt.Println(err)
	Expect(err).NotTo(HaveOccurred())
	kubeconfigPath := filepath.Join(testTempDir, "kubeconfig")
	err = os.WriteFile(kubeconfigPath, kubeconfigBytes, 0644)
	Expect(err).NotTo(HaveOccurred())

	KOptions.SetKubeConfig(kubeconfigPath, "default")

	k8sClient, err = client.New(cfg, client.Options{Scheme: schemes})
	Expect(err).ToNot(HaveOccurred())
	Expect(k8sClient).ToNot(BeNil())

	cmd := NewCmdVerifyResource()
	err = KOptions.InitGet(cmd)
	Expect(err).ToNot(HaveOccurred())

	testpubBytes, err := base64.StdEncoding.DecodeString(string(b64EncodedTestPubKey))
	Expect(err).ToNot(HaveOccurred())
	err = os.WriteFile(filepath.Join(testTempDir, "testpub"), testpubBytes, 0644)
	Expect(err).ToNot(HaveOccurred())

}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())

	fmt.Println("testTempDir: ", testTempDir)
	// err = os.RemoveAll(testTempDir)
	// Expect(err).ToNot(HaveOccurred())
})

var _ = Describe("Test Kubeutil Sigstore Functions", func() {
	It("VerifyResource Test (No Signature)", func() {
		var timeout int = 10
		Eventually(func() error {
			var err error
			err = createTestResource("testdata/sample-configmap.yaml", "default")
			if err != nil {
				return err
			}

			verified, err := verifyResource(nil, []string{"cm", "sample-cm"}, "", "", "", "", "", "", false, false, false, "", "", "", "", "", "", 4)
			if err != nil {
				return err
			}
			if verified {
				return errors.New("result should not be verified")
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("VerifyResource Test (Valid Signature)", func() {
		var timeout int = 10
		Eventually(func() error {
			var err error
			err = createTestResource("testdata/sample-configmap-signed.yaml", "default")
			if err != nil {
				return err
			}

			pubkeyPath := filepath.Join(testTempDir, "testpub")
			verified, err := verifyResource(nil, []string{"cm", "sample-cm-signed"}, "", "", pubkeyPath, "", "", "", false, false, false, "", "", "", "", "", "json", 4)
			if err != nil {
				return err
			}
			if !verified {
				return errors.New("result should be verified")
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
})
