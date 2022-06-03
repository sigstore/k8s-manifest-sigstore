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

//go:build e2e_test
// +build e2e_test

package test

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/k8s-manifest-sigstore/cmd/kubectl-sigstore/cli"

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

const cosignExperimentalEnv = "COSIGN_EXPERIMENTAL"

var testTempDir string
var inPath, outPath, inExpPath, outExpPath, keyPath, pubkeyPath string
var cfg *rest.Config
var k8sClient client.Client
var testEnv *envtest.Environment
var schemes *runtime.Scheme
var exitCode int

//go:embed testdata/testkey
var b64EncodedTestKey []byte

//go:embed testdata/testpub
var b64EncodedTestPubKey []byte

func TestWithEnvtest(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
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

	testTempDir, err = ioutil.TempDir("", "k8s-manifest-sigstore-e2e-test")
	Expect(err).NotTo(HaveOccurred())

	kubeconfigBytes, err := testUser.KubeConfig()
	Expect(err).NotTo(HaveOccurred())
	fmt.Println(err)
	Expect(err).NotTo(HaveOccurred())
	kubeconfigPath := filepath.Join(testTempDir, "kubeconfig")
	err = ioutil.WriteFile(kubeconfigPath, kubeconfigBytes, 0644)
	Expect(err).NotTo(HaveOccurred())

	cli.KOptions.SetKubeConfig(kubeconfigPath, "default")

	k8sClient, err = client.New(cfg, client.Options{Scheme: schemes})
	Expect(err).ToNot(HaveOccurred())
	Expect(k8sClient).ToNot(BeNil())

	inPath = filepath.Join("testdata", "sample-configmap.yaml")
	outPath = filepath.Join(testTempDir, "signed-configmap.yaml")
	inExpPath = filepath.Join("testdata", "sample-configmap-exp.yaml")
	outExpPath = filepath.Join(testTempDir, "signed-configmap-exp.yaml")
	keyPath = filepath.Join(testTempDir, "testkey")
	pubkeyPath = filepath.Join(testTempDir, "testpub")

	err = setup(keyPath, pubkeyPath)
	Expect(err).ToNot(HaveOccurred())

	cli.OSExit = func(code int) {
		exitCode = code
	}

}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).ToNot(HaveOccurred())

	err = os.RemoveAll(testTempDir)
	Expect(err).ToNot(HaveOccurred())
})

var _ = Describe("E2e Test for Kubectl Sigstore Commands", func() {
	It("Sign Test", func() {
		var timeout int = 10
		Eventually(func() error {
			os.Setenv("COSIGN_PASSWORD", "")
			err := sign(inPath, outPath, keyPath)
			if err != nil {
				return err
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("Verify Test", func() {
		var timeout int = 10
		Eventually(func() error {
			err := verify(outPath, pubkeyPath)
			if err != nil {
				return err
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("Sign with tlog Test", func() {
		var timeout int = 10
		Eventually(func() error {
			os.Setenv("COSIGN_EXPERIMENTAL", "1")
			os.Setenv("COSIGN_PASSWORD", "")
			err := sign(inExpPath, outExpPath, keyPath)
			if err != nil {
				return err
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("Verify with tlog Test", func() {
		var timeout int = 10
		Eventually(func() error {
			os.Setenv("COSIGN_EXPERIMENTAL", "1")
			err := verify(outExpPath, pubkeyPath)
			if err != nil {
				return err
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("VerifyResource Test", func() {
		var timeout int = 10
		Eventually(func() error {
			testNamespace := "default"
			err := verifyResource(outPath, pubkeyPath, testNamespace, "")
			if err != nil {
				return err
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("VerifyResource Test with pubkey in env var", func() {
		var timeout int = 10
		Eventually(func() error {
			testNamespace := "default"
			testPubkeyBytes, err := base64.StdEncoding.DecodeString(string(b64EncodedTestPubKey))
			if err != nil {
				return err
			}
			pubkeyEnvVarName := "K8S_MANIFEST_SIGSTORE_TEST_PUBLIC_KEY"
			err = os.Setenv(pubkeyEnvVarName, string(testPubkeyBytes))
			if err != nil {
				return err
			}
			defer os.Unsetenv(pubkeyEnvVarName)
			pubkeyRef := fmt.Sprintf("env://%s", pubkeyEnvVarName)
			err = verifyResource(outPath, pubkeyRef, testNamespace, "")
			if err != nil {
				return err
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("VerifyResource Test With Keyless-signed Resource", func() {
		var timeout int = 10
		Eventually(func() error {
			_ = os.Setenv(cosignExperimentalEnv, "1")
			defer os.Unsetenv(cosignExperimentalEnv)
			testNamespace := "default"
			mnfPath := filepath.Join("testdata", "sample-configmap-with-keyless-sig.yaml")
			err := verifyResource(mnfPath, "", testNamespace, "")
			if err != nil {
				return err
			}
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("VerifyResource Test Without Signature (This verification should fail)", func() {
		var timeout int = 10
		Eventually(func() error {
			testNamespace := "default"
			mnfPath := filepath.Join("testdata", "sample-configmap-without-sig.yaml")
			err := verifyResource(mnfPath, keyPath, testNamespace, "")
			if err != nil {
				return errors.Wrap(err, "error in verifying a resource")
			}
			if exitCode != 1 {
				return fmt.Errorf("this verification should fail and exit with 1, but got exit code %v", exitCode)
			}
			exitCode = 0
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("VerifyResource Test With Signer Config (This verification should fail)", func() {
		var timeout int = 10
		Eventually(func() error {
			_ = os.Setenv(cosignExperimentalEnv, "1")
			defer os.Unsetenv(cosignExperimentalEnv)
			testNamespace := "default"
			mnfPath := filepath.Join("testdata", "sample-configmap-with-keyless-sig.yaml")
			configPath := filepath.Join("testdata", "config-sample-1.yaml")
			err := verifyResource(mnfPath, "", testNamespace, configPath)
			if err != nil {
				return errors.Wrap(err, "error in verifying a resource")
			}
			if exitCode != 1 {
				return fmt.Errorf("this verification should fail and exit with 1, but got exit code %v", exitCode)
			}
			exitCode = 0
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("VerifyResource Test With a Change (This verification should fail)", func() {
		var timeout int = 10
		Eventually(func() error {
			_ = os.Setenv(cosignExperimentalEnv, "1")
			defer os.Unsetenv(cosignExperimentalEnv)
			testNamespace := "default"
			mnfPath := filepath.Join("testdata", "sample-configmap-modified.yaml")
			err := verifyResource(mnfPath, "", testNamespace, "")
			if err != nil {
				return errors.Wrap(err, "error in verifying a resource")
			}
			if exitCode != 1 {
				return fmt.Errorf("this verification should fail and exit with 1, but got exit code %v", exitCode)
			}
			exitCode = 0
			return nil
		}, timeout, 1).Should(BeNil())
	})
	It("VerifyResource Test With a Change in Ignored Field", func() {
		var timeout int = 10
		Eventually(func() error {
			_ = os.Setenv(cosignExperimentalEnv, "1")
			defer os.Unsetenv(cosignExperimentalEnv)
			testNamespace := "default"
			mnfPath := filepath.Join("testdata", "sample-configmap-modified.yaml")
			configPath := filepath.Join("testdata", "config-sample-2.yaml")
			err := verifyResource(mnfPath, "", testNamespace, configPath)
			if err != nil {
				return errors.Wrap(err, "error in verifying a resource")
			}
			if exitCode != 0 {
				return fmt.Errorf("this verification should fail and exit with 0, but got exit code %v", exitCode)
			}
			exitCode = 0
			return nil
		}, timeout, 1).Should(BeNil())
	})
})

func setup(keyPath, pubkeyPath string) error {
	testkeyBytes, err := base64.StdEncoding.DecodeString(string(b64EncodedTestKey))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(keyPath, testkeyBytes, 0644)
	if err != nil {
		return err
	}

	testPubkeyBytes, err := base64.StdEncoding.DecodeString(string(b64EncodedTestPubKey))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(pubkeyPath, testPubkeyBytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

func sign(inPath, outPath, keyPath string) error {
	cmd := cli.NewCmdSign()
	b := bytes.NewBufferString("")
	cmd.SetOut(b)
	cmd.SetArgs([]string{"-f", inPath, "-k", keyPath, "-o", outPath})
	err := cmd.Execute()
	if err != nil {
		return err
	}
	return nil
}

func verify(inPath, keyPath string) error {
	cmd := cli.NewCmdVerify()
	b := bytes.NewBufferString("")
	cmd.SetOut(b)
	cmd.SetArgs([]string{"-f", inPath, "-k", keyPath})
	err := cmd.Execute()
	if err != nil {
		return err
	}
	return nil
}

func verifyResource(inPath, keyPath, namespace, configPath string) error {
	err := createTestResource(inPath, namespace)
	if err != nil {
		return err
	}
	obj, err := loadObjYAML(inPath)
	if err != nil {
		return err
	}
	objKind := obj.GetKind()
	objName := obj.GetName()
	cmd := cli.NewCmdVerifyResource()
	b := bytes.NewBufferString("")
	cmd.SetOut(b)

	args := []string{objKind, "-n", namespace, objName}
	if keyPath != "" {
		args = append(args, "-k", keyPath)
	}
	if configPath != "" {
		args = append(args, "-c", configPath)
	}
	args = append(args, "-o", "json")
	cmd.SetArgs(args)
	err = cli.KOptions.InitGet(cmd)
	if err != nil {
		return err
	}
	err = cmd.Execute()
	if err != nil {
		return err
	}
	return nil
}

func createTestResource(fname string, namespace string) error {
	var obj *unstructured.Unstructured
	var err error

	objBytes, err := ioutil.ReadFile(fname)
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

func loadObjYAML(fname string) (*unstructured.Unstructured, error) {
	var obj *unstructured.Unstructured
	objBytes, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(objBytes, &obj)
	if err != nil {
		return nil, err
	}
	return obj, nil
}
