module github.com/sigstore/k8s-manifest-sigstore

go 1.16

require (
	github.com/ProtonMail/go-crypto v0.0.0-20210707164159-52430bf6b52c
	github.com/cyberphone/json-canonicalization v0.0.0-20210823021906-dc406ceaf94b
	github.com/ghodss/yaml v1.0.0
	github.com/go-openapi/runtime v0.21.0
	github.com/google/go-containerregistry v0.7.1-0.20211203164431-c75901cce627
	github.com/in-toto/in-toto-golang v0.4.0-prerelease
	github.com/jinzhu/copier v0.3.2
	github.com/oliveagle/jsonpath v0.0.0-20180606110733-2e52cf6e6852
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.17.0
	github.com/open-policy-agent/gatekeeper v0.0.0-20210824170141-dd97b8a7e966
	github.com/pkg/errors v0.9.1
	github.com/r3labs/diff v1.1.0
	github.com/secure-systems-lab/go-securesystemslib v0.2.0
	github.com/sigstore/cosign v1.4.1
	github.com/sigstore/fulcio v0.1.2-0.20211207184413-f4746cc4ff3d
	github.com/sigstore/rekor v0.3.1-0.20211203233407-3278f72b78bd
	github.com/sigstore/sigstore v1.0.2-0.20211203233310-c8e7f70eab4e
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.2.1
	github.com/tektoncd/chains v0.3.0
	github.com/theupdateframework/go-tuf v0.0.0-20211209174453-13f0687177ba
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.23.0
	k8s.io/apimachinery v0.23.0
	k8s.io/cli-runtime v0.23.0
	k8s.io/client-go v0.23.0
	k8s.io/kube-openapi v0.0.0-20211115234752-e816edb12b65
	k8s.io/kubectl v0.23.0
	sigs.k8s.io/controller-runtime v0.11.0-beta.0.0.20211115163949-4d10a0615b11
	sigs.k8s.io/kustomize/api v0.10.1
	sigs.k8s.io/kustomize/kyaml v0.13.0
)

// `go install` only works with a project which has no replace for main module in go.mod.
// So please uncomment the below manually if you are working on a fork repo and if you want to test your local changes.
// replace github.com/sigstore/k8s-manifest-sigstore => ./
