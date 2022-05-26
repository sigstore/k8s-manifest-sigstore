module github.com/sigstore/k8s-manifest-sigstore

go 1.16

require (
	github.com/ProtonMail/go-crypto v0.0.0-20210707164159-52430bf6b52c
	github.com/cyberphone/json-canonicalization v0.0.0-20210823021906-dc406ceaf94b
	github.com/ghodss/yaml v1.0.0
	github.com/go-openapi/runtime v0.23.3
	github.com/google/go-containerregistry v0.8.1-0.20220209165246-a44adc326839
	github.com/in-toto/in-toto-golang v0.3.4-0.20211211042327-af1f9fb822bf
	github.com/jinzhu/copier v0.3.2
	github.com/oliveagle/jsonpath v0.0.0-20180606110733-2e52cf6e6852
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.18.1
	github.com/open-policy-agent/gatekeeper v0.0.0-20210824170141-dd97b8a7e966
	github.com/pkg/errors v0.9.1
	github.com/r3labs/diff v1.1.0
	github.com/secure-systems-lab/go-securesystemslib v0.3.1
	github.com/sigstore/cosign v1.8.0
	github.com/sigstore/fulcio v0.1.2-0.20220114150912-86a2036f9bc7
	github.com/sigstore/rekor v0.4.1-0.20220114213500-23f583409af3
	github.com/sigstore/sigstore v1.2.1-0.20220424143412-3d41663116d5
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/afero v1.8.2
	github.com/spf13/cobra v1.4.0
	github.com/tektoncd/chains v0.3.0
	github.com/theupdateframework/go-tuf v0.0.0-20220211205608-f0c3294f63b9
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.23.5
	k8s.io/apimachinery v0.23.5
	k8s.io/cli-runtime v0.23.0
	k8s.io/client-go v0.23.5
	k8s.io/kube-openapi v0.0.0-20220124234850-424119656bbf
	k8s.io/kubectl v0.23.0
	sigs.k8s.io/controller-runtime v0.11.0-beta.0.0.20211115163949-4d10a0615b11
	sigs.k8s.io/kustomize/api v0.10.1
	sigs.k8s.io/kustomize/kyaml v0.13.0
)

// `go install` only works with a project which has no replace for main module in go.mod.
// So please uncomment the below manually if you are working on a fork repo and if you want to test your local changes.
// replace github.com/sigstore/k8s-manifest-sigstore => ./
