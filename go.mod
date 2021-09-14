module github.com/sigstore/k8s-manifest-sigstore

go 1.16

require (
	github.com/cyberphone/json-canonicalization v0.0.0-20210823021906-dc406ceaf94b
	github.com/ghodss/yaml v1.0.0
	github.com/go-openapi/runtime v0.19.29
	github.com/google/go-containerregistry v0.6.0
	github.com/in-toto/in-toto-golang v0.2.1-0.20210627200632-886210ae2ab9
	github.com/jinzhu/copier v0.3.2
	github.com/oliveagle/jsonpath v0.0.0-20180606110733-2e52cf6e6852
	github.com/onsi/ginkgo v1.16.4
	github.com/onsi/gomega v1.13.0
	github.com/open-policy-agent/gatekeeper v0.0.0-20210824170141-dd97b8a7e966
	github.com/pkg/errors v0.9.1
	github.com/r3labs/diff v1.1.0
	github.com/sigstore/cosign v1.1.0
	github.com/sigstore/fulcio v0.1.1
	github.com/sigstore/rekor v0.3.0
	github.com/sigstore/sigstore v0.0.0-20210729211320-56a91f560f44
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/cobra v1.2.1
	github.com/tektoncd/chains v0.3.0
	github.com/theupdateframework/go-tuf v0.0.0-20210804171843-477a5d73800a
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.21.3
	k8s.io/apimachinery v0.21.3
	k8s.io/cli-runtime v0.21.2
	k8s.io/client-go v0.21.3
	k8s.io/kube-openapi v0.0.0-20210421082810-95288971da7e
	k8s.io/kubectl v0.19.4
	sigs.k8s.io/controller-runtime v0.9.0
	sigs.k8s.io/kustomize/api v0.9.0
)

replace (
	github.com/sigstore/k8s-manifest-sigstore => ./
	k8s.io/kubectl => k8s.io/kubectl v0.21.2
)
