module github.com/sigstore/k8s-manifest-sigstore/example/admission-controller

go 1.16

require (
	github.com/ghodss/yaml v1.0.0
	github.com/pkg/errors v0.9.1
	github.com/sigstore/k8s-manifest-sigstore v0.0.0-20210614125345-f77cfab7eb0e
	github.com/sirupsen/logrus v1.8.1
	k8s.io/api v0.21.3
	k8s.io/apimachinery v0.21.3
	k8s.io/client-go v0.21.3
	sigs.k8s.io/controller-runtime v0.9.0
)

replace (
	github.com/sigstore/cosign => github.com/sigstore/cosign v1.0.1
	github.com/sigstore/k8s-manifest-sigstore => ../../
	github.com/sigstore/k8s-manifest-sigstore/example/admission-controller => ./
	k8s.io/kubectl => k8s.io/kubectl v0.21.2
)
