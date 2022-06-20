module github.com/sigstore/k8s-manifest-sigstore/example/admission-controller

go 1.16

require (
	github.com/ghodss/yaml v1.0.0
	github.com/pkg/errors v0.9.1
	github.com/sigstore/k8s-manifest-sigstore v0.0.0-20210614125345-f77cfab7eb0e
	github.com/sirupsen/logrus v1.8.1
	k8s.io/api v0.23.5
	k8s.io/apimachinery v0.23.5
	k8s.io/client-go v0.23.5
	sigs.k8s.io/controller-runtime v0.11.0-beta.0.0.20211115163949-4d10a0615b11
)

replace (
	github.com/sigstore/k8s-manifest-sigstore => ../../
	github.com/sigstore/k8s-manifest-sigstore/example/admission-controller => ./
)
