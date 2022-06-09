module github.com/sigstore/k8s-manifest-sigstore/example/verify-resource

go 1.16

require (
	github.com/ghodss/yaml v1.0.0
	github.com/pkg/errors v0.9.1
	github.com/sigstore/k8s-manifest-sigstore v0.2.0
	github.com/sirupsen/logrus v1.8.1
	k8s.io/api v0.23.5
	k8s.io/apimachinery v0.23.5
	k8s.io/client-go v0.23.5
)

replace github.com/sigstore/k8s-manifest-sigstore => ../../
