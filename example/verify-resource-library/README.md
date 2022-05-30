## Example Use of k8s-manifest-sigstore as A Library

With this example code, you can learn how to import and use k8s-manifest-sigstore for verifying resources in your go project.

`sample.go` in this directory is the sample code, and you can execute it just by this.

```
$ go run sample.go
```

This example is verifying a sample configmap resource and its signature with a special configuration to allow changes in some specific fields in the configmap.

You can check how to configure them and how to execute it in the next section. 

## Description of the code

First, to verify Kubernetes resources in your go project, import the `k8s-manifest-sigstore` module as below.

```go
import (
    // ... other modules
    "github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
)
```

Then, you can call `k8smanifest.VerifyResource()`, which is the very function to verify a resource in a cluster.

The arguments for this function are just the following 2 variables.

1. `obj` - A resource to be verified
1. `opt` - Configuration of the verification

`obj` is the resource you want to verify here, and you can get it via K8s API modules. ([client-go example](https://github.com/kubernetes/client-go#how-to-use-it))

If you want to verify multiple resources, just to call `VerifyResource()` for each of them.

`opt` is a variable of type `k8smanifest.VerifyResourceOption`, and this is a set of verification configuration.

Typically, you may want to configure some specific fields that can be changed without signature (e.g. `spec.replicas` in a Deployment resource).

For that, you can use `IgnoreFields` config as below.

```go
opt := &k8smanifest.VerifyResourceOption{}

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
```

The `autoEmbeddedLabel` label and the `changable` field in the ConfigMap data can be changed after signing and the changes in these fields do not cause verification failure with this option.

Also, in this sample code, a public key is specified in the `KeyPath` config like the following.

```go
opt.KeyPath = pubkeyPath
```

Then you can add a pre-defined config to yours so that `VerifyResource()` can ignore some changes made by Kubernetes system.

```go
opt = k8smanifest.AddDefaultConfig(opt)
```

Now you can call `VerifyResource()` as below.

```go
result, err := k8smanifest.VerifyResource(obj, opt)
if err != nil {
	// handle the error
}
if result.Verified {
    // verification success.
} else {
    // verification failure. you can check the detail of the verification by the `result` variable. 
}
```

This is the expected output of the sample code.

```
$ go run sample.go
Verified OK
INFO[0000] verification OK: {"verified":true,"inScope":true,"signer":"","signedTime":null,"sigRef":"__embedded_in_annotation__","diff":null,"containerImages":[]}
```

