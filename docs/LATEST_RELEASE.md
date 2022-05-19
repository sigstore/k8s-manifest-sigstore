
# What's new in v0.1.0

This is the first release of the project!

In this release, a kubectl subcommand plugin is ready, which can be used for signing and verifying Kubernetes (K8s) YAML manifests and resources.

This plugin has 3 major operations around singing and verification as below.

<img src="images/overview.png" alt="overview" width="1000"/>

- `kubectl sigstore sign` generates signature data ("SIG" in the figure) and attach it to a YAML manifest.
- `kubectl sigstore verify` verifies the signature in the signed YAML manifest, and checks equivalence of an input YAML manifest and encoded manifest data in "SIG".
- `kubectl sigstore verify-resource` verifies the signature in the speciifed resource, and it checks equivalence between the resource and an encoded manifest in "SIG".

## Easy install & simple use
You can install it by a single command.
```
$ go install github.com/sigstore/k8s-manifest-sigstore/cmd/kubectl-sigstore@latest
```

Once installed, you can use it as a kubectl subcommand like `kubectl sigstore sign`.

## Sign and verify Kubernetes YAML manifest & resource

The command to sign a YAML manifest is like this. (About `cosign.key`, please refer to [this](https://github.com/sigstore/cosign/blob/main/doc/cosign_generate-key-pair.md).)

```
$ kubectl sigstore sign -f sample-manifest.yaml -k cosign.key
```

This command generates a self-contained manifest with signature and several other data.

To verify the signed YAML manifest, you can do it by this command.
```
$ kubectl sigstore verify -f sample-manifest.yaml.signed -k cosign.pub
```

After deploying a resource with the signed YAML manifest, you can verify it by specifying the resource with the same arguments as `kubectl get` command.

```
$ kubectl sigstore verify-resource cm -n sample-ns sample-configmap -k cosign.pub
```


## Using OCI registry

Additionally, another way to store signature is supported in this release. It uses OCI registry.

The overall flow is described as the image below. `kubectl sigstore sign` command creates "manifest image" which contains a YAML manifest inside, and push it to OCI registry, and then sign the manifest image. This mode does not require any change in the original YAML manifest.

For verification, `kubectl sigstore verify` and `verify-resource` commands pull the specified manifest image, and check the signature of it.

<img src="images/oci-registry.png" alt="oci-registry" width="1200"/>

To sign a YAML manifest using OCI registry, you can use this command. This command uploads a manifest as an image `sample-registry/sample-manifest:dev`, and signs the image.

```
$ kubectl sigstore sign -f sample-manifest.yaml -k cosign.key -i sample-registry/sample-manifest:dev
```

This way of signing does not requires changes in a YAML manifest, so you can verify the original YAML manifest like this.

```
$ kubectl sigstore verify -f sample-manifest.yaml -k cosign.pub -i sample-registry/sample-manifest:dev
```

A resource created from this YAML manifest also can be verified.

In this case, a target resource of verification is automatically selected by checking a manifest in image, so you don't need to specify resource information other than namespace.


```
$ kubectl sigstore verify-resource -n sample-ns -k cosign.pub -i sample-registry/sample-manifest:dev
```

Also, this mode (using OCI registry) is useful to sign multiple YAML manifests at once. In the case, the corresponding resources to manifests can be verified by a single verification. Ths signing part against multiple YAMLs is explained as below.

<img src="images/multi-yamls.png" alt="multi-yamls" width="600"/>

For working with multiple YAML manifests, the commands are like the following.

```
# sign multiple YAML manifests at once ("yamls" is a directory for them)
$ kubectl sigstore sign -f ./yamls/ -k cosign.key -i sample-registry/sample-manifest:dev

# verify a local manifest
$ kubectl sigstore verify -f ./yamls/sample-manifest.yaml -k cosign.pub -i sample-registry/sample-manifest:dev

# verify resources on a cluster at once
$ kubectl sigstore verify-resource -n sample-ns -i sample-registry/sample-manifest:dev
```


## Example of admission controller implementation

A reference impletementation of admission controller with verify-resource feature is inside [example/admission-controller](../example/admission-controller) directory.

For more comprehensive admission controller implementation which uses this project, you can try [Integrity Shield](https://github.com/open-cluster-management/integrity-shield).


