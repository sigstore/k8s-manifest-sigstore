# k8s-manifest-sigstore

kubectl plugin for signing Kubernetes manifest YAML files with sigstore

> :warning: Still under developement, not ready for production use yet!

This kubectl subcommand plugin enables developer to sign k8s manifest yaml files and deployment teams to verify the authenticity of configurations.   Not only is this possible for developers to sign and verify, but  the integrity of deployed manifests can be confirmed on a k8s cluster. 

![intro](images/intro.gif?)

## Installation

The plugin is a standalone executable file `kubectl-sigstore`. 

You can install it just by a single command.
```
go install github.com/sigstore/k8s-manifest-sigstore/cmd/kubectl-sigstore@latest
```

Or you can find the pre-built executables in the release page too.

To build it from source codes, run the following. 
```
git clone git@github.com:sigstore/k8s-manifest-sigstore.git
cd k8s-manifest-sigstore
make
```
You will find new file `kubectl-sigstore`.

To install the plugin, move this executable file to any location on your PATH.


## Usage (bundle image on OCI registry)

```
Usage:
  kubectl sigstore [flags]
  kubectl sigstore [command]

Available Commands:
  apply-after-verify A command to apply Kubernetes YAML manifests only after verifying signature
  sign               A command to sign Kubernetes YAML manifests
  verify             A command to verify Kubernetes YAML manifests
  verify-resource    A command to verify Kubernetes manifests of resources on cluster
```

To use keyless signing, set `export COSIGN_EXPERIMENTAL=1`

### Sign k8s yaml manifest files as bundle OCI image

K8s YAML files are bundled as image, and then pushed to OCI registory. Then, it is signed with cosign. A bundle image reference is added in metadata.annotations in manifest yaml by default. 

`kubectl sigstore sign -f foo.yaml --image bundle-bar:dev`

Inserting annotation can be disabled by adding `--annotation-metadata=false` option. (If annotation is not added, `--image` option must be supplied when verifying signature.)

`kubectl sigstore sign -f foo.yaml --image bundle-bar:dev --annotation-metadata=false`

### Verify a k8s yaml manifest file

`kubectl sigstore verify -f foo.yaml`

An image reference can be supplied with command option.

`kubectl sigstore verify -f foo.yaml --image bundle-bar:dev`

### Create resource with a k8s yaml manifest file after verifying signature

`kubectl sigstore apply-after-verify -f foo.yaml -n ns1`

### Verify a k8s yaml manifest of deployed resource with signature

`kubectl sigstore verify-resource cm foo -n ns1`


Commands

```
Usage:
  kubectl sigstore sign -f FILENAME [-i IMAGE] [flags]

Flags:
  -a, --annotation stringArray      extra key=value pairs to sign
      --annotation-metadata         whether to update annotation and generate signed yaml file (default true)
  -A, --append-signature            if true, keep the existing signatures and append the new one to the annotation like "signature_1" or "signature_2"
      --apply-signature-configmap   whether to apply a generated signature configmap only when "output" is k8s configmap
  -f, --filename string             file name which will be signed (if dir, all YAMLs inside it will be signed)
  -h, --help                        help for sign
  -i, --image string                image name which bundles yaml files and be signed
  -k, --key string                  path to your signing key (if empty, do key-less signing)
  -o, --output string               output file name or k8s signature configmap reference (if empty, use "<filename>.signed")
      --replace-signature           just to clarify the default mode of signature storing. If false, "append-signature" is enabled automatically (default true)
```

```
Usage:
  kubectl sigstore verify -f FILENAME [-i IMAGE] [flags]

Flags:
  -c, --config string     path to verification config YAML file (for advanced verification)
  -f, --filename string   file name which will be verified
  -h, --help              help for verify
  -i, --image string      a comma-separated list of signed image names that contains YAML manifests
  -k, --key string        a comma-separated list of paths to public keys or environment variable names start with "env://" (if empty, do key-less verification)
```

```
Usage:
  kubectl sigstore apply-after-verify -f FILENAME [-i IMAGE] [flags]

Flags:
  -c, --config string                  path to verification config YAML file (for advanced verification)
  -f, --filename string                file name which will be verified and applied
  -h, --help                           help for apply-after-verify
  -i, --image string                   a comma-separated list of signed image names that contains YAML manifests
  -k, --key string                     a comma-separated list of paths to public keys or environment variable names start with "env://" (if empty, do key-less verification)
```

```
Usage:
  kubectl-sigstore verify-resource (RESOURCE/NAME | -f FILENAME | -i IMAGE) [flags]

Flags:
  -c, --config string            path to verification config YAML file (for advanced verification)
      --disable-default-config   if true, disable default ignore fields configuration (default to false)
  -f, --filename string          manifest filename (this can be "-", then read a file from stdin)
  -h, --help                     help for verify-resource
  -i, --image string             a comma-separated list of signed image names that contains YAML manifests
  -k, --key string               a comma-separated list of paths to public keys or environment variable names start with "env://" (if empty, do key-less verification)
  -o, --output string            output format string, either "json" or "yaml" (if empty, a result is shown as a table)
```

## Security

Should you discover any security issues, please refer to sigstore'ss [security
process](https://github.com/sigstore/community/blob/main/SECURITY.md)

## Info

`k8s-manifest-sigstore` is developed as part of the [`sigstore`](https://sigstore.dev) project.

We also use a [slack channel](https://sigstore.slack.com)!
Click [here](https://join.slack.com/t/sigstore/shared_invite/zt-mhs55zh0-XmY3bcfWn4XEyMqUUutbUQ) for the invite link.
