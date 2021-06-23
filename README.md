# k8s-manifest-sigstore

kubectl plugin for signing Kubernetes manifest YAML files with sigstore

> :warning: Still under developement, not ready for production use yet!

This kubectl subscommand plugin enables developer to sign k8s manifest yaml files and deployment teams  to verify the authenticity of configurations.   Not only is this possible for developers to sign and verify, but  the integrity of deployed manifests can be confirmed on a k8s cluster. 

![intro](images/intro.gif)

## Installation

The plugin is a standalone executable file `kubectl-sigstore`. 

To build this file, run the following. 
```
git clone git@github.com:yuji-watanabe-jp/k8s-manifest-sigstore.git
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

Inserting annotation can be disabled by adding `--annotation=false` option. (If annotation is not added, `--image` option must be supplied when verifying signature.)

`kubectl sigstore sign -f foo.yaml --image bundle-bar:dev --annotation=false`

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
  kubectl-sigstore sign -f <YAMLFILE> [-i <IMAGE>] [flags]

Flags:
  -a, --annotation              whether to update annotation and generate signed yaml file (default true)
  -f, --filename string         file name which will be signed (if dir, all YAMLs inside it will be signed)
  -h, --help                    help for sign
  -i, --image string            signed image name which bundles yaml files
  -k, --key string              path to your signing key (if empty, do key-less signing)
  -o, --output <input>.signed   output file name (if empty, use <input>.signed)
```

```
Usage:
  kubectl-sigstore verify -f <YAMLFILE> [-i <IMAGE>] [flags]

Flags:
  -f, --filename string   file name which will be signed (if dir, all YAMLs inside it will be signed)
  -h, --help              help for verify
  -i, --image string      signed image name which bundles yaml files
  -k, --key string        path to your signing key (if empty, do key-less signing)
```

```
Usage:
  kubectl-sigstore apply-after-verify -f <YAMLFILE> [-i <IMAGE>] [flags]

Flags:
  -f, --filename string   file name which will be signed (if dir, all YAMLs inside it will be signed)
  -h, --help              help for apply-after-verify
  -i, --image string      signed image name which bundles yaml files
  -k, --key string        path to your signing key (if empty, do key-less signing)
```

```
Usage:
  kubectl-sigstore verify-resource <options> [-i <IMAGE>] [flags]

opitons are same as "kubectl get"

Flags:
  -h, --help               help for verify-resource
  -i, --image string       signed image name which bundles yaml files
  -k, --key string         path to your signing key (if empty, do key-less signing)
  -n, --namespace string   namespace of specified resource
```

## Security

Should you discover any security issues, please refer to sigstores [security
process](https://github.com/sigstore/community/blob/main/SECURITY.md)

## Info

`k8s-manifest-sigstore` is developed as part of the [`sigstore`](https://sigstore.dev) project.

We also use a [slack channel](https://sigstore.slack.com)!
Click [here](https://join.slack.com/t/sigstore/shared_invite/zt-mhs55zh0-XmY3bcfWn4XEyMqUUutbUQ) for the invite link.
