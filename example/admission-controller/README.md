# Example k8s admission controller for k8s manifest verification

This is small example to show how to implement admission controller for verifying k8s manifest with sigstore signing. The original design comes from Integrity Shield project (https://github.com/IBM/integrity-enforcer) which includes more advanced capabilities.

### Setup

You can setup the admission controller just by the following commands.

Please specify an image which you can push there and which can be pulled from the cluster as <YOUR_IMAGE_NAME>.

```
# Build & push an image of admission controller into a registry
$ make build IMG=<YOUR_IMAGE_NAME>

# Deploy an admission controller
$ make deploy IMG=<YOUR_IMAGE_NAME>
```

### Usage

In this example, the admission webhook is configured to check requests of "v1" resources like "ConfigMap" or "Secret" in namespaces that have a label "k8s-manifest-sigstore=true" .

This command shows which namespace is targetted by the admission controller.
```
$ kubectl get ns -L k8s-manifest-sigstore
NAME                    STATUS   AGE    K8S-MANIFEST-SIGSTORE
default                 Active   22d
k8s-manifest-sigstore   Active   16s
kube-system             Active   22d
sample-ns               Active   19d    true
```


First, creating a ConfigMap in a target namespace without signature will be blocked.
```
$ kubectl create -n sample-ns -f sample-configmap.yaml
Error from server (no signature found): error when creating "sample-configmap.yaml": admission webhook "k8smanifest.sigstore.dev" denied the request: no signature found
```

Then, sign the ConfigMap YAML manifest with `kubectl sigstore sign` command and creating it will pass the verification.
```
$ kubectl sigstore sign -f sample-configmap.yaml -i <K8S_MANIFEST_IMAGE>
...

$ kubectl create -n sample-ns -f sample-configmap.yaml.signed
configmap/sample-cm created
```

After the above, any runtime modification without signature will be blocked.
```
$ kubectl patch cm -n sample-ns sample-cm -p '{"data":{"key1":"val1.1"}}'
Error from server (diff found: {"items":[{"key":"data.key1","values":{"after":"val1","before":"val1.1"}}]}): admission webhook "k8smanifest.sigstore.dev" denied the request: diff found: {"items":[{"key":"data.key1","values":{"after":"val1","before":"val1.1"}}]}
```


### Uninstall

To remove the deployed resources, just do this.

```
# Remove all deployed resources by `make deploy`
$ make undeploy
```