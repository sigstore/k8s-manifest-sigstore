
FROM registry.access.redhat.com/ubi7/ubi-minimal:7.8

RUN mkdir /myapp 

COPY build/_bin/k8s-manifest-sigstore /myapp/k8s-manifest-sigstore

RUN chgrp -R 0 /myapp && chmod -R g=u /myapp

WORKDIR /myapp

ENTRYPOINT ["/myapp/k8s-manifest-sigstore"]
