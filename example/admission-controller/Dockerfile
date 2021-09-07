
FROM registry.access.redhat.com/ubi8/ubi-minimal:8.3-298

RUN mkdir /myapp 

COPY build/_bin/k8s-manifest-sigstore /myapp/k8s-manifest-sigstore

RUN chgrp -R 0 /myapp && chmod -R g=u /myapp

WORKDIR /myapp

ENTRYPOINT ["/myapp/k8s-manifest-sigstore"]
