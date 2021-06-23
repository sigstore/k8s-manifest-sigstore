#
# Copyright 2020 IBM Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

IMG ?= localhost:5000/k8s-manifest-sigstore:dev

TMP_KUSTOMIZE_DIR ?= /tmp/k8s-manifest-sigstore

CERT_DIR ?= config/webhook/cert/
WEBHOOK_SERVICE_NAME ?= k8s-manifest-webhook-service
K8S_MANIFEST_SIGSTORE_NS ?= k8s-manifest-sigstore
TMP_CERT_CONFIG_PATH ?= /tmp/crt.conf


.PHONY: build deploy undeploy gen-certs

build:
	@echo building binary for image
	go mod tidy
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -o build/_bin/k8s-manifest-sigstore ./
	@echo building image
	docker build -t $(IMG) .
	docker push $(IMG)

gencerts:
	@if [ ! -f "$(CERT_DIR)tls.crt" ]; then \
		echo generating webhook tls certs into $(CERT_DIR) ; \
		mkdir -p $(CERT_DIR) ; \
		cd $(CERT_DIR) ; \
		cat ../crt.conf | sed 's/SERVICE_NAME_PLACEHOLDER/$(WEBHOOK_SERVICE_NAME)/g' | sed 's/NAMESPACE_PLACEHOLDER/$(K8S_MANIFEST_SIGSTORE_NS)/g' > $(TMP_CERT_CONFIG_PATH) ; \
		openssl req -nodes -new -x509 -keyout ca.key -out ca.crt -subj "/CN=$(WEBHOOK_SERVICE_NAME)_ca" ; \
		openssl genrsa -out tls.key 2048 ; \
		openssl req -new -key tls.key -subj "/CN=$(WEBHOOK_SERVICE_NAME).$(K8S_MANIFEST_SIGSTORE_NS).svc" -out tls.csr ; \
		openssl x509 -extfile $(TMP_CERT_CONFIG_PATH) -extensions v3_req -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out tls.crt ; \
		cp ca.crt ca_crt ; \
	else \
		echo use existing webhook tls certs in $(CERT_DIR) ; \
	fi

deploy: gencerts
	@echo deploying resources
	cp -r ./ $(TMP_KUSTOMIZE_DIR)
	cd $(TMP_KUSTOMIZE_DIR)/config/common && kustomize edit set image k8s-manifest-sigstore=$(IMG)
	kustomize build $(TMP_KUSTOMIZE_DIR)/config/default | kubectl apply -f -

undeploy:
	@echo removing resources
	cp -r ./ $(TMP_KUSTOMIZE_DIR)
	cd $(TMP_KUSTOMIZE_DIR)/config/common && kustomize edit set image k8s-manifest-sigstore=$(IMG)
	kustomize build $(TMP_KUSTOMIZE_DIR)/config/default | kubectl delete -f -
