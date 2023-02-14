
VERSION_PKG ?= github.com/sigstore/k8s-manifest-sigstore/pkg/util

TEST_OPTIONS ?= COSIGN_EXPERIMENTAL=0 KUBEBUILDER_ASSETS=$$(test/setup-envtest.sh)

# Set version variables for LDFLAGS
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +'%Y-%m-%dT%H:%M:%SZ'
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif

LDFLAGS="-X $(VERSION_PKG).GitVersion=$(GIT_VERSION) -X $(VERSION_PKG).gitCommit=$(GIT_HASH) -X $(VERSION_PKG).gitTreeState=$(GIT_TREESTATE) -X $(VERSION_PKG).buildDate=$(BUILD_DATE)"

.PHONY: build
build:
	@echo building binary for cli
	go mod tidy
	CGO_ENABLED=0 GOARCH=amd64 GO111MODULE=on go build -ldflags $(LDFLAGS) -a -o kubectl-sigstore ./cmd/kubectl-sigstore

.PHONY: kubectl-sigstore
kubectl-sigstore: build

.PHONY: lint
lint:
	golangci-lint run

.PHONY: lint-and-fix
lint-and-fix:
	golangci-lint run --fix

.PHONY: test
test:
	@echo doing unit test
	$(TEST_OPTIONS) go test -v ./...

.PHONY: e2e-test
e2e-test:
	@echo doing e2e test
	$(TEST_OPTIONS) test/e2e/e2e_test.sh

.PHONY: github-oidc-test
github-oidc-test:
	@echo doing github OIDC test
	test/github_oidc_test.sh

# basically used only by github action for releasing
.PHONY: release
release:
	LDFLAGS=$(LDFLAGS) goreleaser release