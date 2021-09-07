
VERSION_PKG ?= github.com/sigstore/k8s-manifest-sigstore/pkg/util

.PHONY: build

build:
	@echo building binary for cli
	go mod tidy
	git_status=$$(git status --porcelain --untracked=no 2>/dev/null) && \
	git_tree_state="dirty"  && \
	if [[ -z "$$git_status" ]]; then \
		git_tree_state="clean"; \
	fi && \
	CGO_ENABLED=0 GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w \
	    -X $(VERSION_PKG).buildDate=$$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
		-X $(VERSION_PKG).gitCommit=$$(git rev-parse HEAD 2>/dev/null || echo unknown) \
		-X $(VERSION_PKG).gitTreeState=$$git_tree_state \
		-X $(VERSION_PKG).gitVersion=$$(git describe --tags --abbrev=0 || echo develop)" \
		-a -o kubectl-sigstore ./cmd/kubectl-sigstore
