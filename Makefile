
.PHONY: build

build:
	@echo building binary for cli
	go mod tidy
	CGO_ENABLED=0 GOARCH=amd64 GO111MODULE=on go build -ldflags="-s -w" -a -o kubectl-sigstore ./cmd/kubectl-sigstore
