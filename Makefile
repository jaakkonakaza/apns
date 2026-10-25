GOLANGCI_LINT_VERSION := v2.15.0
GOVULNCHECK_VERSION := v1.1.4
TOOLS_DIR := $(CURDIR)/.bin
GOLANGCI_LINT := $(TOOLS_DIR)/golangci-lint-$(GOLANGCI_LINT_VERSION)/golangci-lint
GOVULNCHECK := $(TOOLS_DIR)/govulncheck-$(GOVULNCHECK_VERSION)/govulncheck
COVER_PACKAGES = $(shell go list -f '{{if ne .Name "main"}}{{.ImportPath}}{{end}}' ./... | paste -sd, -)

.PHONY: tools fmt fmt-check lint build test coverage vuln check

tools: $(GOLANGCI_LINT) $(GOVULNCHECK)

$(GOLANGCI_LINT):
	GOBIN="$(dir $(GOLANGCI_LINT))" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(GOVULNCHECK):
	GOBIN="$(dir $(GOVULNCHECK))" go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

fmt: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) fmt ./...

fmt-check: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) fmt --diff ./...

lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run ./...

build:
	go build ./...

test:
	go test -race ./...

coverage:
	go test -race -covermode=atomic -coverpkg="$(COVER_PACKAGES)" -coverprofile=covprofile ./...

vuln: $(GOVULNCHECK)
	$(GOVULNCHECK) ./...

check: fmt-check lint build test vuln
