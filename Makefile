GOLANGCI_LINT_VERSION := v2.15.0
GOVULNCHECK_VERSION := v1.1.4
TOOLS_DIR := $(CURDIR)/.bin
GOLANGCI_LINT := $(TOOLS_DIR)/golangci-lint-$(GOLANGCI_LINT_VERSION)/golangci-lint
GOVULNCHECK := $(TOOLS_DIR)/govulncheck-$(GOVULNCHECK_VERSION)/govulncheck
GO_FILES := $(shell git ls-files --cached --others --exclude-standard '*.go' ':!:vendor/**')
EXAMPLE_PACKAGES := $(addprefix ./,$(sort $(dir $(filter _example/%,$(GO_FILES)))))
PACKAGES := ./... $(EXAMPLE_PACKAGES)

.PHONY: tools fmt fmt-check lint build test coverage vuln check

tools: $(GOLANGCI_LINT) $(GOVULNCHECK)

$(GOLANGCI_LINT):
	GOBIN="$(dir $(GOLANGCI_LINT))" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(GOVULNCHECK):
	GOBIN="$(dir $(GOVULNCHECK))" go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

fmt: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) fmt $(GO_FILES)

fmt-check: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) fmt --diff $(GO_FILES)

lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run $(PACKAGES)

build:
	go build $(PACKAGES)

test:
	go test -race $(PACKAGES)

coverage:
	go test -race -covermode=atomic -coverprofile=covprofile $(PACKAGES)

vuln: $(GOVULNCHECK)
	$(GOVULNCHECK) $(PACKAGES)

check: fmt-check lint build test vuln
