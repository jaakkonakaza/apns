#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

golangci_lint=$(go list -mod=readonly -m -f '{{.Version}}' github.com/golangci/golangci-lint/v2@latest)
govulncheck=$(go list -mod=readonly -m -f '{{.Version}}' golang.org/x/vuln@latest)

updated_makefile=$(mktemp)
trap 'rm -f "$updated_makefile"' EXIT HUP INT TERM

awk -v lint="$golangci_lint" -v vuln="$govulncheck" '
    $1 == "GOLANGCI_LINT_VERSION" && $2 == ":=" { $3 = lint; found++ }
    $1 == "GOVULNCHECK_VERSION" && $2 == ":=" { $3 = vuln; found++ }
    { print }
    END { if (found != 2) exit 1 }
' Makefile > "$updated_makefile"

if cmp -s Makefile "$updated_makefile"; then
    printf '%s\n' 'Tool versions are up to date.'
else
    cat "$updated_makefile" > Makefile
    printf '%s\n' 'Updated tool versions in Makefile. Run make tools and make check to validate.'
fi
