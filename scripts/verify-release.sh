#!/usr/bin/env bash
set -euo pipefail

tag=${1:?Usage: verify-release.sh TAG}
export GOWORK=off
go run ./internal/release "$tag" >/dev/null
module=$(go list -m)
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
cd "$work_dir"
go mod init example.com/apns-release-check

for attempt in {1..6}; do
  if go mod download "$module@$tag"; then
    break
  fi
  if [[ $attempt == 6 ]]; then
    exit 1
  fi
  sleep 10
done

go get "$module/...@$tag"
go test -race "$module/..."
GOBIN="$work_dir/bin" go install "$module/cmd/apns@$tag"
actual=$("$work_dir/bin/apns" --version)
if [[ $actual != "$tag" ]]; then
  echo "CLI version $actual does not match $tag" >&2
  exit 1
fi
echo "Verified module installation, tests, and CLI version for $tag"
