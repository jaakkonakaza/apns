# Contributing

## Bugs and changes

Use [GitHub Issues](https://github.com/jaakkonakaza/apns/issues) for ordinary bugs
and feature requests. Include the library version or commit, Go version, expected
behavior, and a minimal reproduction when reporting a bug. Use synthetic
payloads and credentials. Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

Keep pull requests focused. Add regression coverage for behavior changes and
update documentation when the public API changes. Describe the motivation and
tradeoffs for substantial API changes in the pull request.

## Local checks

Use the Go version specified in `go.mod` or later. Run:

```sh
make fmt
make check
```

The Makefile installs pinned tools into `.bin/` when needed. Tests use local
servers and fixtures and do not require Apple credentials or a device. Live
APNs testing is separate and requires your own credentials and test device.
Do not commit signing keys, bearer tokens, or device tokens.

## Releases

Describe user-visible changes under `Unreleased` in [CHANGELOG.md](CHANGELOG.md).
Before a release, review those changes, run `make check`, and create the next
versioned changelog entry. The release workflow uses its contents for the
GitHub release notes.

Beta tags use `v1.0.0-beta.N`. A prerelease must be selected explicitly when
installing it. Stable `v1.0.0` follows validation in the consuming app and marks
the start of the compatibility commitment. Keep existing release tags unchanged.

Push the reviewed commit to `main`, then push its version tag. The `release`
workflow checks the tag and changelog, runs `make check`, and installs the tagged
module through `proxy.golang.org` with checksum verification. It tests the
downloaded packages and checks the installed CLI's version before creating a
GitHub release. Alpha, beta, and release-candidate tags produce prereleases.
The workflow publishes release notes, without prebuilt binary assets.

Pushing a tag makes the Go module available even if the workflow later fails.
The workflow gates the GitHub release announcement. If module propagation is
delayed or a transient check fails, rerun the failed workflow from GitHub Actions.
Fix code failures in a new version rather than moving a published tag.

To check an already published tag locally:

```sh
GOPROXY=https://proxy.golang.org bash scripts/verify-release.sh v1.0.0-beta.1
```

Contributions are provided under the project's [MIT license](LICENSE).
