# Contributing

## Bugs and changes

Include the library version or commit, Go version, expected behavior, and a
minimal reproduction when reporting a bug or proposing a change. Use synthetic
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
versioned changelog entry. Use its contents for the GitHub release notes.

Beta tags use `v1.0.0-beta.N`. A prerelease must be selected explicitly when
installing it. Stable `v1.0.0` follows validation in the consuming app and marks
the start of the compatibility commitment. Keep existing release tags unchanged.

Contributions are provided under the project's [MIT license](LICENSE).
