# Changelog

## Unreleased

## v1.0.0-beta.1

First prerelease of `github.com/jaakkonakaza/apns`, derived from `apns2`.
The public API may change before `v1.0.0`.

### Included

- Certificate and token authentication over a standard-library HTTP/2
  transport, with optional proxy support.
- Device pushes, Live Activity pushes, broadcast pushes, and channel
  management on one client.
- Typed payload values for alerts, sounds, background, MDM, and ActivityKit
  start, update, and end events, plus a raw JSON path.
- Optional client caching by certificate or token identity in `apns/cache`.
- Bearer token snapshots that can be saved and restored.
- A CLI with certificate and token authentication and push priorities.
- Security reporting and contribution guidelines, and tag-triggered release
  checks that publish GitHub release notes from this changelog.

### Changes from apns2

- Clients are configured once at construction from an explicit environment and
  transport policy, and do not connect until the first request.
- Requests and responses are plain values. Every request takes a context, and
  each operation returns its own result type.
- Requests are validated before sending, including the topic and the priority.
- APNs rejections are typed errors with a `Reason`, and response metadata is
  preserved on both success and failure. Error messages leave out tokens,
  payloads, and other sensitive request data, which remain available by
  unwrapping.
- A request APNs accepted is reported as accepted, even if its response body
  then fails to read.
- Bearer tokens are verified before they are restored, and a token is only
  invalidated when the rejected request used it.

### Migrating from apns2

- Use module `github.com/jaakkonakaza/apns`, package `apns`, and CLI `apns`.
- Create clients with `NewCertificateClient` or `NewTokenClient` and a
  `Config` that sets `Environment`. Constructors return a client and an error.
- Send a `Request` with `Push(ctx, req)`. Set `Topic` and `PushType` on every
  request.
- Build payloads with the `payload` package types instead of the payload
  builder, or pass raw JSON.
- Check errors with `errors.AsType[*apns.Rejection]` and compare its `Reason`
  with the `Reason*` constants instead of reading a reason string from the
  response.
- Construct provider credentials with `token.New` and use `Bearer` or
  `Snapshot`. Signing keys, identifiers, and cached bearer fields are private.
- Replace the client manager with `cache.New`.
- Use `certificate.FromPEMFile` or `FromPEMBytes` without a password argument.

## Release policy

Beta releases use `v1.0.0-beta.N`. Release `v1.0.0` after validating the API and
behavior in the consuming app. Stable v1 releases preserve API compatibility.
Published tags remain unchanged. GitHub release notes reuse the corresponding
changelog entry.
