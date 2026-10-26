# Changelog

## v1.0.0-beta.1

First prerelease of `github.com/jaakkonakaza/apns`, derived from `apns2`.
The public API may change before `v1.0.0`.

### Included

- Certificate and token authentication with standard-library HTTP/2 transport.
- Live Activity pushes, broadcast pushes, and channel management.
- Concurrent client caching by certificate or token identity, with removal and expiry.
- Typed Live Activity content and attributes in the payload builder.
- CLI certificate and token authentication, push priorities, and build version reporting.
- Security reporting and contribution guidelines.
- Tag-triggered release checks, public module installation verification, and
  GitHub release notes from this changelog.

### Migrating from apns2

- Use module `github.com/jaakkonakaza/apns`, package `apns`, and CLI `apns`.
- Constructors return a client and an error. Supply an endpoint with `WithHost`.
- Call `Push(ctx, notification)` and set the notification's `PushType`.
- Configure transport settings through constructor options.
- Construct provider credentials with `token.New` and use `Bearer` or `Snapshot`.
  Signing keys, identifiers, and cached bearer fields are private.
- Construct managers with `ManagerConfig`. Lookups return a client and an error.
- Use `Success`, `APNSID`, and `APNSUniqueID` on responses.
  Response timestamps are `time.Time` values.
- Use `certificate.FromPEMFile` or `FromPEMBytes` without a password argument.
- Push type and payload enum names omit the `E` prefix. Live Activity setters
  omit the `Set` prefix and date setters accept `time.Time`.
- Use `Sound` for an ordinary alert sound and `CriticalSound` for a critical
  alert sound.

## Release policy

Beta releases use `v1.0.0-beta.N`. Release `v1.0.0` after validating the API and
behavior in the consuming app. Stable v1 releases preserve API compatibility.
Published tags remain unchanged. GitHub release notes reuse the corresponding
changelog entry.
