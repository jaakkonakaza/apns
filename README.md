# apns

A Go client for sending Apple Push Notification service (APNs) notifications over HTTP/2.

This is a prerelease. The API may change before `v1.0.0`.
See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Features

- Certificate and token authentication
- Persistent HTTP/2 connections with idle health checks
- Context cancellation and per-client configuration
- Payload builder for alerts, background notifications, and Live Activities
- Concurrent client cache for multiple certificates
- Requires Go 1.27.3 or later

## Install

- Make sure you have [Go 1.27.3 or later](https://go.dev/doc/install) installed.
- Add apns to your Go module:

```sh
go get github.com/jaakkonakaza/apns@v1.0.0-beta.1
```

To run the test suite from this repository:

```sh
go test -race ./...
```

## Development

Run `make tools` to install the pinned development tools into `.bin/`.
Run `make update-tools` to refresh the linter and vulnerability scanner pins,
then run `make check` before committing the updates.

- `make fmt` formats Go files with gofumpt and goimports.
- `make fmt-check` checks formatting without changing files.
- `make tidy-check` checks that module files are tidy without changing them.
- `make lint` checks Go code for issues.
- `make build` builds the library, CLI, and examples.
- `make test` runs tests with race detection.
- `make vuln` checks for known vulnerabilities with govulncheck.
- `make check` runs formatting, module, lint, build, test, and vulnerability checks.

## Example

Token authentication works with every push type. You need a signing key
(`.p8` file), its Key ID and your Team ID
[from Apple](https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns).

```go
package main

import (
  "context"
  "fmt"
  "log"

  "github.com/jaakkonakaza/apns"
  "github.com/jaakkonakaza/apns/token"
)

func main() {
  authKey, err := token.AuthKeyFromFile("AuthKey_ABC123DEFG.p8")
  if err != nil {
    log.Fatal(err)
  }
  provider, err := token.New(authKey, "ABC123DEFG", "DEF123GHIJ")
  if err != nil {
    log.Fatal(err)
  }

  // Use HostDevelopment for builds installed directly from Xcode.
  client, err := apns.NewTokenClient(provider, apns.WithHost(apns.HostProduction))
  if err != nil {
    log.Fatal(err)
  }
  defer client.CloseIdleConnections()
  res, err := client.Push(context.Background(), &apns.Notification{
    DeviceToken: "11aa01229f15f0f0c52029d8cf8cd0aeaf2365fe4cebc4af26cd6d76b7919ef7",
    Topic:       "com.example.app",
    PushType:    apns.PushTypeAlert,
    Payload:     []byte(`{"aps":{"alert":"Hello!"}}`), // See Payload section below
  })
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(res.StatusCode, res.APNSID, res.Reason)
}
```

- Team-scoped keys cover a team's topics; topic-specific keys cover their configured topics.
- New keys are scoped to either development or production. Existing keys that
  support both environments remain supported. Select the matching APNs host.
- A signing key doesn’t expire but can be revoked.

Reuse one `*token.Token` per signing identity. For short-lived processes,
`Snapshot` returns an atomic bearer/issue-time pair for persistence. Pass that
pair to `Restore` when starting another process with the same signing identity.
Keep persisted bearers private. The token constructor validates and copies its
signing key and identifiers.

### Certificate authentication

Certificates support a subset of push types and are valid for a year. Export the
certificate and key from Keychain Access as a `.p12` file:

```go
cert, err := certificate.FromP12File("cert.p12", "password")
if err != nil {
  log.Fatal(err)
}
client, err := apns.NewClient(cert, apns.WithHost(apns.HostProduction))
if err != nil {
  log.Fatal(err)
}
```

For a combined PEM certificate and private key, use
`certificate.FromPEMFile("certificate.pem")`. Encrypted PEM keys are unsupported.

## Notification

At a minimum, a _Notification_ needs a _DeviceToken_, a _Topic_, a _PushType_
and a _Payload_.

```go
notification := &apns.Notification{
  DeviceToken: "11aa01229f15f0f0c52029d8cf8cd0aeaf2365fe4cebc4af26cd6d76b7919ef7",
  Topic:       "com.example.app",
  PushType:    apns.PushTypeAlert,
  Payload:     []byte(`{"aps":{"alert":"Hello!"}}`),
}
```

You can also set an optional _APNSID_, _Expiration_ or _Priority_.

```go
notification.APNSID = "40636a2c-c093-493e-936a-2a4333c06dea"
notification.Expiration = time.Now()
notification.Priority = apns.PriorityLow
```

Set the topic suffix required by the push type. Background notifications default
to priority 5 and reject other explicit priorities. Other push types leave an
unset priority to APNs. `Push` validates that the encoded payload is a JSON
object within the 4096-byte device limit, or 5120 bytes for VoIP.

## Payload

You can use raw bytes for the `notification.Payload` as above, or you can use the payload builder package which makes it easy to construct APNs payloads.

```go
// {"aps":{"alert":"hello","badge":1},"key":"val"}

payload := payload.NewPayload().Alert("hello").Badge(1).Custom("key", "val")

notification.Payload = payload
client.Push(context.Background(), notification)
```

Live Activity payloads use the same builder:

```go
payload := payload.NewPayload().
  Event(payload.LiveActivityEventUpdate).
  ContentState(struct {
    Progress float64 `json:"progress"`
  }{Progress: 0.5}).
  Timestamp(time.Now()).
  StaleDate(time.Now().Add(5*time.Minute))

notification.PushType = apns.PushTypeLiveActivity
notification.Topic = "com.example.app.push-type.liveactivity"
notification.Priority = apns.PriorityLow
notification.Payload = payload
```

Refer to the [payload](https://pkg.go.dev/github.com/jaakkonakaza/apns/payload) docs for more info.

## Broadcast notifications and channels

`BroadcastClient` sends Live Activity updates to channels and supports channel
creation, inspection, listing, and deletion. Select an endpoint pair at
construction:

```go
broadcast, err := apns.NewBroadcastTokenClient(provider,
  apns.DevelopmentBroadcastEndpoints())
if err != nil {
  log.Fatal(err)
}
defer broadcast.CloseIdleConnections()

channel, err := broadcast.CreateChannel(ctx,
  &apns.ChannelRequest{BundleID: "com.example.app"},
  apns.MessageStorageNone)
if err != nil {
  log.Fatal(err)
}
if !channel.Success() {
  log.Fatal(channel.Reason)
}
```

Use the returned `ChannelID` in a `BroadcastNotification`. Its payload is a Live
Activity update. `GetChannel`, `ListChannels`, and `DeleteChannel` manage the
app's channels. Inspect `Success()` for every operation, including deletion.
Enable the app's broadcast capability in Apple Developer before using channels.

## Response, Error handling

`Push` returns a response for APNs acceptance or rejection. Check `Success()` to
see whether APNs accepted the notification. Request, transport, and response
decoding failures return an error. When response decoding fails, the response
still contains the HTTP status, APNs identifiers, and response `Header`.
Unknown APNs reason strings are retained.

Check the error first. A response may still be present when decoding fails:

```go
res, err := client.Push(context.Background(), notification)
if err != nil {
  log.Println("There was an error", err)
  return
}

if res.Success() {
  log.Println("Sent:", res.APNSID)
} else {
  fmt.Printf("Not Sent: %v %v %v\n", res.StatusCode, res.APNSID, res.Reason)
}
```

`Push` never retries automatically. Use the response status and reason to choose
an application policy. Apple's [response guidance](https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns)
distinguishes these cases:

| Response | Caller action |
| --- | --- |
| `BadDeviceToken`, `DeviceTokenNotForTopic`, `Forbidden`, `ExpiredToken`, `Unregistered`, `PayloadTooLarge` | Do not resend the same rejected notification. Correct the destination, authorization, or payload before sending new work. |
| Other 4xx responses | Fix the reported reason before retrying. |
| `TooManyRequests` | Retry after a delay, with backoff. |
| 5xx responses | Apple's guidance permits retrying after 15 minutes, with backoff. |
| Transport failure | Decide whether to retry, accounting for uncertain acceptance. |

`Header.Get("Retry-After")` preserves server or intermediary retry metadata when
present. Its presence is not assumed, and the library does not choose a delay.

## Context & Timeouts

Configure each client when creating it:

```go
client, err := apns.NewTokenClient(authToken,
  apns.WithHost(apns.HostProduction),
  apns.WithTimeout(30*time.Second),
  apns.WithDialTimeout(5*time.Second),
  apns.WithReadIdleTimeout(15*time.Second),
)
if err != nil {
  log.Fatal(err)
}
```

Constructors validate endpoint and authentication configuration before returning.
They do not connect to APNs. A client's endpoint and identity remain fixed.

Use `WithTransportWrapper` to wrap the default transport for instrumentation
without replacing its certificate, protocol settings, or idle cleanup. Use
`httptrace.WithClientTrace` on a request context for standard HTTP tracing.
`WithHTTPClient` transfers transport and TLS configuration to a supplied client,
which must already carry its certificate for certificate authentication.

Every push takes a context for cancellation and individual request deadlines:

```go
ctx, cancel := context.WithTimeout(context.Background(), 10 * time.Second)
defer cancel()
res, err := client.Push(ctx, notification)
```

## Connection reuse

Reuse a client across pushes. Its HTTP transport pools connections and supports
concurrent requests. Call `CloseIdleConnections()` when retiring a client.

`NewClientManager` caches certificate and token clients and closes idle
connections when entries expire, are evicted, or are removed. Token clients are
keyed by team, key ID, public key, and host. Reuse the returned client across
pushes.

```go
manager, err := apns.NewClientManager(apns.ManagerConfig{
  Host: apns.HostProduction,
  MaxSize: 64,
})
if err != nil {
  log.Fatal(err)
}
defer manager.CloseIdleConnections()
client, err := manager.GetByToken(provider)
if err != nil {
  log.Fatal(err)
}
```

Use `Remove(cert)` or `RemoveByToken(provider)` when credentials or topic access
change, or APNs reports `UnrelatedKeyIdInToken`. A later lookup creates a fresh
client. Removal closes idle connections without interrupting requests in use.
Set `ManagerConfig.Factory` or `TokenFactory` to customize client creation.
Factories and both lookup methods return errors. A lookup invalidated by removal
returns `ErrClientRemoved`; a missing factory result returns `ErrClientUnavailable`.
`Add(client)` returns an error for an invalid identity or mismatched host.
`CloseIdleConnections()` closes idle connections across the cache without
interrupting active requests. Zero cache size means no size limit.

## Command line tool

Install the command line tool:

```sh
go install github.com/jaakkonakaza/apns/cmd/apns@v1.0.0-beta.1
```

From a checkout, use `go install ./cmd/apns`. Usage:

```sh
apns --help
apns --certificate-path=certificate.pem --topic=com.example.app --mode=production
apns --auth-key-path=AuthKey.p8 --key-id=KEY_ID --team-id=TEAM_ID --topic=com.example.app --push-type=background --priority=5
```

The CLI reads `<DeviceToken> <APNs Payload>` lines from STDIN and prints the
APNs response code and reason to STDOUT. Use `--help` (or `-h`) to list
flags and `--version` to print the module version or development build revision.
Choose certificate authentication or supply all three token authentication flags.
`--push-type` selects the notification type, and `--priority` accepts 1, 5, or 10.
Priority 0 uses the push type's default. The CLI prints every APNs response and
returns a failure status if any notification is rejected. Transport, input, or
output errors stop the batch immediately.

## Acknowledgments

Derived from [sideshow/apns2](https://github.com/sideshow/apns2).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development and release guidance.
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Copyright (c) 2016 Adam Jones.
