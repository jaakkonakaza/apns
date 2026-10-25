# APNS/2

A Go client for sending Apple Push Notification service (APNs) notifications over HTTP/2.

## Features

- Certificate and token authentication
- Persistent HTTP/2 connections with idle health checks
- Context cancellation and per-client configuration
- Payload builder for alerts, background notifications, and Live Activities
- Concurrent client cache for multiple certificates
- Requires Go 1.27.3 or later

## Install

- Make sure you have [Go 1.27.3 or later](https://go.dev/doc/install) installed.
- Add apns2 to your Go module:

```sh
go get github.com/jaakkonakaza/apns2
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

  "github.com/jaakkonakaza/apns2"
  "github.com/jaakkonakaza/apns2/token"
)

func main() {
  authKey, err := token.AuthKeyFromFile("AuthKey_ABC123DEFG.p8")
  if err != nil {
    log.Fatal(err)
  }
  provider := &token.Token{
    AuthKey: authKey,
    KeyID:   "ABC123DEFG", // Certificates, Identifiers & Profiles -> Keys
    TeamID:  "DEF123GHIJ", // Membership details
  }

  // Use HostDevelopment for builds installed directly from Xcode.
  client := apns2.NewTokenClient(provider, apns2.WithHost(apns2.HostProduction))
  res, err := client.Push(context.Background(), &apns2.Notification{
    DeviceToken: "11aa01229f15f0f0c52029d8cf8cd0aeaf2365fe4cebc4af26cd6d76b7919ef7",
    Topic:       "com.example.app",
    PushType:    apns2.PushTypeAlert,
    Payload:     []byte(`{"aps":{"alert":"Hello!"}}`), // See Payload section below
  })
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println(res.StatusCode, res.ApnsID, res.Reason)
}
```

- Team-scoped keys cover a team's topics; topic-specific keys cover their configured topics.
- New keys are scoped to either development or production. Existing keys that
  support both environments remain supported. Select the matching APNs host.
- A signing key doesn’t expire but can be revoked.

Reuse one `*token.Token` per signing identity. For short-lived processes,
`IssuedAt` and `Restore` let you reuse a previously signed bearer.

### Certificate authentication

Certificates support a subset of push types and are valid for a year. Export the
certificate and key from Keychain Access as a `.p12` file:

```go
cert, err := certificate.FromP12File("cert.p12", "password")
if err != nil {
  log.Fatal(err)
}
client := apns2.NewClient(cert, apns2.WithHost(apns2.HostProduction))
```

For a combined PEM certificate and private key, use
`certificate.FromPemFile("certificate.pem")`. Encrypted PEM keys are unsupported.

## Notification

At a minimum, a _Notification_ needs a _DeviceToken_, a _Topic_, a _PushType_
and a _Payload_.

```go
notification := &apns2.Notification{
  DeviceToken: "11aa01229f15f0f0c52029d8cf8cd0aeaf2365fe4cebc4af26cd6d76b7919ef7",
  Topic:       "com.example.app",
  PushType:    apns2.PushTypeAlert,
  Payload:     []byte(`{"aps":{"alert":"Hello!"}}`),
}
```

You can also set an optional _ApnsID_, _Expiration_ or _Priority_.

```go
notification.ApnsID = "40636a2c-c093-493e-936a-2a4333c06dea"
notification.Expiration = time.Now()
notification.Priority = apns2.PriorityLow
```

For other push types, set `Priority` and the matching topic suffix too; the
`PushType` constants name each suffix.

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
  ContentState(map[string]any{"progress": 0.5}).
  Timestamp(time.Now()).
  StaleDate(time.Now().Add(5*time.Minute))

notification.PushType = apns2.PushTypeLiveActivity
notification.Topic = "com.example.app.push-type.liveactivity"
notification.Priority = apns2.PriorityLow
notification.Payload = payload
```

Refer to the [payload](https://pkg.go.dev/github.com/jaakkonakaza/apns2/payload) docs for more info.

## Broadcast notifications and channels

`BroadcastClient` sends Live Activity updates to channels and supports channel
creation, inspection, listing, and deletion. Set both endpoints explicitly:

```go
broadcast := apns2.NewBroadcastTokenClient(provider)
broadcast.Host = apns2.HostBroadcastDevelopment
broadcast.ChannelHost = apns2.HostChannelDevelopment
defer broadcast.CloseIdleConnections()

channel, err := broadcast.CreateChannel(ctx,
  &apns2.ChannelRequest{BundleID: "com.example.app"},
  apns2.MessageStorageNone)
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

`Push` returns a response for APNs acceptance or rejection. Check `Sent()` to
see whether APNs accepted the notification. Request, transport, and response
decoding failures return an error. When response decoding fails, the response
still contains the HTTP status and APNs identifiers.

Check the error first. A response may still be present when decoding fails:

```go
res, err := client.Push(context.Background(), notification)
if err != nil {
  log.Println("There was an error", err)
  return
}

if res.Sent() {
  log.Println("Sent:", res.ApnsID)
} else {
  fmt.Printf("Not Sent: %v %v %v\n", res.StatusCode, res.ApnsID, res.Reason)
}
```

## Context & Timeouts

Configure each client when creating it:

```go
client := apns2.NewTokenClient(authToken,
  apns2.WithHost(apns2.HostProduction),
  apns2.WithTimeout(30*time.Second),
  apns2.WithDialTimeout(5*time.Second),
  apns2.WithReadIdleTimeout(15*time.Second),
)
```

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
manager := apns2.NewClientManager(apns2.WithHost(apns2.HostProduction))
client, err := manager.GetByToken(provider)
if err != nil {
  log.Fatal(err)
}
```

Use `Remove(cert)` or `RemoveByToken(provider)` when credentials or topic access
change, or APNs reports `UnrelatedKeyIdInToken`. A later lookup creates a fresh
client. Removal closes idle connections without interrupting requests in use.
Configure `Factory` or `TokenFactory` before concurrent use to customize client
creation. `Add(client)` returns an error if the client has an invalid identity.

## Command line tool

Install the command line tool:

```sh
go install github.com/jaakkonakaza/apns2/cmd/apns2@latest
```

From a checkout, use `go install ./cmd/apns2`. Usage:

```sh
apns2 --help
apns2 --certificate-path=certificate.pem --topic=com.example.app --mode=production
apns2 --auth-key-path=AuthKey.p8 --key-id=KEY_ID --team-id=TEAM_ID --topic=com.example.app --push-type=background --priority=5
```

The CLI reads `<DeviceToken> <APNs Payload>` lines from STDIN and prints the
APNs response code and reason to STDOUT. Use `--help` (or `-h`) to list
flags and `--version` to print the module version or development build revision.
Choose certificate authentication or supply all three token authentication flags.
`--push-type` selects the notification type, and `--priority` accepts 1, 5, or 10.
The default priority, 0, omits the header.

## License

The MIT License (MIT)

Copyright (c) 2016 Adam Jones

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
