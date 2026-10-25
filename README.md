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

```go
package main

import (
  "context"
  "log"
  "fmt"

  "github.com/jaakkonakaza/apns2"
  "github.com/jaakkonakaza/apns2/certificate"
)

func main() {

  cert, err := certificate.FromP12File("../cert.p12", "")
  if err != nil {
    log.Fatal("Cert Error:", err)
  }

  notification := &apns2.Notification{}
  notification.DeviceToken = "11aa01229f15f0f0c52029d8cf8cd0aeaf2365fe4cebc4af26cd6d76b7919ef7"
  notification.Topic = "com.example.app"
  notification.Payload = []byte(`{"aps":{"alert":"Hello!"}}`) // See Payload section below

  // Use HostDevelopment for builds installed directly from Xcode.
  client := apns2.NewClient(cert, apns2.WithHost(apns2.HostProduction))
  res, err := client.Push(context.Background(), notification)

  if err != nil {
    log.Fatal("Error:", err)
  }

  fmt.Printf("%v %v %v\n", res.StatusCode, res.ApnsID, res.Reason)
}
```

For a combined PEM certificate and private key, use
`certificate.FromPemFile("certificate.pem")`. Encrypted PEM keys are unsupported.

## JWT Token Example

Instead of using a `.p12` or `.pem` certificate as above, you can optionally use
APNs JWT _Provider Authentication Tokens_. First you will need a signing key (`.p8` file), Key ID and Team ID [from Apple](http://help.apple.com/xcode/mac/current/#/dev54d690a66). Once you have these details, you can create a new client:

```go
authKey, err := token.AuthKeyFromFile("../AuthKey_XXX.p8")
if err != nil {
  log.Fatal("token error:", err)
}

token := &token.Token{
  AuthKey: authKey,
  // KeyID from developer account (Certificates, Identifiers & Profiles -> Keys)
  KeyID:   "ABC123DEFG",
  // TeamID from developer account (View Account -> Membership)
  TeamID:  "DEF123GHIJ",
}
...

client := apns2.NewTokenClient(token)
res, err := client.Push(context.Background(), notification)
```

- You can use one APNs signing key to authenticate tokens for multiple apps.
- A signing key works for both the development and production environments.
- A signing key doesn’t expire but can be revoked.

## Notification

At a minimum, a _Notification_ needs a _DeviceToken_, a _Topic_ and a _Payload_.

```go
notification := &apns2.Notification{
  DeviceToken: "11aa01229f15f0f0c52029d8cf8cd0aeaf2365fe4cebc4af26cd6d76b7919ef7",
  Topic: "com.example.app",
  Payload: []byte(`{"aps":{"alert":"Hello!"}}`),
}
```

You can also set an optional _ApnsID_, _Expiration_ or _Priority_.

```go
notification.ApnsID =  "40636A2C-C093-493E-936A-2A4333C06DEA"
notification.Expiration = time.Now()
notification.Priority = apns2.PriorityLow
```

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
```

Refer to the [payload](https://pkg.go.dev/github.com/jaakkonakaza/apns2/payload) docs for more info.

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

For multiple certificates, `NewClientManager` caches clients and closes idle
connections when entries expire or are evicted. Size the cache and sending
concurrency for your workload.

## Command line tool

Install the command line tool:

```sh
go install github.com/jaakkonakaza/apns2/cmd/apns2@latest
```

From a checkout, use `go install ./cmd/apns2`. Usage:

```sh
apns2 --help
apns2 --certificate-path=certificate.pem --topic=com.example.app --mode=production
```

The CLI reads `<DeviceToken> <APNs Payload>` lines from STDIN and prints the
APNs response code and reason to STDOUT. Use `--help` (or `-h`) to list
flags and `--version` to print the version.

## License

The MIT License (MIT)

Copyright (c) 2016 Adam Jones

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
