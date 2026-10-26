# apns

A Go client for Apple Push Notification service (APNs). It supports token and
certificate authentication, typed and raw payloads, Live Activities, broadcast
pushes, and channel management. Clients are safe for concurrent use.

## Install

```sh
go get github.com/jaakkonakaza/apns@v1.0.0-beta.1
```

Requires Go 1.27.3 or later.

## Send a notification

```go
key, err := token.AuthKeyFromFile("AuthKey.p8")
if err != nil {
    return err
}
provider, err := token.New(key, "KEY_ID", "TEAM_ID")
if err != nil {
    return err
}
client, err := apns.NewTokenClient(provider, apns.Config{
    Environment: apns.Sandbox,
})
if err != nil {
    return err
}
defer client.CloseIdleConnections()

response, err := client.Push(ctx, apns.Request{
    DeviceToken: deviceToken,
    Topic: "com.example.app",
    PushType: apns.PushTypeAlert,
    Payload: payload.Notification{
        APS: payload.APS{
            Alert: &payload.Alert{Body: "Your order is ready"},
            Badge: new(0),
        },
        Custom: map[string]any{"orderID": "123"},
    },
})
if err != nil {
    return err
}
fmt.Println("APNs accepted", response.APNSID)
```

Use `apns.Production` for production-signed apps; the environment is required.
For certificate authentication, load a PEM or PKCS#12 file with
`apns/certificate` and call `apns.NewCertificateClient(cert, cfg)`. Apple
explains how to get a
[signing key](https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns)
or a
[certificate](https://developer.apple.com/documentation/usernotifications/establishing-a-certificate-based-connection-to-apns).

Create one client per credential and reuse it. Share one `*token.Token` per
signing key. Tokens refresh automatically, and `Snapshot` and `Restore` let you
persist a token between runs. Treat snapshots as secrets.

## Handling errors

A nil error means APNs accepted the request, not that the notification was
delivered or shown. When APNs rejects a request, the error is an
`*apns.Rejection`:

```go
if r, ok := errors.AsType[*apns.Rejection](err); ok {
    switch r.Reason {
    case apns.ReasonBadDeviceToken, apns.ReasonUnregistered:
        // Stop sending to this device token.
    }
}
```

An unexpected response returns `*apns.ResponseError`. Both keep the response
metadata. Error messages leave out tokens and payloads, but the unwrapped
causes, headers, and unknown reasons may contain sensitive data, so redact them
before logging. Apple's
[response guide](https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns)
explains each reason.

For a 410 rejection, `DeviceTokenInvalidatedAt` says when the device token
stopped being valid. Compare it with your own registration records before
deleting a token, since the device may have registered again since then.

The library does not retry or queue requests; that is up to your application.

## Payloads

`Request.Payload` accepts the typed values in `apns/payload`, your own structs
and maps, or raw JSON as a `jsontext.Value`. It must encode as a JSON object.
Payloads are limited to 4 KB, or 5 KB for VoIP and broadcast pushes.

Always set `Topic` and `PushType`. Leave `Priority` at zero to use the default
for the push type. `ExpiresAt` controls how long APNs stores the notification
if the device is offline. Leave it nil for the APNs default, or set it to
`time.Unix(0, 0)` to deliver only once with no storage.

Apple documents the
[payload keys](https://developer.apple.com/documentation/usernotifications/generating-a-remote-notification)
and the
[request options](https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns).

## Live Activities

```go
type Progress struct {
    Counter int `json:"counter"`
    Message string `json:"message"`
}
response, err := client.Push(ctx, apns.Request{
    DeviceToken: activityUpdateToken,
    Topic: "com.example.app.push-type.liveactivity",
    PushType: apns.PushTypeLiveActivity,
    Priority: apns.PriorityHigh,
    Payload: payload.ActivityUpdate[Progress]{
        Timestamp: time.Now(),
        State: Progress{Counter: 7, Message: "Arriving soon"},
    },
})
```

To start an activity remotely, send `payload.ActivityStart` to the
push-to-start token. The app then reports the new activity's update token
separately; the start response doesn't include it. See Apple's guide to
[updating Live Activities with push notifications](https://developer.apple.com/documentation/activitykit/starting-and-updating-live-activities-with-activitykit-push-notifications).

## Broadcasts and channels

The same client provides `Broadcast`, `CreateChannel`, `GetChannel`,
`ListChannels`, and `DeleteChannel`. See the [examples](example_test.go) and
[examples/channel](examples/channel). Apple covers
[setting up broadcasts](https://developer.apple.com/documentation/usernotifications/setting-up-broadcast-push-notifications),
[broadcast requests](https://developer.apple.com/documentation/usernotifications/sending-broadcast-push-notification-requests-to-apns),
and
[channel management](https://developer.apple.com/documentation/usernotifications/sending-channel-management-requests-to-apns).

## Proxies and transport settings

`Config.Transport` sets proxies, custom root certificates, custom dialing, and
connection health checks. `Config.RequestTimeout` sets the per-request timeout
(60 seconds by default). Context deadlines also apply.

## Caching clients

If you send for many apps or credentials, `apns/cache` keeps one client per
credential and closes clients that haven't been used for a while.

## CLI

```sh
go install github.com/jaakkonakaza/apns/cmd/apns@v1.0.0-beta.1
printf '%s\n' 'aabbcc {"aps":{"alert":"Hello"}}' |
  apns --mode=development --topic=com.example.app \
    --auth-key-path=AuthKey.p8 --key-id=KEY_ID --team-id=TEAM_ID
```

The CLI reads one `<DeviceToken> <JSON payload>` per line and prints each
response status, with the reason for rejections. Run `apns --help` for all flags.

## Development

Run `make tools` once, then `make check` before sending changes. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

See [LICENSE](LICENSE). This library is derived from
[sideshow/apns2](https://github.com/sideshow/apns2) and keeps its original
license attribution.
