package apns

import (
	"context"
	"encoding/json/jsontext"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/jaakkonakaza/apns/payload"
)

func BenchmarkPayloadEncoding(b *testing.B) {
	for name, value := range map[string]any{
		"typed": payload.Notification{APS: payload.APS{Alert: &payload.Alert{Title: "Order ready", Body: "Your order is ready for collection"}, Badge: new(0), ThreadID: "orders", MutableContent: true}, Custom: map[string]any{"orderID": "123", "locale": "日本語"}},
		"map":   map[string]any{"aps": map[string]any{"alert": map[string]string{"title": "Order ready", "body": "Your order is ready for collection"}, "badge": 0, "thread-id": "orders", "mutable-content": 1}, "orderID": "123", "locale": "日本語"},
		"raw":   jsontext.Value(`{"aps":{"alert":{"title":"Order ready","body":"Your order is ready for collection"},"badge":0,"thread-id":"orders","mutable-content":1},"orderID":"123","locale":"日本語"}`),
	} {
		b.Run(name, func(b *testing.B) {
			encoded, err := marshalPayload(value, 4096)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(encoded)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := marshalPayload(value, 4096); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPooledLocalHTTP2Push(b *testing.B) {
	var dials atomic.Int32
	server, roots := transportServer(b, "h2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Header.Get("Authorization") == "" {
			b.Error("benchmark bypassed HTTP/2 or authentication")
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			b.Error(err)
		}
		w.Header().Set("apns-id", "local-benchmark")
		w.WriteHeader(http.StatusOK)
	}))
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		b.Fatal(err)
	}
	provider := apiProvider(b)
	if _, err := provider.Bearer(); err != nil {
		b.Fatal(err)
	}
	client, err := NewTokenClient(provider, Config{Environment: Sandbox, Transport: TransportConfig{RootCAs: roots, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, endpoint.Host)
	}}})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(client.CloseIdleConnections)
	request := Request{DeviceToken: "aabb", Topic: "com.example.benchmark", PushType: PushTypeAlert, Payload: payload.Notification{APS: payload.APS{Alert: &payload.Alert{Body: "Pooled local request"}}}}
	if _, err := client.Push(context.Background(), request); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if response, err := client.Push(context.Background(), request); err != nil || response.StatusCode != 200 {
			b.Fatalf("local push status=%d error=%v", response.StatusCode, err)
		}
	}
	b.ReportMetric(float64(dials.Load()), "connections")
	if dials.Load() != 1 {
		b.Fatalf("benchmark did not retain pooled connection: dials=%d", dials.Load())
	}
}
