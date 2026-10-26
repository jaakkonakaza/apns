package apns2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaakkonakaza/apns2/token"
)

type apiRoundTripper func(*http.Request) (*http.Response, error)

func (f apiRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func apiProvider(t *testing.T) *token.Token {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := token.New(key, "key", "team")
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func TestClientConstructionValidatesEndpoint(t *testing.T) {
	provider := apiProvider(t)
	for _, host := range []string{"", "api.example.com", "https://example.com/path", "https://user:password@example.com", "https://example.com?query=1", "https://example.com#fragment", "https://example.com?", "https://example.com#", "http://example.com"} {
		if client, err := NewTokenClient(provider, WithHost(host)); err == nil || client != nil {
			t.Errorf("accepted endpoint %q", host)
		}
	}
	if client, err := NewClient(tls.Certificate{}, WithHost(HostDevelopment)); err == nil || client != nil {
		t.Error("accepted missing native TLS identity")
	}
	if client, err := NewTokenClient(nil, WithHost(HostDevelopment)); err == nil || client != nil {
		t.Error("accepted nil provider")
	}
	if client, err := NewTokenClient(provider, WithHost(HostDevelopment), nil); err == nil || client != nil {
		t.Error("accepted nil option")
	}
	if client, err := NewTokenClient(provider, WithHost(HostDevelopment), WithTimeout(-time.Second)); err == nil || client != nil {
		t.Error("accepted negative native timeout")
	}
	if _, err := NewClient(tls.Certificate{}, WithHost("http://example.com/"), WithHTTPClient(&http.Client{})); err != nil {
		t.Fatalf("custom HTTP client policy: %v", err)
	}
	if _, err := NewTokenClient(provider, WithHost("http://example.com"), WithHTTPClient(&http.Client{}), WithTimeout(-time.Second), WithTLSConfig(&tls.Config{MaxVersion: tls.VersionTLS11})); err != nil {
		t.Fatalf("irrelevant native settings changed custom HTTP client policy: %v", err)
	}
	if client, err := NewTokenClient(provider, WithHost(HostDevelopment), WithHTTPClient(&http.Client{}), WithTransportWrapper(func(rt http.RoundTripper) http.RoundTripper { return rt })); err == nil || client != nil {
		t.Error("accepted competing transport ownership")
	}
}

func TestBroadcastEndpointsAreRequiredAndCopied(t *testing.T) {
	provider := apiProvider(t)
	for _, endpoints := range []BroadcastEndpoints{{}, {Push: HostBroadcastDevelopment}, {Channels: HostChannelDevelopment}} {
		if client, err := NewBroadcastTokenClient(provider, endpoints); err == nil || client != nil {
			t.Error("accepted incomplete broadcast endpoints")
		}
	}
	endpoints := DevelopmentBroadcastEndpoints()
	client, err := NewBroadcastTokenClient(provider, endpoints)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	endpoints.Push = HostBroadcastProduction
	if client.Endpoints() != DevelopmentBroadcastEndpoints() {
		t.Error("caller changed constructed endpoint pair")
	}
	for _, host := range []string{HostDevelopment, ""} {
		if client, err := NewBroadcastTokenClient(provider, DevelopmentBroadcastEndpoints(), WithHost(host)); err == nil || client != nil {
			t.Error("silently ignored WithHost")
		}
	}
}

func TestPushPayloadAndPriorityPreflight(t *testing.T) {
	calls := 0
	var priority string
	httpClient := &http.Client{Transport: apiRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		priority = r.Header.Get("apns-priority")
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	client, err := NewTokenClient(apiProvider(t), WithHost("https://example.com"), WithHTTPClient(httpClient))
	if err != nil {
		t.Fatal(err)
	}
	notification := func(value any, pushType PushType) *Notification {
		return &Notification{DeviceToken: "aabb", Topic: "com.example", PushType: pushType, Payload: value}
	}
	for _, value := range []any{nil, "null", `[1,2]`, `"text"`, map[string]any{"text": strings.Repeat("界", 1400)}} {
		if _, err := client.Push(context.Background(), notification(value, PushTypeAlert)); err == nil {
			t.Errorf("accepted invalid ordinary payload %T", value)
		}
	}
	invalidBackground := notification(`{}`, PushTypeBackground)
	invalidBackground.Priority = PriorityHigh
	if _, err := client.Push(context.Background(), invalidBackground); err == nil {
		t.Error("accepted background priority10")
	}
	if calls != 0 {
		t.Fatalf("invalid requests reached transport %d times", calls)
	}
	background := notification(`{}`, PushTypeBackground)
	if _, err := client.Push(context.Background(), background); err != nil {
		t.Fatal(err)
	}
	if priority != "5" || background.Priority != 0 {
		t.Fatalf("resolved priority = %q, original priority = %d", priority, background.Priority)
	}
	large := map[string]any{"text": strings.Repeat("x", 4800)}
	if _, err := client.Push(context.Background(), notification(large, PushTypeVOIP)); err != nil {
		t.Fatalf("valid VoIP payload: %v", err)
	}
	broadcast, err := NewBroadcastTokenClient(apiProvider(t), DevelopmentBroadcastEndpoints(), WithHTTPClient(httpClient))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broadcast.Push(context.Background(), &BroadcastNotification{BundleID: "com.example", ChannelID: "channel", Payload: large}); err != nil {
		t.Fatalf("valid broadcast payload: %v", err)
	}
	before := calls
	if _, err := broadcast.Push(context.Background(), &BroadcastNotification{BundleID: "com.example", ChannelID: "channel", Payload: []int{1, 2}}); err == nil {
		t.Error("accepted broadcast array")
	}
	if calls != before {
		t.Error("invalid broadcast reached transport")
	}
}

func TestResponseHeadersSurviveDecodeFailure(t *testing.T) {
	header := http.Header{"Retry-After": []string{"60"}, "Apns-Id": []string{"push-id"}, "Apns-Request-Id": []string{"request-id"}}
	httpClient := &http.Client{Transport: apiRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusTooManyRequests, Header: header, Body: io.NopCloser(strings.NewReader("{"))}, nil
	})}
	provider := apiProvider(t)
	client, err := NewTokenClient(provider, WithHost(HostDevelopment), WithHTTPClient(httpClient))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Push(context.Background(), &Notification{DeviceToken: "aabb", Topic: "com.example", PushType: PushTypeAlert, Payload: map[string]any{}})
	if err == nil || response == nil || response.StatusCode != 429 || response.APNSID != "push-id" || response.Header.Get("Retry-After") != "60" {
		t.Fatalf("response = %+v, err = %v", response, err)
	}
	broadcast, err := NewBroadcastTokenClient(provider, DevelopmentBroadcastEndpoints(), WithHTTPClient(httpClient))
	if err != nil {
		t.Fatal(err)
	}
	channel, err := broadcast.ListChannels(context.Background(), &ChannelRequest{BundleID: "com.example"})
	if err == nil || channel == nil || channel.StatusCode != 429 || channel.RequestID != "request-id" || channel.Header.Get("Retry-After") != "60" {
		t.Fatalf("channel = %+v, err = %v", channel, err)
	}
	header.Set("Retry-After", "120")
	if response.Header.Get("Retry-After") != "60" || channel.Header.Get("Retry-After") != "60" {
		t.Error("response headers were not copied")
	}
}

func TestTransportWrapperKeepsOwnedIdleCleanup(t *testing.T) {
	closed := make(chan struct{})
	var once sync.Once
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Error("wrapper lost HTTP/2")
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			once.Do(func() { close(closed) })
		}
	}
	server.StartTLS()
	defer server.Close()
	wrapped := false
	client, err := NewTokenClient(apiProvider(t), WithHost(server.URL), WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig), WithTransportWrapper(func(rt http.RoundTripper) http.RoundTripper {
		return apiRoundTripper(func(r *http.Request) (*http.Response, error) { wrapped = true; return rt.RoundTrip(r) })
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if _, err := client.Push(context.Background(), &Notification{DeviceToken: "aabb", Topic: "com.example", PushType: PushTypeAlert, Payload: map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if !wrapped {
		t.Fatal("wrapper was not called")
	}
	client.CloseIdleConnections()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("owned connection remained open behind wrapper")
	}
}

func TestUnifiedResponseSuccess(t *testing.T) {
	for _, status := range []int{200, 201, 204, 400} {
		want := status < 300
		if (&Response{StatusCode: status}).Success() != want || (&BroadcastResponse{StatusCode: status}).Success() != want {
			t.Errorf("success differs for %d", status)
		}
	}
}
