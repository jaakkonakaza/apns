package apns2_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	apns "github.com/sideshow/apns2"
	"github.com/sideshow/apns2/token"
)

// Mocks

func mockNotification() *apns.Notification {
	n := &apns.Notification{}
	n.DeviceToken = "11aa01229f15f0f0c52029d8cf8cd0aeaf2365fe4cebc4af26cd6d76b7919ef7"
	n.Payload = []byte(`{"aps":{"alert":"Hello!"}}`)
	return n
}

func mockToken() *token.Token {
	pubkeyCurve := elliptic.P256()
	authKey, _ := ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
	return &token.Token{AuthKey: authKey}
}

func mockCert() tls.Certificate {
	return tls.Certificate{}
}

func mockClient(url string) *apns.Client {
	return apns.NewClient(mockCert(), apns.WithHost(url), apns.WithHTTPClient(&http.Client{}))
}

type mockTransport struct {
	*http.Transport
	closed bool
}

func (c *mockTransport) CloseIdleConnections() {
	c.closed = true
}

// Unit Tests

func TestClientDefaultHost(t *testing.T) {
	client := apns.NewClient(mockCert())
	if got, want := client.Host, "https://api.sandbox.push.apple.com"; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestTokenDefaultHost(t *testing.T) {
	client := apns.NewTokenClient(mockToken(), apns.WithHost(apns.HostDevelopment))
	if got, want := client.Host, "https://api.sandbox.push.apple.com"; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientDevelopmentHost(t *testing.T) {
	client := apns.NewClient(mockCert(), apns.WithHost(apns.HostDevelopment))
	if got, want := client.Host, "https://api.sandbox.push.apple.com"; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestTokenClientDevelopmentHost(t *testing.T) {
	client := apns.NewTokenClient(mockToken(), apns.WithHost(apns.HostDevelopment))
	if got, want := client.Host, "https://api.sandbox.push.apple.com"; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientProductionHost(t *testing.T) {
	client := apns.NewClient(mockCert(), apns.WithHost(apns.HostProduction))
	if got, want := client.Host, "https://api.push.apple.com"; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestTokenClientProductionHost(t *testing.T) {
	client := apns.NewTokenClient(mockToken(), apns.WithHost(apns.HostProduction))
	if got, want := client.Host, "https://api.push.apple.com"; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientBadUrlError(t *testing.T) {
	n := mockNotification()
	res, err := mockClient("badurl://badurl.com").Push(context.Background(), n)
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
	if got := res; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestClientBadDeviceToken(t *testing.T) {
	n := &apns.Notification{}
	n.DeviceToken = "DGw\aOoD+HwSroh#Ug]%xzd]"
	n.Payload = []byte(`{"aps":{"alert":"Hello!"}}`)
	res, err := mockClient("https://api.push.apple.com").Push(context.Background(), n)
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
	if got := res; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

// Exercise the constructor's actual dialer against a peer that never completes TLS.
func TestDialTimeout(t *testing.T) {
	const dialTimeout = 50 * time.Millisecond
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	client := apns.NewTokenClient(mockToken(), apns.WithDialTimeout(dialTimeout))
	defer client.CloseIdleConnections()
	client.Host = "https://" + listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	_, err = client.Push(ctx, mockNotification())
	if timeout, ok := errors.AsType[net.Error](err); !ok || !timeout.Timeout() {
		t.Fatalf("dial error = %v, want timeout", err)
	}
	if ctx.Err() != nil {
		t.Fatal("request context expired instead of dial timeout")
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("dial took %s with dial timeout=%s", elapsed, dialTimeout)
	}
	select {
	case conn := <-accepted:
		_ = conn.Close()
	case <-time.After(time.Second):
		t.Fatal("dialer did not connect to test listener")
	}
}

// Functional Tests

func TestURL(t *testing.T) {
	n := mockNotification()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, "POST"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.URL.String(), fmt.Sprintf("/3/device/%s", n.DeviceToken); !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()
	_, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestDefaultHeaders(t *testing.T) {
	n := mockNotification()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Content-Type"), "application/json; charset=utf-8"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("apns-id"), ""; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("apns-collapse-id"), ""; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("apns-priority"), ""; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("apns-topic"), ""; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("apns-expiration"), ""; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("thread-id"), ""; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("apns-push-type"), "alert"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()
	_, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestClientPushWithTimeout(t *testing.T) {
	const timeout = time.Nanosecond
	n := mockNotification()
	apnsID := "02ABC856-EF8D-4E49-8F15-7B8A61D978D6"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("apns-id", apnsID)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	time.Sleep(timeout)
	res, err := mockClient(server.URL).Push(ctx, n)
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
	if got := res; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	cancel()
}

func TestClientPush(t *testing.T) {
	n := mockNotification()
	apnsID := "02ABC856-EF8D-4E49-8F15-7B8A61D978D6"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("apns-id", apnsID)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	res, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got, want := apnsID, res.ApnsID; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestHeaders(t *testing.T) {
	n := mockNotification()
	n.ApnsID = "84DB694F-464F-49BD-960A-D6DB028335C9"
	n.CollapseID = "game1.start.identifier"
	n.Topic = "com.testapp"
	n.Priority = 10
	n.Expiration = time.Now()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("apns-id"), n.ApnsID; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("apns-collapse-id"), n.CollapseID; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("apns-priority"), "10"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("apns-topic"), n.Topic; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("apns-expiration"), fmt.Sprintf("%v", n.Expiration.Unix()); !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()
	_, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestExpirationHeader(t *testing.T) {
	n := mockNotification()
	n.ApnsID = "84DB694F-464F-49BD-960A-D6DB028335C9"
	n.CollapseID = "game1.start.identifier"
	n.Topic = "com.testapp"
	n.Priority = 10
	n.Expiration = time.Unix(0, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("apns-id"), n.ApnsID; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("apns-collapse-id"), n.CollapseID; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("apns-priority"), "10"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("apns-topic"), n.Topic; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("apns-expiration"), "0"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()
	_, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestPushTypeAlertHeader(t *testing.T) {
	n := mockNotification()
	n.PushType = apns.PushTypeAlert
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("apns-push-type"), "alert"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()
	_, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestPushTypeBackgroundHeader(t *testing.T) {
	n := mockNotification()
	n.PushType = apns.PushTypeBackground
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("apns-push-type"), "background"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()
	_, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestPushTypeLocationHeader(t *testing.T) {
	n := mockNotification()
	n.PushType = apns.PushTypeLocation
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("apns-push-type"), "location"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()
	_, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestPushTypeVOIPHeader(t *testing.T) {
	n := mockNotification()
	n.PushType = apns.PushTypeVOIP
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("apns-push-type"), "voip"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()
	_, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestPushTypeComplicationHeader(t *testing.T) {
	n := mockNotification()
	n.PushType = apns.PushTypeComplication
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("apns-push-type"), "complication"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()
	_, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestPushTypeFileProviderHeader(t *testing.T) {
	n := mockNotification()
	n.PushType = apns.PushTypeFileProvider
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("apns-push-type"), "fileprovider"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()
	_, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestPushTypeMDMHeader(t *testing.T) {
	n := mockNotification()
	n.PushType = apns.PushTypeMDM
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("apns-push-type"), "mdm"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()
	_, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestPushTypeLiveActivityHeader(t *testing.T) {
	n := mockNotification()
	n.PushType = apns.PushTypeLiveActivity
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("apns-push-type"), "liveactivity"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()
	_, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestPushTypePushToTalkHeader(t *testing.T) {
	n := mockNotification()
	n.PushType = apns.PushTypePushToTalk
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("apns-push-type"), "pushtotalk"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()
	_, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestAuthorizationHeader(t *testing.T) {
	n := mockNotification()
	token := mockToken()
	bearer, err := token.Bearer()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Content-Type"), "application/json; charset=utf-8"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("authorization"), "bearer "+bearer; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()

	client := mockClient(server.URL)
	client.Token = token
	_, err = client.Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestPayload(t *testing.T) {
	n := mockNotification()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if got := err; got != nil {
			t.Errorf("got %v, want nil", got)
		}
		if got, want := body, n.Payload; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()
	_, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestBadPayload(t *testing.T) {
	n := mockNotification()
	n.Payload = func() {}
	_, err := mockClient("").Push(context.Background(), n)
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
}

func Test200SuccessResponse(t *testing.T) {
	n := mockNotification()
	apnsID := "02ABC856-EF8D-4E49-8F15-7B8A61D978D6"
	apnsUniqueID := "A6739D99-D92A-424B-A91E-BF012365BD4E"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("apns-id", apnsID)
		w.Header().Set("apns-unique-id", apnsUniqueID)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	res, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got, want := res.StatusCode, http.StatusOK; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.ApnsID, apnsID; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.ApnsUniqueID, apnsUniqueID; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.Sent(), true; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func Test400BadRequestPayloadEmptyResponse(t *testing.T) {
	n := mockNotification()
	apnsID := "02ABC856-EF8D-4E49-8F15-7B8A61D978D6"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("apns-id", apnsID)
		w.WriteHeader(http.StatusBadRequest)
		_, err := w.Write([]byte("{\"reason\":\"PayloadEmpty\"}"))
		if got := err; got != nil {
			t.Errorf("got %v, want nil", got)
		}
	}))
	defer server.Close()
	res, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got, want := res.StatusCode, 400; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.ApnsID, apnsID; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.Reason, apns.ReasonPayloadEmpty; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.Sent(), false; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func Test410UnregisteredResponse(t *testing.T) {
	n := mockNotification()
	apnsID := "9F595474-356C-485E-B67F-9870BAE68702"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("apns-id", apnsID)
		w.WriteHeader(http.StatusGone)
		_, err := w.Write([]byte("{\"reason\":\"Unregistered\", \"timestamp\": 1458114061260 }"))
		if got := err; got != nil {
			t.Errorf("got %v, want nil", got)
		}
	}))
	defer server.Close()
	res, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got, want := res.StatusCode, 410; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.ApnsID, apnsID; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.Reason, apns.ReasonUnregistered; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.Timestamp.UnixMilli(), int64(1458114061260); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.Sent(), false; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestMalformedJSONResponse(t *testing.T) {
	n := mockNotification()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, err := w.Write([]byte("{{MalformedJSON}}"))
		if got := err; got != nil {
			t.Errorf("got %v, want nil", got)
		}
	}))
	defer server.Close()
	res, err := mockClient(server.URL).Push(context.Background(), n)
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
	if got, want := res.StatusCode, http.StatusOK; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCloseIdleConnections(t *testing.T) {
	transport := &mockTransport{}

	client := apns.NewClient(mockCert(), apns.WithHTTPClient(&http.Client{Transport: transport}))

	if got, want := transport.closed, false; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	client.CloseIdleConnections()
	if got, want := transport.closed, true; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

// Exercise the real constructor transport, TLS verification, ALPN, and public
// dial hook. The other functional tests use a supplied HTTP client.
func TestConstructorHTTP2(t *testing.T) {
	for _, tokenAuth := range []bool{false, true} {
		t.Run(fmt.Sprintf("token=%t", tokenAuth), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 {
					t.Errorf("protocol = %s, want HTTP/2", r.Proto)
				}
				w.WriteHeader(http.StatusOK)
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			called := make(chan *tls.Config, 1)
			dial := func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				called <- cfg
				return (&tls.Dialer{Config: cfg}).DialContext(ctx, network, addr)
			}
			options := []apns.ClientOption{apns.WithDialTLSContext(dial), apns.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig), apns.WithReadIdleTimeout(25 * time.Millisecond)}
			client := apns.NewClient(mockCert(), options...)
			if tokenAuth {
				client = apns.NewTokenClient(mockToken(), options...)
			}
			defer client.CloseIdleConnections()
			client.Host = server.URL
			response, err := client.Push(context.Background(), mockNotification())
			if err != nil || !response.Sent() {
				t.Fatalf("HTTP/2 push: response=%v, error=%v", response, err)
			}
			cfg := <-called
			if cfg.MinVersion < tls.VersionTLS12 || cfg.ServerName == "" || len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "h2" {
				t.Fatalf("dial hook received incorrect TLS config: %+v", cfg)
			}
		})
	}
}

func TestConstructorRejectsHTTP1(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP/1-only server received a push")
	}))
	defer server.Close()
	client := apns.NewClient(mockCert(), apns.WithHost(server.URL), apns.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig))
	defer client.CloseIdleConnections()
	if _, err := client.Push(context.Background(), mockNotification()); err == nil {
		t.Fatal("HTTP/1-only endpoint accepted")
	}
}

func TestConstructorRejectsNoALPN(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server without ALPN received a push")
	}))
	server.TLS = &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			cfg := server.TLS.Clone()
			cfg.GetConfigForClient = nil
			cfg.NextProtos = nil
			return cfg, nil
		},
	}
	server.StartTLS()
	defer server.Close()
	for _, customDial := range []bool{false, true} {
		t.Run(fmt.Sprintf("customDial=%t", customDial), func(t *testing.T) {
			options := []apns.ClientOption{apns.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig)}
			if customDial {
				options = append(options, apns.WithDialTLSContext(func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
					return (&tls.Dialer{Config: cfg}).DialContext(ctx, network, addr)
				}))
			}
			client := apns.NewTokenClient(mockToken(), options...)
			defer client.CloseIdleConnections()
			client.Host = server.URL
			_, err := client.Push(context.Background(), mockNotification())
			if err == nil {
				t.Fatal("endpoint without ALPN accepted")
			}
			if _, ok := errors.AsType[*url.Error](err); !ok {
				t.Fatalf("protocol error = %T %v, want *url.Error", err, err)
			}
		})
	}
}

func TestConstructorRejectsPlaintext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("plaintext server received a push")
	}))
	defer server.Close()
	for _, client := range []*apns.Client{apns.NewClient(mockCert()), apns.NewTokenClient(mockToken())} {
		client.Host = server.URL
		defer client.CloseIdleConnections()
		if _, err := client.Push(context.Background(), mockNotification()); err == nil {
			t.Error("plaintext endpoint accepted")
		}
	}
}
