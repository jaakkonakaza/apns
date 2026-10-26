package apns2_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apns "github.com/jaakkonakaza/apns2"
	"github.com/jaakkonakaza/apns2/token"
)

type mockTransport struct {
	*http.Transport
	closed bool
}

func (c *mockTransport) CloseIdleConnections() {
	c.closed = true
}

// Unit Tests

func TestConstructorsRequireHost(t *testing.T) {
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("client construction sent a request")
		return nil, errors.New("unexpected request")
	})
	for name, construct := range map[string]func() (*apns.Client, error){
		"certificate": func() (*apns.Client, error) {
			return apns.NewClient(mockCert(), apns.WithHTTPClient(&http.Client{Transport: transport}))
		},
		"token": func() (*apns.Client, error) {
			return apns.NewTokenClient(mockToken(), apns.WithHTTPClient(&http.Client{Transport: transport}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			if client, err := construct(); err == nil || client != nil {
				t.Fatalf("constructor = %v, %v, want missing-host error", client, err)
			}
		})
	}
}

func TestClientDevelopmentHost(t *testing.T) {
	client := mustClient(t, mockCert(), apns.WithHost(apns.HostDevelopment))
	if got, want := client.Host(), "https://api.sandbox.push.apple.com"; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestTokenClientDevelopmentHost(t *testing.T) {
	client := mustTokenClient(t, mockToken(), apns.WithHost(apns.HostDevelopment))
	if got, want := client.Host(), "https://api.sandbox.push.apple.com"; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientProductionHost(t *testing.T) {
	client := mustClient(t, mockCert(), apns.WithHost(apns.HostProduction))
	if got, want := client.Host(), "https://api.push.apple.com"; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestTokenClientProductionHost(t *testing.T) {
	client := mustTokenClient(t, mockToken(), apns.WithHost(apns.HostProduction))
	if got, want := client.Host(), "https://api.push.apple.com"; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientBadURLError(t *testing.T) {
	client, err := apns.NewClient(mockCert(), apns.WithHost("badurl://badurl.com"), apns.WithHTTPClient(&http.Client{}))
	if err == nil || client != nil {
		t.Fatalf("constructor = %v, %v, want invalid-host error", client, err)
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
	client := mustTokenClient(t, mockToken(), apns.WithHost("https://"+listener.Addr().String()), apns.WithDialTimeout(dialTimeout))
	defer client.CloseIdleConnections()
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
	n.Topic = ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Content-Type"), ""; !reflect.DeepEqual(got, want) {
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
	if got, want := apnsID, res.APNSID; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestHeaders(t *testing.T) {
	n := mockNotification()
	n.APNSID = "84db694f-464f-49bd-960a-d6db028335c9"
	n.CollapseID = "game1.start.identifier"
	n.Topic = "com.testapp"
	n.Priority = 10
	n.Expiration = time.Now()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("apns-id"), n.APNSID; !reflect.DeepEqual(got, want) {
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
	n.APNSID = "84db694f-464f-49bd-960a-d6db028335c9"
	n.CollapseID = "game1.start.identifier"
	n.Topic = "com.testapp"
	n.Priority = 10
	n.Expiration = time.Unix(0, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("apns-id"), n.APNSID; !reflect.DeepEqual(got, want) {
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

func TestPushTypeHeader(t *testing.T) {
	for _, tc := range []struct {
		pushType apns.PushType
		want     string
	}{
		{apns.PushTypeAlert, "alert"},
		{apns.PushTypeBackground, "background"},
		{apns.PushTypeLocation, "location"},
		{apns.PushTypeVOIP, "voip"},
		{apns.PushTypeComplication, "complication"},
		{apns.PushTypeFileProvider, "fileprovider"},
		{apns.PushTypeMDM, "mdm"},
		{apns.PushTypeLiveActivity, "liveactivity"},
		{apns.PushTypePushToTalk, "pushtotalk"},
		{apns.PushTypeAccessory, "accessory"},
		{apns.PushTypeControls, "controls"},
		{apns.PushTypeWidgets, "widgets"},
		{apns.PushTypeNowPlaying, "nowplaying"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			n := mockNotification()
			n.PushType = tc.pushType
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("apns-push-type"); got != tc.want {
					t.Errorf("got %#v, want %#v", got, tc.want)
				}
			}))
			defer server.Close()
			if _, err := mockClient(server.URL).Push(context.Background(), n); err != nil {
				t.Errorf("got %v, want nil", err)
			}
		})
	}
}

func TestPushRejectsInvalidNotifications(t *testing.T) {
	for name, tc := range map[string]struct {
		token  bool
		modify func(*apns.Notification)
	}{
		"empty push type":         {modify: func(n *apns.Notification) { n.PushType = "" }},
		"token client no topic":   {token: true, modify: func(n *apns.Notification) { n.Topic = "" }},
		"collapse ID too long":    {modify: func(n *apns.Notification) { n.CollapseID = strings.Repeat("x", 65) }},
		"apns-id without hyphens": {modify: func(n *apns.Notification) { n.APNSID = "84db694f464f49bd960ad6db028335c9" }},
	} {
		t.Run(name, func(t *testing.T) {
			n := mockNotification()
			tc.modify(n)
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Error("invalid notification was sent")
				return nil, errors.New("unexpected request")
			})
			client := mustClient(t, mockCert(), apns.WithHost(apns.HostDevelopment), apns.WithHTTPClient(&http.Client{Transport: transport}))
			if tc.token {
				client = mustTokenClient(t, mockToken(), apns.WithHost(apns.HostDevelopment), apns.WithHTTPClient(&http.Client{Transport: transport}))
			}
			if _, err := client.Push(context.Background(), n); err == nil {
				t.Fatal("invalid notification was accepted")
			}
		})
	}
}

// The control for TestPushRejectsInvalidNotifications: the same clients send
// a valid notification, including one with an uppercase apns-id.
func TestPushSendsValidNotification(t *testing.T) {
	for name, token := range map[string]bool{"certificate": false, "token": true} {
		t.Run(name, func(t *testing.T) {
			sent := false
			transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				sent = true
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			})
			client := mustClient(t, mockCert(), apns.WithHost(apns.HostDevelopment), apns.WithHTTPClient(&http.Client{Transport: transport}))
			if token {
				client = mustTokenClient(t, mockToken(), apns.WithHost(apns.HostDevelopment), apns.WithHTTPClient(&http.Client{Transport: transport}))
			}
			n := mockNotification()
			n.APNSID = "84DB694F-464F-49BD-960A-D6DB028335C9"
			if res, err := client.Push(context.Background(), n); err != nil || !res.Success() || !sent {
				t.Fatalf("Push = %v, %v (sent %t), want a sent notification", res, err, sent)
			}
		})
	}
}

func TestPushInvalidatesRejectedRestoredToken(t *testing.T) {
	provider := mockToken()
	provider.Restore("restored.bearer.value", time.Now().Add(-time.Minute))
	var bearers []string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		bearers = append(bearers, r.Header.Get("authorization"))
		body := `{"reason":"InvalidProviderToken"}`
		if len(bearers) > 1 {
			body = ""
		}
		status := http.StatusForbidden
		if len(bearers) > 1 {
			status = http.StatusOK
		}
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	client := mustTokenClient(t, provider, apns.WithHost(apns.HostDevelopment), apns.WithHTTPClient(&http.Client{Transport: transport}))
	for range 2 {
		if _, err := client.Push(context.Background(), mockNotification()); err != nil {
			t.Fatal(err)
		}
	}
	if len(bearers) != 2 || bearers[0] != "bearer restored.bearer.value" || bearers[1] == bearers[0] {
		t.Errorf("bearers = %q, want the rejected restored token replaced", bearers)
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
		if got, want := r.Header.Get("Content-Type"), ""; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("authorization"), "bearer "+bearer; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()

	client := mustTokenClient(t, token, apns.WithHost(server.URL), apns.WithHTTPClient(server.Client()))
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
	_, err := mockClient(apns.HostDevelopment).Push(context.Background(), n)
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
}

func TestDuplicatePayloadKeysAreNotSent(t *testing.T) {
	n := mockNotification()
	n.Payload = `{"aps":{"alert":"one","alert":"two"}}`
	client := mustClient(t, mockCert(), apns.WithHost(apns.HostDevelopment), apns.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("payload with duplicate keys was sent")
		return nil, errors.New("unexpected request")
	})}))
	if _, err := client.Push(context.Background(), n); err == nil {
		t.Fatal("accepted payload with duplicate keys")
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
	if got, want := res.APNSID, apnsID; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.APNSUniqueID, apnsUniqueID; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.Success(), true; !reflect.DeepEqual(got, want) {
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
	if got, want := res.APNSID, apnsID; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.Reason, apns.ReasonPayloadEmpty; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.Success(), false; !reflect.DeepEqual(got, want) {
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
	if got, want := res.APNSID, apnsID; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.Reason, apns.ReasonUnregistered; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.Timestamp.UnixMilli(), int64(1458114061260); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := res.Success(), false; !reflect.DeepEqual(got, want) {
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

func TestAmbiguousOrOversizedResponse(t *testing.T) {
	for name, body := range map[string]string{
		"duplicate names": `{"reason":"one","reason":"two"}`,
		"trailing value":  `{} {}`,
		"invalid UTF-8":   "{\"reason\":\"\xff\"}",
		"oversized":       `{"reason":"` + strings.Repeat("x", 64<<10) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("apns-id", "5D2EA1E7-61E4-4E18-8FD9-8B5D3A8F0A41")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			res, err := mockClient(server.URL).Push(context.Background(), mockNotification())
			if err == nil {
				t.Fatal("accepted malformed response")
			}
			if res == nil || res.StatusCode != http.StatusBadRequest || res.APNSID == "" {
				t.Errorf("response metadata = %+v, want status and apns-id", res)
			}
		})
	}
}

func TestCloseIdleConnections(t *testing.T) {
	transport := &mockTransport{}

	client := mustClient(t, mockCert(), apns.WithHost(apns.HostDevelopment), apns.WithHTTPClient(&http.Client{Transport: transport}))

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
			options := []apns.ClientOption{apns.WithHost(server.URL), apns.WithDialTLSContext(dial), apns.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig), apns.WithReadIdleTimeout(25 * time.Millisecond)}
			client := mustClient(t, mockCert(), options...)
			if tokenAuth {
				client = mustTokenClient(t, mockToken(), options...)
			}
			defer client.CloseIdleConnections()
			response, err := client.Push(context.Background(), mockNotification())
			if err != nil || !response.Success() {
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
	client := mustClient(t, mockCert(), apns.WithHost(server.URL), apns.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig))
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
			options := []apns.ClientOption{apns.WithHost(server.URL), apns.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig)}
			if customDial {
				options = append(options, apns.WithDialTLSContext(func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
					return (&tls.Dialer{Config: cfg}).DialContext(ctx, network, addr)
				}))
			}
			client := mustTokenClient(t, mockToken(), options...)
			defer client.CloseIdleConnections()
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
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("plaintext endpoint received request") }))
	defer server.Close()
	for name, construct := range map[string]func() (*apns.Client, error){
		"certificate": func() (*apns.Client, error) { return apns.NewClient(mockCert(), apns.WithHost(server.URL)) },
		"token":       func() (*apns.Client, error) { return apns.NewTokenClient(mockToken(), apns.WithHost(server.URL)) },
	} {
		t.Run(name, func(t *testing.T) {
			if client, err := construct(); err == nil || client != nil {
				t.Fatalf("constructor = %v, %v, want plaintext rejection", client, err)
			}
		})
	}
}

func TestClientCustomHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	for _, tokenAuth := range []bool{false, true} {
		t.Run(map[bool]string{false: "certificate", true: "token"}[tokenAuth], func(t *testing.T) {
			options := []apns.ClientOption{apns.WithHost(server.URL), apns.WithHTTPClient(server.Client())}
			client := mustClient(t, mockCert(), options...)
			if tokenAuth {
				client = mustTokenClient(t, mockToken(), options...)
			}
			defer client.CloseIdleConnections()
			response, err := client.Push(context.Background(), mockNotification())
			if err != nil || response == nil || !response.Success() {
				t.Fatalf("custom HTTP push = %v, %v", response, err)
			}
		})
	}
}

func TestClientPreservesTransportErrorDuringCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	transportErr := errors.New("TLS handshake failed")
	client := mustTokenClient(t, mockToken(), apns.WithHost(apns.HostDevelopment), apns.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		cancel()
		return nil, transportErr
	})}))
	_, err := client.Push(ctx, mockNotification())
	if _, ok := errors.AsType[*url.Error](err); !ok {
		t.Fatalf("error = %T %v, want *url.Error", err, err)
	}
	if !errors.Is(err, transportErr) {
		t.Fatalf("error = %v, want original transport failure", err)
	}
}

func TestClientPreservesDeadlineErrorWrapper(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	client := mustTokenClient(t, mockToken(), apns.WithHost(apns.HostDevelopment), apns.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}))
	_, err := client.Push(ctx, mockNotification())
	if _, ok := errors.AsType[*url.Error](err); !ok {
		t.Fatalf("error = %T %v, want *url.Error", err, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
}

func TestResponseMetadataSurvivesDecodeError(t *testing.T) {
	for _, status := range []int{http.StatusGone, http.StatusServiceUnavailable} {
		for _, body := range []string{"{", `{"timestamp":"invalid"}`} {
			t.Run(fmt.Sprintf("status=%d/body=%s", status, body), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("apns-id", "request-id")
					w.Header().Set("apns-unique-id", "unique-id")
					w.WriteHeader(status)
					_, _ = w.Write([]byte(body))
				}))
				defer server.Close()
				response, err := mockClient(server.URL).Push(context.Background(), mockNotification())
				if err == nil {
					t.Fatal("malformed response returned no error")
				}
				if response == nil || response.StatusCode != status || response.APNSID != "request-id" || response.APNSUniqueID != "unique-id" {
					t.Fatalf("response metadata lost: %+v", response)
				}
			})
		}
	}
}

func TestResponseBodyCannotReplaceHTTPMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("apns-id", "request-id")
		w.Header().Set("apns-unique-id", "unique-id")
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"StatusCode":200,"APNSID":"body-id","APNSUniqueID":"body-unique-id","reason":"Unregistered","timestamp":1458114061260}`))
	}))
	defer server.Close()
	response, err := mockClient(server.URL).Push(context.Background(), mockNotification())
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusGone || response.APNSID != "request-id" || response.APNSUniqueID != "unique-id" {
		t.Fatalf("body replaced metadata: %+v", response)
	}
	if response.Reason != "Unregistered" || response.Timestamp.UnixMilli() != 1458114061260 {
		t.Fatalf("incorrect body fields: %+v", response)
	}
}

func TestDeviceTokenValidation(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.RawQuery != "" || !strings.HasPrefix(r.URL.Path, "/3/device/") {
			t.Errorf("unexpected URL %s", r.URL)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := mockClient(server.URL)
	for _, value := range []string{"", "a", "zz", "dead/beef", "dead?beef", "dead#beef", "de ad"} {
		n := mockNotification()
		n.DeviceToken = value
		if _, err := client.Push(context.Background(), n); err == nil {
			t.Errorf("accepted invalid device token %q", value)
		}
	}
	if _, err := client.Push(context.Background(), nil); err == nil {
		t.Error("accepted nil notification")
	}
	if requests.Load() != 0 {
		t.Fatalf("invalid tokens caused %d requests", requests.Load())
	}
	for _, value := range []string{"00", "aAbB", strings.Repeat("ab", 40)} {
		n := mockNotification()
		n.DeviceToken = value
		if _, err := client.Push(context.Background(), n); err != nil {
			t.Errorf("rejected hexadecimal token %q: %v", value, err)
		}
	}
	if requests.Load() != 3 {
		t.Errorf("valid tokens caused %d requests, want 3", requests.Load())
	}
}

func TestTokenConstructorRejectsMissingKey(t *testing.T) {
	client, err := apns.NewTokenClient(&token.Token{}, apns.WithHost(apns.HostDevelopment), apns.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("invalid provider reached transport")
		return nil, errors.New("unexpected request")
	})}))
	if !errors.Is(err, token.ErrAuthKeyNil) || client != nil {
		t.Fatalf("constructor = %v, %v, want ErrAuthKeyNil", client, err)
	}
}

func TestZeroExpirationOmitsHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, present := r.Header["Apns-Expiration"]; present {
			t.Error("zero expiration sent an expiration header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if _, err := mockClient(server.URL).Push(context.Background(), mockNotification()); err != nil {
		t.Fatal(err)
	}
}

func TestPreEpochExpirationSendsZero(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("apns-expiration"); got != "0" {
			t.Errorf("expiration = %q, want 0", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	n := mockNotification()
	n.Expiration = time.Unix(-1, 0)
	if _, err := mockClient(server.URL).Push(context.Background(), n); err != nil {
		t.Fatal(err)
	}
}
