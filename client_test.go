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
	"reflect"
	"testing"
	"time"

	"golang.org/x/net/http2"

	apns "github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
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
	return &apns.Client{Host: url, HTTPClient: http.DefaultClient}
}

type mockTransport struct {
	*http2.Transport
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
	client := apns.NewTokenClient(mockToken()).Development()
	if got, want := client.Host, "https://api.sandbox.push.apple.com"; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientDevelopmentHost(t *testing.T) {
	client := apns.NewClient(mockCert()).Development()
	if got, want := client.Host, "https://api.sandbox.push.apple.com"; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestTokenClientDevelopmentHost(t *testing.T) {
	client := apns.NewTokenClient(mockToken()).Development()
	if got, want := client.Host, "https://api.sandbox.push.apple.com"; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientProductionHost(t *testing.T) {
	client := apns.NewClient(mockCert()).Production()
	if got, want := client.Host, "https://api.push.apple.com"; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestTokenClientProductionHost(t *testing.T) {
	client := apns.NewTokenClient(mockToken()).Production()
	if got, want := client.Host, "https://api.push.apple.com"; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientBadUrlError(t *testing.T) {
	n := mockNotification()
	res, err := mockClient("badurl://badurl.com").Push(n)
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
	if got := res; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestClientBadTransportError(t *testing.T) {
	n := mockNotification()
	client := mockClient("badurl://badurl.com")
	client.HTTPClient.Transport = nil
	res, err := client.Push(n)
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
	res, err := mockClient("https://api.push.apple.com").Push(n)
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
	if got := res; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestClientNameToCertificate(t *testing.T) {
	crt, _ := certificate.FromP12File("certificate/testdata/certificate-valid.p12", "")
	client := apns.NewClient(crt)

	// Check if the client's certificate is set correctly
	clientCerts := client.HTTPClient.Transport.(*http2.Transport).TLSClientConfig.Certificates
	if got, want := len(clientCerts), 1; got != want {
		t.Errorf("length = %d, want %d", got, want)
	}
	if got, want := clientCerts[0], crt; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	// Test with an empty certificate
	certificate2 := tls.Certificate{}
	client2 := apns.NewClient(certificate2)

	// Check if the client's certificate is empty
	clientCerts2 := client2.HTTPClient.Transport.(*http2.Transport).TLSClientConfig.Certificates
	if got, want := len(clientCerts2), 1; got != want {
		t.Errorf("length = %d, want %d", got, want)
	}
	if got, want := clientCerts2[0], certificate2; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestDialTLSTimeout(t *testing.T) {
	apns.TLSDialTimeout = 10 * time.Millisecond
	crt, _ := certificate.FromP12File("certificate/testdata/certificate-valid.p12", "")
	client := apns.NewClient(crt)

	// Replace the DialTLS with DialTLSContext
	transport := client.HTTPClient.Transport.(*http2.Transport)
	transport.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout: apns.TLSDialTimeout,
		}
		return tls.DialWithDialer(dialer, network, addr, nil)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	defer func() {
		if got := listener.Close(); got != nil {
			t.Errorf("got %v, want nil", got)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), apns.TLSDialTimeout)
	defer cancel()

	var e error
	if _, e = transport.DialTLSContext(ctx, "tcp", address, nil); e == nil {
		t.Fatal("Dial completed successfully")
	}

	if !errors.Is(e, context.DeadlineExceeded) {
		t.Errorf("Unexpected error: %s", e)
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
	_, err := mockClient(server.URL).Push(n)
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
	_, err := mockClient(server.URL).Push(n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestClientPushWithContextWithTimeout(t *testing.T) {
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
	res, err := mockClient(server.URL).PushWithContext(ctx, n)
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
	if got := res; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	cancel()
}

func TestClientPushWithContext(t *testing.T) {
	n := mockNotification()
	apnsID := "02ABC856-EF8D-4E49-8F15-7B8A61D978D6"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("apns-id", apnsID)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	res, err := mockClient(server.URL).PushWithContext(context.Background(), n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got, want := apnsID, res.ApnsID; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientPushWithNilContext(t *testing.T) {
	n := mockNotification()
	apnsID := "02ABC856-EF8D-4E49-8F15-7B8A61D978D6"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("apns-id", apnsID)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	res, err := mockClient(server.URL).PushWithContext(nil, n)
	if err := err; err == nil || err.Error() != "net/http: nil Context" {
		t.Errorf("error = %v, want %q", err, "net/http: nil Context")
	}
	if got := res; got != nil {
		t.Errorf("got %v, want nil", got)
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
	_, err := mockClient(server.URL).Push(n)
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
		if got, want := r.Header.Get("apns-expiration"), ""; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()
	_, err := mockClient(server.URL).Push(n)
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
	_, err := mockClient(server.URL).Push(n)
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
	_, err := mockClient(server.URL).Push(n)
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
	_, err := mockClient(server.URL).Push(n)
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
	_, err := mockClient(server.URL).Push(n)
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
	_, err := mockClient(server.URL).Push(n)
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
	_, err := mockClient(server.URL).Push(n)
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
	_, err := mockClient(server.URL).Push(n)
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
	_, err := mockClient(server.URL).Push(n)
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
	_, err := mockClient(server.URL).Push(n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestAuthorizationHeader(t *testing.T) {
	n := mockNotification()
	token := mockToken()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Content-Type"), "application/json; charset=utf-8"; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := r.Header.Get("authorization"), fmt.Sprintf("bearer %v", token.Bearer); !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}))
	defer server.Close()

	client := mockClient(server.URL)
	client.Token = token
	_, err := client.Push(n)
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
	_, err := mockClient(server.URL).Push(n)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestBadPayload(t *testing.T) {
	n := mockNotification()
	n.Payload = func() {}
	_, err := mockClient("").Push(n)
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
	res, err := mockClient(server.URL).Push(n)
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
	res, err := mockClient(server.URL).Push(n)
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
	res, err := mockClient(server.URL).Push(n)
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
	if got, want := res.Timestamp.Unix(), int64(1458114061260)/1000; !reflect.DeepEqual(got, want) {
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
	res, err := mockClient(server.URL).Push(n)
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
	if got, want := res.Sent(), false; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCloseIdleConnections(t *testing.T) {
	transport := &mockTransport{}

	client := mockClient("")
	client.HTTPClient.Transport = transport

	if got, want := transport.closed, false; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	client.CloseIdleConnections()
	if got, want := transport.closed, true; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}
