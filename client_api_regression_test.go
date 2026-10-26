package apns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json/jsontext"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jaakkonakaza/apns/token"
)

type apiRoundTripper func(*http.Request) (*http.Response, error)

func (f apiRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func apiProvider(t testing.TB) *token.Token {
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

func testClient(t testing.TB, provider *token.Token, rt apiRoundTripper) *Client {
	t.Helper()
	c, err := NewTokenClient(provider, Config{Environment: Sandbox, RequestTimeout: new(time.Duration(0)), Transport: TransportConfig{Decorate: func(http.RoundTripper) http.RoundTripper { return rt }}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

func testRequest() Request {
	return Request{DeviceToken: "aabb", Topic: "com.example", PushType: PushTypeAlert, Payload: jsontext.Value(`{}`)}
}

func testResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Apns-Id": {"push-id"}, "Apns-Unique-Id": {"unique-id"}, "Apns-Request-Id": {"request-id"}, "Retry-After": {"60"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestConstructorsValidateWithoutConnecting(t *testing.T) {
	for _, env := range []Environment{0, 3, 255} {
		if c, err := NewTokenClient(apiProvider(t), Config{Environment: env}); err == nil || c != nil {
			t.Errorf("accepted environment %d", env)
		}
	}
	if c, err := NewTokenClient(nil, Config{Environment: Sandbox}); err == nil || c != nil {
		t.Error("accepted nil provider")
	}
	if c, err := NewTokenClient(&token.Token{}, Config{Environment: Sandbox}); err == nil || c != nil {
		t.Error("accepted empty provider")
	}
	if c, err := NewCertificateClient(tls.Certificate{}, Config{Environment: Sandbox}); err == nil || c != nil {
		t.Error("accepted missing certificate")
	}
	for _, env := range []Environment{Sandbox, Production} {
		c, err := NewTokenClient(apiProvider(t), Config{Environment: env, Transport: TransportConfig{Decorate: func(http.RoundTripper) http.RoundTripper {
			return apiRoundTripper(func(*http.Request) (*http.Response, error) {
				t.Error("construction invoked HTTP")
				return nil, errors.New("unexpected request")
			})
		}}})
		if err != nil {
			t.Fatal(err)
		}
		c.CloseIdleConnections()
	}
}

func TestRequestValidationBeforeHTTP(t *testing.T) {
	calls := 0
	c := testClient(t, apiProvider(t), func(*http.Request) (*http.Response, error) { calls++; return testResponse(200, ""), nil })
	for name, modify := range map[string]func(*Request){
		"empty token": func(r *Request) { r.DeviceToken = "" }, "invalid token": func(r *Request) { r.DeviceToken = "secret-invalid-token" }, "odd token": func(r *Request) { r.DeviceToken = "a" }, "topic": func(r *Request) { r.Topic = "" }, "push type": func(r *Request) { r.PushType = "" }, "collapse bytes": func(r *Request) { r.CollapseID = strings.Repeat("界", 22) },
	} {
		t.Run(name, func(t *testing.T) {
			r := testRequest()
			modify(&r)
			response, err := c.Push(context.Background(), r)
			if err == nil || response.StatusCode != 0 {
				t.Fatalf("response=%+v error=%v", response, err)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("invalid request reached HTTP %d times", calls)
	}
	for _, value := range []string{"00", "001122334455", "AABBCC"} {
		r := testRequest()
		r.DeviceToken = value
		if _, err := c.Push(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCertificateRequestAlsoRequiresTopic(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("certificate/testdata/certificate-valid.pem", "certificate/testdata/certificate-valid.pem")
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCertificateClient(cert, Config{Environment: Sandbox, Transport: TransportConfig{Decorate: func(http.RoundTripper) http.RoundTripper {
		return apiRoundTripper(func(*http.Request) (*http.Response, error) {
			t.Error("missing topic reached HTTP")
			return testResponse(200, ""), nil
		})
	}}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseIdleConnections()
	r := testRequest()
	r.Topic = ""
	if _, err := c.Push(context.Background(), r); err == nil {
		t.Fatal("accepted missing certificate topic")
	}
}

func TestCertificateRejectsTypedNilSigner(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("certificate/testdata/certificate-valid.pem", "certificate/testdata/certificate-valid.pem")
	if err != nil {
		t.Fatal(err)
	}
	cert.PrivateKey = (*ecdsa.PrivateKey)(nil)
	if c, err := NewCertificateClient(cert, Config{Environment: Sandbox}); err == nil || c != nil {
		t.Fatal("accepted typed-nil certificate signer")
	}
}
