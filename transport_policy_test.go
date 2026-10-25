package apns2_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	apns "github.com/sideshow/apns2"
)

func TestHTTPSProxyHasIndependentTLSVerification(t *testing.T) {
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	proxy, _ := newConnectProxy(t, true)
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := origin.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs.Clone()
	roots.AddCert(proxy.Certificate())
	var verified atomic.Int32
	client := apns.NewTokenClient(mockToken(), apns.WithHost(origin.URL), apns.WithProxy(http.ProxyURL(proxyURL)), apns.WithTLSConfig(&tls.Config{
		RootCAs:    roots,
		ServerName: "example.com",
		VerifyConnection: func(state tls.ConnectionState) error {
			verified.Add(1)
			if state.ServerName != "example.com" || state.NegotiatedProtocol != "h2" {
				return fmt.Errorf("origin verifier received proxy state: %s, %s", state.ServerName, state.NegotiatedProtocol)
			}
			return nil
		},
	}))
	defer client.CloseIdleConnections()
	if response, err := client.Push(context.Background(), mockNotification()); err != nil || response == nil || !response.Sent() {
		t.Fatalf("proxy push = %v, %v", response, err)
	}
	if verified.Load() != 1 {
		t.Fatalf("origin verification calls = %d, want 1", verified.Load())
	}
}

func TestConstructorCertificateOverridesCallback(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 1 {
			t.Error("missing constructor certificate")
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return nil, errors.New("origin callback must not override constructor certificate")
	}
	client := apns.NewClient(server.TLS.Certificates[0], apns.WithHost(server.URL), apns.WithTLSConfig(config))
	defer client.CloseIdleConnections()
	if response, err := client.Push(context.Background(), mockNotification()); err != nil || response == nil || !response.Sent() {
		t.Fatalf("certificate push = %v, %v", response, err)
	}
	if config.GetClientCertificate == nil {
		t.Error("constructor changed supplied TLS configuration")
	}
}

func TestTLSDialerNilResultsReturnError(t *testing.T) {
	for _, proxy := range []bool{false, true} {
		for _, typed := range []bool{false, true} {
			t.Run(fmt.Sprintf("proxy=%t/typed=%t", proxy, typed), func(t *testing.T) {
				options := []apns.ClientOption{apns.WithDialTLSContext(func(context.Context, string, string, *tls.Config) (net.Conn, error) {
					if typed {
						var conn *tls.Conn
						return conn, nil
					}
					return nil, nil
				})}
				if proxy {
					options = append(options, apns.WithProxy(http.ProxyURL(&url.URL{Scheme: "https", Host: "proxy.example.com:443"})))
				}
				client := apns.NewTokenClient(mockToken(), options...)
				defer client.CloseIdleConnections()
				if _, err := client.Push(context.Background(), mockNotification()); err == nil {
					t.Fatal("nil TLS connection was accepted")
				}
			})
		}
	}
}

func TestCustomHTTPClientOwnsCertificate(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 1 {
			t.Error("missing custom HTTP client certificate")
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	server.StartTLS()
	defer server.Close()
	httpClient := server.Client()
	transport := httpClient.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = server.TLS.Certificates
	httpClient.Transport = transport
	client := apns.NewClient(mockCert(), apns.WithHost(server.URL), apns.WithHTTPClient(httpClient))
	defer client.CloseIdleConnections()
	if response, err := client.Push(context.Background(), mockNotification()); err != nil || response == nil || !response.Sent() {
		t.Fatalf("custom certificate push = %v, %v", response, err)
	}
}
