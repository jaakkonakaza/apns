package apns2_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	apns "github.com/jaakkonakaza/apns2"
)

func TestClientRequestTimeoutsAreIndependent(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(80 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	tlsOption := apns.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig)
	short := mustTokenClient(t, mockToken(), apns.WithHost(server.URL), tlsOption, apns.WithTimeout(20*time.Millisecond))
	long := mustTokenClient(t, mockToken(), apns.WithHost(server.URL), tlsOption, apns.WithTimeout(time.Second))
	defer short.CloseIdleConnections()
	defer long.CloseIdleConnections()
	shortResult := make(chan error, 1)
	go func() { _, err := short.Push(context.Background(), mockNotification()); shortResult <- err }()
	response, err := long.Push(context.Background(), mockNotification())
	if err != nil || response == nil || !response.Success() {
		t.Fatalf("long-timeout push = %v, %v", response, err)
	}
	if err := <-shortResult; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("short-timeout push = %v, want deadline exceeded", err)
	}
}

func TestClientDialersAndTLSSettingsAreIndependent(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("protocol = %s", r.Proto)
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	roots := server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	var verified atomic.Int32
	sharedTLS := &tls.Config{RootCAs: roots, NextProtos: []string{"h2", "http/1.1"}, VerifyConnection: func(tls.ConnectionState) error { verified.Add(1); return nil }}
	started := make(chan struct{})
	shortDial := func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var shortTLS, longTLS *tls.Config
	short := mustTokenClient(t, mockToken(), apns.WithHost(server.URL), apns.WithTLSConfig(sharedTLS), apns.WithDialTimeout(20*time.Millisecond), apns.WithDialTLSContext(shortDial), apns.WithTransportWrapper(func(base http.RoundTripper) http.RoundTripper {
		shortTLS = base.(*http.Transport).TLSClientConfig
		return base
	}))
	long := mustTokenClient(t, mockToken(), apns.WithHost(server.URL), apns.WithTLSConfig(sharedTLS), apns.WithDialTimeout(time.Second), apns.WithTransportWrapper(func(base http.RoundTripper) http.RoundTripper {
		longTLS = base.(*http.Transport).TLSClientConfig
		return base
	}))
	defer short.CloseIdleConnections()
	defer long.CloseIdleConnections()
	if shortTLS == longTLS || shortTLS == sharedTLS || longTLS == sharedTLS {
		t.Fatal("clients share mutable TLS configuration")
	}
	if sharedTLS.MinVersion != 0 {
		t.Fatal("constructor changed caller's TLS configuration")
	}
	shortResult := make(chan error, 1)
	go func() { _, err := short.Push(context.Background(), mockNotification()); shortResult <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("short client's dialer did not start")
	}
	response, err := long.Push(context.Background(), mockNotification())
	if err != nil || response == nil || !response.Success() {
		t.Fatalf("independent default dialer = %v, %v", response, err)
	}
	if err := <-shortResult; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("short dialer = %v, want deadline exceeded", err)
	}
	if verified.Load() != 1 {
		t.Errorf("custom TLS verification calls = %d, want 1", verified.Load())
	}
	if len(sharedTLS.NextProtos) != 2 || sharedTLS.NextProtos[0] != "h2" || sharedTLS.NextProtos[1] != "http/1.1" {
		t.Fatalf("constructor or transport changed caller's ALPN settings: %v", sharedTLS.NextProtos)
	}
}

func TestClientManagerForwardsClientOptions(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(200 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	var transport *http.Transport
	manager, err := apns.NewClientManager(apns.ManagerConfig{Host: server.URL, ClientOptions: []apns.ClientOption{
		apns.WithTimeout(20 * time.Millisecond), apns.WithReadIdleTimeout(0), apns.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig),
		apns.WithTransportWrapper(func(base http.RoundTripper) http.RoundTripper { transport = base.(*http.Transport); return base }),
	}})
	if err != nil {
		t.Fatal(err)
	}
	client, err := manager.Get(mockCert())
	if err != nil {
		t.Fatal(err)
	}
	defer manager.CloseIdleConnections()
	if client.Host() != server.URL || transport == nil || transport.HTTP2.SendPingTimeout != 0 {
		t.Fatalf("manager did not apply transport options: client=%v transport=%v", client, transport)
	}
	if _, err := client.Push(context.Background(), mockNotification()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("manager client timeout = %v, want deadline exceeded", err)
	}
}

func TestTLSConfigVerificationCannotDisableHTTP2(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("non-HTTP/2 endpoint received a push") }))
	server.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		cfg := server.TLS.Clone()
		cfg.GetConfigForClient = nil
		cfg.NextProtos = nil
		return cfg, nil
	}}
	server.StartTLS()
	defer server.Close()
	var verified atomic.Int32
	client := mustTokenClient(t, mockToken(), apns.WithHost(server.URL), apns.WithTLSConfig(&tls.Config{
		RootCAs:          server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs,
		VerifyConnection: func(tls.ConnectionState) error { verified.Add(1); return nil },
	}))
	defer client.CloseIdleConnections()
	if _, err := client.Push(context.Background(), mockNotification()); !errors.Is(err, apns.ErrHTTP2Required) {
		t.Fatalf("push error = %v, want HTTP/2 rejection", err)
	}
	if verified.Load() != 1 {
		t.Fatal("custom TLS verifier did not run")
	}
}

func TestClientManagerRejectsSharedHTTPClient(t *testing.T) {
	manager, err := apns.NewClientManager(apns.ManagerConfig{Host: apns.HostDevelopment, ClientOptions: []apns.ClientOption{apns.WithHTTPClient(&http.Client{})}})
	if err == nil || manager != nil {
		t.Fatalf("constructor = %v, %v, want shared-client error", manager, err)
	}
}
