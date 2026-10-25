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
	short := apns.NewTokenClient(mockToken(), apns.WithHost(server.URL), tlsOption, apns.WithTimeout(20*time.Millisecond))
	long := apns.NewTokenClient(mockToken(), apns.WithHost(server.URL), tlsOption, apns.WithTimeout(time.Second))
	defer short.CloseIdleConnections()
	defer long.CloseIdleConnections()
	shortResult := make(chan error, 1)
	go func() { _, err := short.Push(context.Background(), mockNotification()); shortResult <- err }()
	response, err := long.Push(context.Background(), mockNotification())
	if err != nil || response == nil || !response.Sent() {
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
	short := apns.NewTokenClient(mockToken(), apns.WithHost(server.URL), apns.WithTLSConfig(sharedTLS), apns.WithDialTimeout(20*time.Millisecond), apns.WithDialTLSContext(shortDial))
	long := apns.NewTokenClient(mockToken(), apns.WithHost(server.URL), apns.WithTLSConfig(sharedTLS), apns.WithDialTimeout(time.Second))
	defer short.CloseIdleConnections()
	defer long.CloseIdleConnections()
	shortTLS := apns.HTTPClientForTesting(short).Transport.(*http.Transport).TLSClientConfig
	longTLS := apns.HTTPClientForTesting(long).Transport.(*http.Transport).TLSClientConfig
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
	if err != nil || response == nil || !response.Sent() {
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
	manager := apns.NewClientManager(apns.WithHost(apns.HostProduction), apns.WithTimeout(3*time.Second), apns.WithReadIdleTimeout(0))
	client := manager.Get(mockCert())
	if client == nil {
		t.Fatal("manager did not construct a client")
	}
	defer client.CloseIdleConnections()
	if client.Host != apns.HostProduction || apns.HTTPClientForTesting(client).Timeout != 3*time.Second {
		t.Fatalf("manager did not apply client options: %+v", client)
	}
	if apns.HTTPClientForTesting(client).Transport.(*http.Transport).HTTP2.SendPingTimeout != 0 {
		t.Fatal("manager did not disable idle pings")
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
	client := apns.NewTokenClient(mockToken(), apns.WithHost(server.URL), apns.WithTLSConfig(&tls.Config{
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
	defer func() {
		if recover() == nil {
			t.Fatal("manager accepted a shared custom HTTP client")
		}
	}()
	apns.NewClientManager(apns.WithHTTPClient(&http.Client{}))
}
