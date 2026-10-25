package apns2_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	apns "github.com/jaakkonakaza/apns2"
)

func TestTransportAuthenticationAndReuse(t *testing.T) {
	for _, tokenAuth := range []bool{false, true} {
		name := "certificate"
		if tokenAuth {
			name = "token"
		}
		t.Run(name, func(t *testing.T) {
			var connections atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 {
					t.Errorf("protocol = %s", r.Proto)
				}
				if tokenAuth {
					if r.Header.Get("Authorization") == "" {
						t.Error("missing token authorization")
					}
				} else if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
					t.Error("missing client certificate")
				}
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(http.StatusOK)
			}))
			server.EnableHTTP2 = true
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			if !tokenAuth {
				server.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
			}
			server.StartTLS()
			defer server.Close()
			options := []apns.ClientOption{
				apns.WithHost(server.URL),
				apns.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig),
			}
			var client *apns.Client
			if tokenAuth {
				client = apns.NewTokenClient(mockToken(), options...)
			} else {
				client = apns.NewClient(server.TLS.Certificates[0], options...)
			}
			defer client.CloseIdleConnections()
			for range 2 {
				response, err := client.Push(context.Background(), mockNotification())
				if err != nil || response == nil || !response.Sent() {
					t.Fatalf("push = %v, %v", response, err)
				}
			}
			if got := connections.Load(); got != 1 {
				t.Errorf("connections = %d, want 1", got)
			}
		})
	}
}

func newConnectProxy(t *testing.T, secure bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	return newDelayedConnectProxy(t, secure, 0)
}

// newDelayedConnectProxy waits for delay before answering CONNECT.
func newDelayedConnectProxy(t *testing.T, secure bool, delay time.Duration) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var connects atomic.Int32
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Errorf("proxy method = %s", r.Method)
			http.Error(w, "CONNECT required", http.StatusBadRequest)
			return
		}
		target, err := net.DialTimeout("tcp", r.Host, time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer func() { _ = target.Close() }()
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("proxy cannot hijack connection")
			return
		}
		conn, buf, err := hijacker.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		connects.Add(1)
		time.Sleep(delay)
		if _, err := buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			t.Error(err)
			return
		}
		if err := buf.Flush(); err != nil {
			t.Error(err)
			return
		}
		done := make(chan struct{})
		go func() { _, _ = io.Copy(target, buf); _ = target.Close(); close(done) }()
		_, _ = io.Copy(conn, target)
		_ = conn.Close()
		<-done
	}))
	if secure {
		proxy.StartTLS()
	} else {
		proxy.Start()
	}
	t.Cleanup(proxy.Close)
	return proxy, &connects
}

func TestTransportProxyProtocols(t *testing.T) {
	for _, custom := range []bool{false, true} {
		for _, secure := range []bool{false, true} {
			for _, protocol := range []string{"h2", "http/1.1", "no-alpn"} {
				t.Run(fmt.Sprintf("custom=%t/https-proxy=%t/origin=%s", custom, secure, protocol), func(t *testing.T) {
					var requests atomic.Int32
					server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						requests.Add(1)
						if r.ProtoMajor != 2 {
							t.Errorf("protocol = %s, want HTTP/2", r.Proto)
						}
						w.WriteHeader(http.StatusOK)
					}))
					server.EnableHTTP2 = protocol == "h2"
					if protocol == "no-alpn" {
						server.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
							cfg := server.TLS.Clone()
							cfg.GetConfigForClient = nil
							cfg.NextProtos = nil
							return cfg, nil
						}}
					}
					server.StartTLS()
					defer server.Close()
					proxy, connects := newConnectProxy(t, secure)
					proxyURL, err := url.Parse(proxy.URL)
					if err != nil {
						t.Fatal(err)
					}
					var options []apns.ClientOption
					if custom {
						options = append(options, apns.WithDialTLSContext(dialWrappedTLS))
					}
					roots := server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs.Clone()
					if secure {
						roots.AddCert(proxy.Certificate())
					}
					options = append(options, apns.WithHost(server.URL), apns.WithProxy(http.ProxyURL(proxyURL)), apns.WithTLSConfig(&tls.Config{RootCAs: roots}))
					client := apns.NewTokenClient(mockToken(), options...)
					defer client.CloseIdleConnections()
					response, err := client.Push(context.Background(), mockNotification())
					if protocol == "h2" {
						if err != nil || response == nil || !response.Sent() {
							t.Fatalf("proxy push = %v, %v", response, err)
						}
						if requests.Load() != 1 {
							t.Errorf("origin requests = %d, want 1", requests.Load())
						}
					} else {
						if err == nil {
							t.Fatalf("accepted %s origin: %v", protocol, response)
						}
						if requests.Load() != 0 {
							t.Errorf("origin received %d requests, want 0", requests.Load())
						}
					}
					if connects.Load() != 1 {
						t.Errorf("CONNECT requests = %d, want 1", connects.Load())
					}
				})
			}
		}
	}
}

func TestTransportRejectsRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("redirect followed") }))
	defer target.Close()
	for _, location := range []string{target.URL, ""} {
		t.Run(map[bool]string{true: "with-location", false: "without-location"}[location != ""], func(t *testing.T) {
			server := newRedirectServer(t, location)
			client := apns.NewTokenClient(mockToken(), apns.WithHost(server.URL), apns.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig))
			defer client.CloseIdleConnections()
			response, err := client.Push(context.Background(), mockNotification())
			if location == "" {
				// Without a Location there is nothing to follow, so the status is reported as is.
				if err != nil || response == nil || response.StatusCode != http.StatusTemporaryRedirect || response.Sent() {
					t.Fatalf("redirect without location = %v, %v", response, err)
				}
				return
			}
			if _, ok := errors.AsType[*url.Error](err); !ok {
				t.Fatalf("redirect error = %T %v, want *url.Error", err, err)
			}
		})
	}
}

func TestTransportKeepsCallerRedirectPolicy(t *testing.T) {
	server := newRedirectServer(t, "https://example.com/elsewhere")
	httpClient := server.Client()
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client := apns.NewTokenClient(mockToken(), apns.WithHost(server.URL), apns.WithHTTPClient(httpClient))
	defer client.CloseIdleConnections()
	response, err := client.Push(context.Background(), mockNotification())
	if err != nil || response == nil || response.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("caller redirect policy overridden: %v, %v", response, err)
	}
}

func newRedirectServer(t *testing.T, location string) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func TestTransportVerifiesServerCertificate(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("untrusted server received a push")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := apns.NewTokenClient(mockToken())
	defer client.CloseIdleConnections()
	client.Host = server.URL
	if _, err := client.Push(context.Background(), mockNotification()); err == nil {
		t.Fatal("accepted untrusted server certificate")
	}
}

type wrappedTLSConn struct{ *tls.Conn }

func TestTransportWrappedTLSConnection(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("protocol = %s", r.Proto)
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := apns.NewTokenClient(mockToken(), apns.WithHost(server.URL), apns.WithDialTLSContext(dialWrappedTLS), apns.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig))
	defer client.CloseIdleConnections()
	response, err := client.Push(context.Background(), mockNotification())
	if err != nil || response == nil || !response.Sent() {
		t.Fatalf("wrapped TLS push = %v, %v", response, err)
	}
}

func TestTransportDirectALPN(t *testing.T) {
	offered := make(chan []string, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("protocol = %s", r.Proto)
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		offered <- append([]string(nil), hello.SupportedProtos...)
		return nil, nil
	}}
	server.StartTLS()
	defer server.Close()
	client := apns.NewTokenClient(mockToken(), apns.WithHost(server.URL), apns.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig))
	defer client.CloseIdleConnections()
	response, err := client.Push(context.Background(), mockNotification())
	if err != nil || response == nil || !response.Sent() {
		t.Fatalf("direct push = %v, %v", response, err)
	}
	if protocols := <-offered; len(protocols) != 1 || protocols[0] != "h2" {
		t.Errorf("offered ALPN = %v, want [h2]", protocols)
	}
}

func TestTransportDialerReceivesDeadline(t *testing.T) {
	const timeout = 20 * time.Millisecond
	stopped := make(chan struct{})
	dial := func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
		defer close(stopped)
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > timeout {
			return nil, errors.New("dial timeout was not applied")
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	client := apns.NewTokenClient(mockToken(), apns.WithDialTimeout(timeout), apns.WithDialTLSContext(dial))
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := client.Push(ctx, mockNotification()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("push error = %v, want dial deadline exceeded", err)
	}
	if ctx.Err() != nil {
		t.Fatal("request context expired before dial timeout")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("TLS dialer did not stop")
	}
}

// Wrappers such as tracing transports must not disable HTTP/2 enforcement.
func TestTransportWrappedRoundTripperEnforcesHTTP2(t *testing.T) {
	for _, protocol := range []string{"h2", "http/1.1", "plaintext"} {
		t.Run(protocol, func(t *testing.T) {
			var requests atomic.Int32
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusOK)
			})
			server := httptest.NewUnstartedServer(handler)
			server.EnableHTTP2 = protocol == "h2"
			if protocol == "plaintext" {
				server.Start()
			} else {
				server.StartTLS()
			}
			defer server.Close()
			options := []apns.ClientOption{apns.WithHost(server.URL)}
			if protocol != "plaintext" {
				options = append(options, apns.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig))
			}
			native := apns.NewTokenClient(mockToken(), options...)
			defer native.CloseIdleConnections()
			transport := apns.HTTPClientForTesting(native).Transport
			var wrapped atomic.Int32
			httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				wrapped.Add(1)
				return transport.RoundTrip(r)
			})}
			client := apns.NewTokenClient(mockToken(), apns.WithHost(server.URL), apns.WithHTTPClient(httpClient))
			response, err := client.Push(context.Background(), mockNotification())
			if wrapped.Load() != 1 {
				t.Fatalf("wrapper calls = %d, want 1", wrapped.Load())
			}
			if protocol == "h2" {
				if err != nil || response == nil || !response.Sent() {
					t.Fatalf("wrapped h2 push = %v, %v", response, err)
				}
				return
			}
			// An HTTP/1.1-only server refuses the h2-only ALPN offer during the handshake.
			if err == nil || protocol == "plaintext" && !errors.Is(err, apns.ErrHTTP2Required) {
				t.Fatalf("wrapped %s push error = %v", protocol, err)
			}
			if requests.Load() != 0 {
				t.Errorf("origin received %d requests, want 0", requests.Load())
			}
		})
	}
}

func TestTransportProxyOriginALPN(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("https-proxy=%t", secure), func(t *testing.T) {
			offered := make(chan []string, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			server.EnableHTTP2 = true
			server.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				offered <- append([]string(nil), hello.SupportedProtos...)
				return nil, nil
			}}
			server.StartTLS()
			defer server.Close()
			proxy, _ := newConnectProxy(t, secure)
			proxyURL, err := url.Parse(proxy.URL)
			if err != nil {
				t.Fatal(err)
			}
			roots := server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs.Clone()
			if secure {
				roots.AddCert(proxy.Certificate())
			}
			client := apns.NewTokenClient(mockToken(), apns.WithHost(server.URL), apns.WithProxy(http.ProxyURL(proxyURL)), apns.WithTLSConfig(&tls.Config{RootCAs: roots}))
			defer client.CloseIdleConnections()
			response, err := client.Push(context.Background(), mockNotification())
			if err != nil || response == nil || !response.Sent() {
				t.Fatalf("proxy push = %v, %v", response, err)
			}
			if protocols := <-offered; len(protocols) != 1 || protocols[0] != "h2" {
				t.Errorf("origin offered ALPN = %v, want [h2]", protocols)
			}
		})
	}
}

// One dial timeout covers the proxy dial, CONNECT, and origin handshake.
func TestTransportProxyDialBudget(t *testing.T) {
	const budget = 400 * time.Millisecond
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("https-proxy=%t", secure), func(t *testing.T) {
			// The origin accepts TCP but never answers the TLS handshake.
			origin, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = origin.Close() }()
			go func() {
				for {
					conn, err := origin.Accept()
					if err != nil {
						return
					}
					t.Cleanup(func() { _ = conn.Close() })
				}
			}()
			proxy, _ := newDelayedConnectProxy(t, secure, budget*7/8)
			proxyURL, err := url.Parse(proxy.URL)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if secure {
				roots.AddCert(proxy.Certificate())
			}
			client := apns.NewTokenClient(mockToken(), apns.WithDialTimeout(budget), apns.WithHost("https://"+origin.Addr().String()), apns.WithProxy(http.ProxyURL(proxyURL)), apns.WithTLSConfig(&tls.Config{RootCAs: roots}))
			defer client.CloseIdleConnections()
			started := time.Now()
			if _, err := client.Push(context.Background(), mockNotification()); err == nil {
				t.Fatal("stalled origin accepted")
			}
			// Separate budgets would take about budget*7/8 + budget.
			if elapsed := time.Since(started); elapsed >= budget*3/2 {
				t.Fatalf("proxied dial took %s with dial timeout=%s", elapsed, budget)
			}
		})
	}
}

// The proxy deadline is cleared after the origin handshake.
func TestTransportProxyConnectionOutlivesDialBudget(t *testing.T) {
	const budget = 200 * time.Millisecond
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("https-proxy=%t", secure), func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			proxy, connects := newConnectProxy(t, secure)
			proxyURL, err := url.Parse(proxy.URL)
			if err != nil {
				t.Fatal(err)
			}
			roots := server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs.Clone()
			if secure {
				roots.AddCert(proxy.Certificate())
			}
			client := apns.NewTokenClient(mockToken(), apns.WithHost(server.URL), apns.WithProxy(http.ProxyURL(proxyURL)), apns.WithTLSConfig(&tls.Config{RootCAs: roots}), apns.WithDialTimeout(budget))
			defer client.CloseIdleConnections()
			for i := range 2 {
				response, err := client.Push(context.Background(), mockNotification())
				if err != nil || response == nil || !response.Sent() {
					t.Fatalf("push %d = %v, %v", i, response, err)
				}
				time.Sleep(budget * 2)
			}
			if connects.Load() != 1 {
				t.Errorf("CONNECT requests = %d, want 1", connects.Load())
			}
		})
	}
}

func TestTransportZeroDialTimeout(t *testing.T) {
	for _, route := range []string{"direct", "http-proxy", "https-proxy"} {
		t.Run(route, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 {
					t.Errorf("protocol = %s", r.Proto)
				}
				w.WriteHeader(http.StatusOK)
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			roots := server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs.Clone()
			options := []apns.ClientOption{apns.WithDialTimeout(0), apns.WithHost(server.URL)}
			if route != "direct" {
				proxy, _ := newConnectProxy(t, route == "https-proxy")
				proxyURL, err := url.Parse(proxy.URL)
				if err != nil {
					t.Fatal(err)
				}
				options = append(options, apns.WithProxy(http.ProxyURL(proxyURL)))
				if route == "https-proxy" {
					roots.AddCert(proxy.Certificate())
				}
			}
			options = append(options, apns.WithTLSConfig(&tls.Config{RootCAs: roots}))
			client := apns.NewTokenClient(mockToken(), options...)
			defer client.CloseIdleConnections()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			response, err := client.Push(ctx, mockNotification())
			if err != nil || response == nil || !response.Sent() {
				t.Fatalf("zero-timeout push = %v, %v", response, err)
			}
		})
	}
}

func dialWrappedTLS(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
	conn, err := (&tls.Dialer{Config: cfg}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &wrappedTLSConn{conn.(*tls.Conn)}, nil
}

func TestTransportIdlePings(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	defer fixture.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: fixture.TLS.Certificates,
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	stop := make(chan struct{})
	defer close(stop)
	pings := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			pings <- err
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			pings <- err
			return
		}
		preface := make([]byte, 24)
		if _, err := io.ReadFull(conn, preface); err != nil {
			pings <- err
			return
		}
		if string(preface) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
			pings <- fmt.Errorf("invalid HTTP/2 preface")
			return
		}
		// Empty SETTINGS lets the client start a request without a response from the peer.
		if _, err := conn.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0}); err != nil {
			pings <- err
			return
		}
		count := 0
		for count < 2 {
			var header [9]byte
			if _, err := io.ReadFull(conn, header[:]); err != nil {
				pings <- err
				return
			}
			size := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
			if size > 1<<20 {
				pings <- fmt.Errorf("unexpected frame size %d", size)
				return
			}
			body := make([]byte, size)
			if _, err := io.ReadFull(conn, body); err != nil {
				pings <- err
				return
			}
			if header[3] != 6 || header[4]&1 != 0 {
				continue
			}
			if size != 8 || binary.BigEndian.Uint32(header[5:]) != 0 {
				pings <- fmt.Errorf("invalid PING frame")
				return
			}
			// Echo the opaque payload with ACK set, keeping the connection healthy.
			header[4] = 1
			if _, err := conn.Write(append(header[:], body...)); err != nil {
				pings <- err
				return
			}
			count++
		}
		pings <- nil
		<-stop
	}()
	client := apns.NewTokenClient(mockToken(),
		apns.WithHost("https://"+listener.Addr().String()),
		apns.WithTLSConfig(fixture.Client().Transport.(*http.Transport).TLSClientConfig),
		apns.WithReadIdleTimeout(20*time.Millisecond),
	)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pushed := make(chan error, 1)
	go func() { _, err := client.Push(ctx, mockNotification()); pushed <- err }()
	select {
	case err := <-pings:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("HTTP/2 idle PINGs were not received")
	}
	cancel()
	select {
	case err := <-pushed:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("push error = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("push did not stop after cancellation")
	}
}

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
