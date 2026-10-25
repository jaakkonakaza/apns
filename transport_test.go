package apns2_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	apns "github.com/sideshow/apns2"
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
			var client *apns.Client
			if tokenAuth {
				client = apns.NewTokenClient(mockToken())
			} else {
				client = apns.NewClient(server.TLS.Certificates[0])
			}
			defer client.CloseIdleConnections()
			client.Host = server.URL
			transport := client.HTTPClient.Transport.(*http.Transport)
			transport.TLSClientConfig.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
			for range 2 {
				response, err := client.Push(mockNotification())
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
					if custom {
						original := apns.DialTLS
						t.Cleanup(func() { apns.DialTLS = original })
						apns.DialTLS = func(network, addr string, cfg *tls.Config) (net.Conn, error) {
							conn, err := tls.Dial(network, addr, cfg)
							if err != nil {
								return nil, err
							}
							return &wrappedTLSConn{conn}, nil
						}
					}
					client := apns.NewTokenClient(mockToken())
					defer client.CloseIdleConnections()
					client.Host = server.URL
					transport := client.HTTPClient.Transport.(*http.Transport)
					transport.Proxy = http.ProxyURL(proxyURL)
					roots := server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs.Clone()
					if secure {
						roots.AddCert(proxy.Certificate())
					}
					transport.TLSClientConfig.RootCAs = roots
					response, err := client.Push(mockNotification())
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
			client := apns.NewTokenClient(mockToken())
			defer client.CloseIdleConnections()
			client.Host = server.URL
			client.HTTPClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
			response, err := client.Push(mockNotification())
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
	client := apns.NewTokenClient(mockToken())
	defer client.CloseIdleConnections()
	client.Host = server.URL
	client.HTTPClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	client.HTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Push(mockNotification())
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
	if _, err := client.Push(mockNotification()); err == nil {
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
	original := apns.DialTLS
	t.Cleanup(func() { apns.DialTLS = original })
	apns.DialTLS = func(network, addr string, cfg *tls.Config) (net.Conn, error) {
		conn, err := tls.Dial(network, addr, cfg)
		if err != nil {
			return nil, err
		}
		return &wrappedTLSConn{conn}, nil
	}
	client := apns.NewTokenClient(mockToken())
	defer client.CloseIdleConnections()
	client.Host = server.URL
	client.HTTPClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	response, err := client.Push(mockNotification())
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
	client := apns.NewTokenClient(mockToken())
	defer client.CloseIdleConnections()
	client.Host = server.URL
	client.HTTPClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	response, err := client.Push(mockNotification())
	if err != nil || response == nil || !response.Sent() {
		t.Fatalf("direct push = %v, %v", response, err)
	}
	if protocols := <-offered; len(protocols) != 1 || protocols[0] != "h2" {
		t.Errorf("offered ALPN = %v, want [h2]", protocols)
	}
}

func TestTransportDefaultDialTLSCanBeWrapped(t *testing.T) {
	if apns.DialTLS == nil {
		t.Fatal("DialTLS has no default")
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	original := apns.DialTLS
	t.Cleanup(func() { apns.DialTLS = original })
	var dials atomic.Int32
	apns.DialTLS = func(network, addr string, cfg *tls.Config) (net.Conn, error) {
		dials.Add(1)
		return original(network, addr, cfg)
	}
	client := apns.NewTokenClient(mockToken())
	defer client.CloseIdleConnections()
	client.Host = server.URL
	client.HTTPClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	response, err := client.Push(mockNotification())
	if err != nil || response == nil || !response.Sent() {
		t.Fatalf("wrapped default dial push = %v, %v", response, err)
	}
	if dials.Load() != 1 {
		t.Errorf("dials = %d, want 1", dials.Load())
	}
}

func TestTransportCanceledDialTLSHook(t *testing.T) {
	original := apns.DialTLS
	t.Cleanup(func() { apns.DialTLS = original })
	release := make(chan struct{})
	closed := make(chan struct{})
	apns.DialTLS = func(string, string, *tls.Config) (net.Conn, error) {
		<-release
		client, server := net.Pipe()
		_ = server.Close()
		return &closeNotifyConn{Conn: client, closed: closed}, nil
	}
	client := apns.NewTokenClient(mockToken())
	defer client.CloseIdleConnections()
	client.Host = "https://127.0.0.1:1"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := client.PushWithContext(ctx, mockNotification()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
	close(release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("connection from abandoned dial was not closed")
	}
}

type closeNotifyConn struct {
	net.Conn
	closed chan struct{}
}

func (c *closeNotifyConn) Close() error {
	close(c.closed)
	return c.Conn.Close()
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
			client := apns.NewTokenClient(mockToken())
			defer client.CloseIdleConnections()
			client.Host = server.URL
			transport := client.HTTPClient.Transport.(*http.Transport)
			if protocol != "plaintext" {
				transport.TLSClientConfig.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
			}
			var wrapped atomic.Int32
			client.HTTPClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				wrapped.Add(1)
				return transport.RoundTrip(r)
			})
			response, err := client.Push(mockNotification())
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
			client := apns.NewTokenClient(mockToken())
			defer client.CloseIdleConnections()
			client.Host = server.URL
			transport := client.HTTPClient.Transport.(*http.Transport)
			transport.Proxy = http.ProxyURL(proxyURL)
			roots := server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs.Clone()
			if secure {
				roots.AddCert(proxy.Certificate())
			}
			transport.TLSClientConfig.RootCAs = roots
			response, err := client.Push(mockNotification())
			if err != nil || response == nil || !response.Sent() {
				t.Fatalf("proxy push = %v, %v", response, err)
			}
			if protocols := <-offered; len(protocols) != 1 || protocols[0] != "h2" {
				t.Errorf("origin offered ALPN = %v, want [h2]", protocols)
			}
		})
	}
}

// One TLSDialTimeout covers the proxy dial, CONNECT, and origin handshake.
func TestTransportProxyDialBudget(t *testing.T) {
	const budget = 400 * time.Millisecond
	original := apns.TLSDialTimeout
	apns.TLSDialTimeout = budget
	t.Cleanup(func() { apns.TLSDialTimeout = original })
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
			client := apns.NewTokenClient(mockToken())
			defer client.CloseIdleConnections()
			client.Host = "https://" + origin.Addr().String()
			transport := client.HTTPClient.Transport.(*http.Transport)
			transport.Proxy = http.ProxyURL(proxyURL)
			if secure {
				roots := x509.NewCertPool()
				roots.AddCert(proxy.Certificate())
				transport.TLSClientConfig.RootCAs = roots
			}
			started := time.Now()
			if _, err := client.Push(mockNotification()); err == nil {
				t.Fatal("stalled origin accepted")
			}
			// Separate budgets would take about budget*7/8 + budget.
			if elapsed := time.Since(started); elapsed >= budget*3/2 {
				t.Fatalf("proxied dial took %s with TLSDialTimeout=%s", elapsed, budget)
			}
		})
	}
}

// The proxy deadline is cleared after the origin handshake.
func TestTransportProxyConnectionOutlivesDialBudget(t *testing.T) {
	const budget = 200 * time.Millisecond
	original := apns.TLSDialTimeout
	apns.TLSDialTimeout = budget
	t.Cleanup(func() { apns.TLSDialTimeout = original })
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
			client := apns.NewTokenClient(mockToken())
			defer client.CloseIdleConnections()
			client.Host = server.URL
			transport := client.HTTPClient.Transport.(*http.Transport)
			transport.Proxy = http.ProxyURL(proxyURL)
			roots := server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs.Clone()
			if secure {
				roots.AddCert(proxy.Certificate())
			}
			transport.TLSClientConfig.RootCAs = roots
			for i := range 2 {
				response, err := client.Push(mockNotification())
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
	originalTimeout := apns.TLSDialTimeout
	apns.TLSDialTimeout = 0
	t.Cleanup(func() { apns.TLSDialTimeout = originalTimeout })
	for _, nilHook := range []bool{false, true} {
		for _, route := range []string{"direct", "http-proxy", "https-proxy"} {
			t.Run(fmt.Sprintf("nil-hook=%t/%s", nilHook, route), func(t *testing.T) {
				originalHook := apns.DialTLS
				if nilHook {
					apns.DialTLS = nil
				}
				t.Cleanup(func() { apns.DialTLS = originalHook })
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.ProtoMajor != 2 {
						t.Errorf("protocol = %s", r.Proto)
					}
					w.WriteHeader(http.StatusOK)
				}))
				server.EnableHTTP2 = true
				server.StartTLS()
				defer server.Close()
				client := apns.NewTokenClient(mockToken())
				defer client.CloseIdleConnections()
				client.Host = server.URL
				transport := client.HTTPClient.Transport.(*http.Transport)
				roots := server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs.Clone()
				if route != "direct" {
					proxy, _ := newConnectProxy(t, route == "https-proxy")
					proxyURL, err := url.Parse(proxy.URL)
					if err != nil {
						t.Fatal(err)
					}
					transport.Proxy = http.ProxyURL(proxyURL)
					if route == "https-proxy" {
						roots.AddCert(proxy.Certificate())
					}
				}
				transport.TLSClientConfig.RootCAs = roots
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				response, err := client.PushWithContext(ctx, mockNotification())
				if err != nil || response == nil || !response.Sent() {
					t.Fatalf("zero-timeout push = %v, %v", response, err)
				}
			})
		}
	}
}
