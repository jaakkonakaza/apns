package apns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func transportCertificate(t testing.TB) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "transport fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost", "api.sandbox.push.apple.com"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func transportServer(t testing.TB, protocol string, handler http.Handler, configure ...func(*httptest.Server)) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	certificate, roots := transportCertificate(t)
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = protocol == "h2"
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	if protocol == "none" {
		server.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{Certificates: []tls.Certificate{certificate}}, nil
		}
	}
	for _, setup := range configure {
		setup(server)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, roots
}

func transportDo(t *testing.T, tr *http.Transport, ctx context.Context, endpoint string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "bearer synthetic")
	resp, err := tr.RoundTrip(prepareRequest(req, tr.Proxy != nil))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, err = io.Copy(io.Discard, resp.Body)
	return err
}

func transportFrom(t *testing.T, cfg Config, certs ...tls.Certificate) *http.Transport {
	t.Helper()
	tr, err := makeTransport(&tls.Config{Certificates: certs}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tr.CloseIdleConnections)
	return tr
}

func TestTransportOwnsTLSAndReusesConnections(t *testing.T) {
	for _, certificateAuth := range []bool{false, true} {
		t.Run(fmt.Sprint(certificateAuth), func(t *testing.T) {
			var connections atomic.Int32
			offered := make(chan []string, 2)
			server, roots := transportServer(t, "h2", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 || r.TLS.NegotiatedProtocol != "h2" {
					t.Error("origin is not HTTP/2")
				}
				if certificateAuth && len(r.TLS.PeerCertificates) != 1 {
					t.Error("missing constructor certificate")
				}
				if !certificateAuth && r.Header.Get("Authorization") != "bearer synthetic" {
					t.Error("missing bearer")
				}
				w.WriteHeader(http.StatusOK)
			}), func(server *httptest.Server) {
				server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateNew {
						connections.Add(1)
					}
				}
				server.TLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					offered <- append([]string(nil), hello.SupportedProtos...)
					return nil, nil
				}
				if certificateAuth {
					server.TLS.ClientAuth = tls.RequireAnyClientCert
				}
			})
			var rawCalls atomic.Int32
			cfg := Config{Environment: Sandbox, Transport: TransportConfig{RootCAs: roots, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				rawCalls.Add(1)
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			}}}
			var certificates []tls.Certificate
			if certificateAuth {
				certificates = server.TLS.Certificates
			}
			tr := transportFrom(t, cfg, certificates...)
			for range 2 {
				if err := transportDo(t, tr, context.Background(), server.URL); err != nil {
					t.Fatal(err)
				}
			}
			if connections.Load() != 1 || rawCalls.Load() != 1 {
				t.Fatalf("connections=%d raw calls=%d", connections.Load(), rawCalls.Load())
			}
			if protocols := <-offered; len(protocols) != 1 || protocols[0] != "h2" {
				t.Fatalf("offered ALPN=%v", protocols)
			}
			tr.CloseIdleConnections()
			if err := transportDo(t, tr, context.Background(), server.URL); err != nil {
				t.Fatal(err)
			}
			if connections.Load() != 2 {
				t.Fatalf("CloseIdleConnections did not permit a fresh connection: connections=%d, raw calls=%d", connections.Load(), rawCalls.Load())
			}
		})
	}
}

func TestTransportRejectsUntrustedAndNonHTTP2Origins(t *testing.T) {
	for _, protocol := range []string{"h2", "http/1.1", "none"} {
		t.Run(protocol, func(t *testing.T) {
			var requests atomic.Int32
			server, roots := transportServer(t, protocol, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
			cfg := Config{Environment: Sandbox}
			if protocol != "h2" {
				cfg.Transport.RootCAs = roots
			}
			err := transportDo(t, transportFrom(t, cfg), context.Background(), server.URL)
			if err == nil || requests.Load() != 0 {
				t.Fatalf("untrusted/non-h2 accepted: %v, requests=%d", err, requests.Load())
			}
		})
	}
}

func transportProxy(t *testing.T, secure bool, delay time.Duration, inspect func(*http.Request)) (*httptest.Server, *x509.CertPool, *atomic.Int32) {
	t.Helper()
	var connects atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Error("proxy received non-CONNECT request")
			http.Error(w, "CONNECT required", 400)
			return
		}
		if inspect != nil {
			inspect(r)
		}
		target, err := net.DialTimeout("tcp", r.Host, time.Second)
		if err != nil {
			http.Error(w, "unreachable fixture", http.StatusBadGateway)
			return
		}
		defer func() { _ = target.Close() }()
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		connects.Add(1)
		if delay != 0 {
			time.Sleep(delay)
		}
		if _, err = buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err = buf.Flush(); err != nil {
			return
		}
		done := make(chan struct{})
		go func() { _, _ = io.Copy(target, buf); _ = target.Close(); close(done) }()
		_, _ = io.Copy(conn, target)
		_ = conn.Close()
		<-done
	})
	if secure {
		server, roots := transportServer(t, "http/1.1", handler, func(server *httptest.Server) { server.TLS.ClientAuth = tls.RequestClientCert })
		return server, roots, &connects
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server, nil, &connects
}

func TestTransportProxyIsolationAndOriginHTTP2(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, protocol := range []string{"h2", "http/1.1", "none"} {
			t.Run(fmt.Sprintf("secure=%t/%s", secure, protocol), func(t *testing.T) {
				var requests atomic.Int32
				origin, roots := transportServer(t, protocol, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.ProtoMajor != 2 || len(r.TLS.PeerCertificates) != 1 {
						t.Error("origin lost h2 or constructor certificate")
					}
					w.WriteHeader(200)
				}), func(server *httptest.Server) { server.TLS.ClientAuth = tls.RequireAnyClientCert })
				proxy, proxyRoots, connects := transportProxy(t, secure, 0, func(r *http.Request) {
					if r.Header.Get("Authorization") != "" {
						t.Error("proxy received provider bearer")
					}
					if secure && len(r.TLS.PeerCertificates) != 0 {
						t.Error("proxy received origin certificate")
					}
				})
				proxyURL, _ := url.Parse(proxy.URL)
				cfg := Config{Environment: Sandbox, Transport: TransportConfig{RootCAs: roots, ProxyRootCAs: proxyRoots, Proxy: http.ProxyURL(proxyURL)}}
				tr := transportFrom(t, cfg, origin.TLS.Certificates...)
				err := transportDo(t, tr, context.Background(), origin.URL)
				if protocol == "h2" {
					if err != nil || requests.Load() != 1 {
						t.Fatalf("proxy request failed: %v requests=%d", err, requests.Load())
					}
				} else if err == nil || requests.Load() != 0 {
					t.Fatalf("non-h2 reached origin: %v requests=%d", err, requests.Load())
				}
				if connects.Load() != 1 {
					t.Fatalf("CONNECTs=%d", connects.Load())
				}
			})
		}
	}
}

func TestHTTPSProxyDoesNotInheritOriginTrust(t *testing.T) {
	origin, originRoots := transportServer(t, "h2", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	proxy, proxyRoots, connects := transportProxy(t, true, 0, nil)
	proxyURL, _ := url.Parse(proxy.URL)
	// Trust both certificates for the origin. The independent nil proxy pool
	// must still use system trust and reject the private proxy certificate.
	originRoots.AddCert(proxy.Certificate())
	cfg := Config{Environment: Sandbox, Transport: TransportConfig{RootCAs: originRoots, Proxy: http.ProxyURL(proxyURL)}}
	if err := transportDo(t, transportFrom(t, cfg), context.Background(), origin.URL); err == nil || connects.Load() != 0 {
		t.Fatalf("proxy inherited origin roots: %v", err)
	}
	cfg.Transport.ProxyRootCAs = proxyRoots
	if err := transportDo(t, transportFrom(t, cfg), context.Background(), origin.URL); err != nil {
		t.Fatal(err)
	}
	// Trusting only the proxy must not grant trust to the private origin.
	cfg.Transport.RootCAs = nil
	if err := transportDo(t, transportFrom(t, cfg), context.Background(), origin.URL); err == nil {
		t.Fatal("origin inherited proxy roots")
	}
}

func TestTransportRawDialDeadlineAndNilResults(t *testing.T) {
	for _, proxyScheme := range []string{"", "http", "https"} {
		t.Run("deadline/"+proxyScheme, func(t *testing.T) {
			cfg := Config{Environment: Sandbox, Transport: TransportConfig{DialTimeout: new(20 * time.Millisecond), DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 20*time.Millisecond {
					return nil, errors.New("dial deadline missing")
				}
				<-ctx.Done()
				return nil, ctx.Err()
			}}}
			if proxyScheme != "" {
				cfg.Transport.Proxy = http.ProxyURL(&url.URL{Scheme: proxyScheme, Host: "proxy.example:443"})
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := transportDo(t, transportFrom(t, cfg), ctx, "https://api.sandbox.push.apple.com"); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("dial failure=%v", err)
			}
			if ctx.Err() != nil {
				t.Fatal("request deadline preceded dial timeout")
			}
		})
		for _, typed := range []bool{false, true} {
			t.Run(fmt.Sprintf("nil/%s/%t", proxyScheme, typed), func(t *testing.T) {
				cfg := Config{Environment: Sandbox, Transport: TransportConfig{DialContext: func(context.Context, string, string) (net.Conn, error) {
					if typed {
						var c *net.TCPConn
						return c, nil
					}
					return nil, nil
				}}}
				if proxyScheme != "" {
					cfg.Transport.Proxy = http.ProxyURL(&url.URL{Scheme: proxyScheme, Host: "proxy.example:443"})
				}
				if err := transportDo(t, transportFrom(t, cfg), context.Background(), "https://api.sandbox.push.apple.com"); err == nil {
					t.Fatal("nil connection accepted")
				}
			})
		}
	}
}

func TestTransportZeroDialStillHonorsContext(t *testing.T) {
	cfg := Config{Environment: Sandbox, Transport: TransportConfig{DialTimeout: new(time.Duration(0)), DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := transportDo(t, transportFrom(t, cfg), ctx, "https://api.sandbox.push.apple.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("zero dial lost caller cancellation: %v", err)
	}
}

func TestTransportProxyCompleteDialBudget(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprint(secure), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			stop, done := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				<-stop
			}()
			t.Cleanup(func() { close(stop); _ = listener.Close(); <-done })
			const budget = 300 * time.Millisecond
			proxy, roots, _ := transportProxy(t, secure, budget*7/8, nil)
			proxyURL, _ := url.Parse(proxy.URL)
			cfg := Config{Environment: Sandbox, Transport: TransportConfig{DialTimeout: new(budget), ProxyRootCAs: roots, Proxy: http.ProxyURL(proxyURL)}}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			started := time.Now()
			if err := transportDo(t, transportFrom(t, cfg), ctx, "https://"+listener.Addr().String()); err == nil {
				t.Fatal("unresponsive origin accepted")
			}
			if elapsed := time.Since(started); elapsed >= budget*3/2 {
				t.Fatalf("CONNECT and TLS received separate budgets: %s", elapsed)
			}
		})
	}
}

func TestTransportProxyDeadlineReleasedAfterTLS(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprint(secure), func(t *testing.T) {
			origin, roots := transportServer(t, "h2", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
			proxy, proxyRoots, connects := transportProxy(t, secure, 0, nil)
			proxyURL, _ := url.Parse(proxy.URL)
			const budget = 80 * time.Millisecond
			cfg := Config{Environment: Sandbox, Transport: TransportConfig{RootCAs: roots, ProxyRootCAs: proxyRoots, Proxy: http.ProxyURL(proxyURL), DialTimeout: new(budget)}}
			tr := transportFrom(t, cfg)
			if err := transportDo(t, tr, context.Background(), origin.URL); err != nil {
				t.Fatal(err)
			}
			time.Sleep(budget * 2)
			if err := transportDo(t, tr, context.Background(), origin.URL); err != nil {
				t.Fatal(err)
			}
			if connects.Load() != 1 {
				t.Fatalf("connection did not outlive dial budget: %d CONNECTs", connects.Load())
			}
		})
	}
}

func TestTransportClosesRejectedRawTLSConnection(t *testing.T) {
	origin, roots := transportServer(t, "h2", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("request reached rejected hook connection") }))
	var supplied *tls.Conn
	cfg := Config{Environment: Sandbox, Transport: TransportConfig{RootCAs: roots, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		var err error
		conn, err := (&tls.Dialer{Config: &tls.Config{RootCAs: roots, NextProtos: []string{"h2"}}}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		supplied = conn.(*tls.Conn)
		return supplied, nil
	}}}
	if err := transportDo(t, transportFrom(t, cfg), context.Background(), origin.URL); err == nil {
		t.Fatal("already handshaken hook accepted")
	}
	if supplied == nil {
		t.Fatal("fixture handshake did not complete")
	}
	if _, err := supplied.Write([]byte("closed")); err == nil {
		t.Fatal("rejected connection remained open")
	}
}

func TestTransportHTTP2HealthChecks(t *testing.T) {
	certificate, roots := transportCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"h2"}})
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
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		preface := make([]byte, 24)
		if _, err := io.ReadFull(conn, preface); err != nil {
			pings <- err
			return
		}
		if string(preface) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
			pings <- errors.New("invalid h2 preface")
			return
		}
		if _, err := conn.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0}); err != nil {
			pings <- err
			return
		}
		for count := 0; count < 2; {
			var header [9]byte
			if _, err := io.ReadFull(conn, header[:]); err != nil {
				pings <- err
				return
			}
			size := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
			if size > 1<<20 {
				pings <- errors.New("oversized frame")
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
				pings <- errors.New("invalid ping frame")
				return
			}
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
	cfg := Config{Environment: Sandbox, Transport: TransportConfig{RootCAs: roots, HTTP2: HTTP2Config{ReadIdleTimeout: new(20 * time.Millisecond)}}}
	tr := transportFrom(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- transportDo(t, tr, ctx, "https://"+listener.Addr().String()) }()
	select {
	case err := <-pings:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("HTTP/2 idle pings not observed")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled request did not exit")
	}
}

func TestTransportClonesTrustPoolsBeforeFirstConnection(t *testing.T) {
	origin, originRoots := transportServer(t, "h2", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	proxy, proxyRoots, _ := transportProxy(t, true, 0, nil)
	proxyURL, _ := url.Parse(proxy.URL)
	for _, poolKind := range []string{"origin", "proxy"} {
		t.Run(poolKind, func(t *testing.T) {
			untrusted := x509.NewCertPool()
			cfg := Config{Environment: Sandbox, Transport: TransportConfig{RootCAs: originRoots, ProxyRootCAs: proxyRoots, Proxy: http.ProxyURL(proxyURL)}}
			var add *x509.Certificate
			if poolKind == "origin" {
				cfg.Transport.RootCAs = untrusted
				add = origin.Certificate()
			} else {
				cfg.Transport.ProxyRootCAs = untrusted
				add = proxy.Certificate()
			}
			tr := transportFrom(t, cfg)
			untrusted.AddCert(add)
			if err := transportDo(t, tr, context.Background(), origin.URL); err == nil {
				t.Fatal("transport retained caller's mutable trust pool")
			}
			if err := transportDo(t, transportFrom(t, cfg), context.Background(), origin.URL); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type transportTrackedConn struct {
	net.Conn
	closed *atomic.Bool
}

func (c transportTrackedConn) Close() error { c.closed.Store(true); return c.Conn.Close() }

func TestTransportClosesRawConnectionAfterTLSFailure(t *testing.T) {
	origin, _ := transportServer(t, "h2", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted origin received request") }))
	var closed atomic.Bool
	cfg := Config{Environment: Sandbox, Transport: TransportConfig{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return transportTrackedConn{Conn: conn, closed: &closed}, nil
	}}}
	if err := transportDo(t, transportFrom(t, cfg), context.Background(), origin.URL); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	if !closed.Load() {
		t.Fatal("owned raw connection was not closed after TLS failure")
	}
}
