package apns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"

	"github.com/jaakkonakaza/apns/internal/nilcheck"
)

// pushTarget identifies the APNs origin of a push. The transport uses it to
// tell origin connections from proxy connections, so it survives RoundTripper
// wrappers that keep the request context.
type pushTarget struct {
	addr      string
	plaintext bool
	proxy     *proxyDialBudget // nil unless the client has a proxy
}

// proxyDialBudget bounds the complete proxy connection establishment. net/http times
// the proxy dial, CONNECT, and origin handshake separately, so the deadline is
// set on the proxy connection and cleared once the origin negotiates h2.
type proxyDialBudget struct {
	mu   sync.Mutex
	conn net.Conn
}

func (b *proxyDialBudget) limit(conn net.Conn, deadline time.Time) error {
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	b.mu.Lock()
	b.conn = conn
	b.mu.Unlock()
	return nil
}

func (b *proxyDialBudget) release() {
	b.mu.Lock()
	conn := b.conn
	b.conn = nil
	b.mu.Unlock()
	if conn != nil {
		_ = conn.SetDeadline(time.Time{})
	}
}

// dialProxy includes CONNECT and the origin handshake in the dial timeout.
func (target pushTarget) dialProxy(ctx context.Context, timeout time.Duration, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	if timeout == 0 {
		return dial(ctx)
	}
	deadline := time.Now().Add(timeout)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	conn, err := dial(ctx)
	if err != nil || target.proxy == nil {
		return conn, err
	}
	if err := target.proxy.limit(conn, deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

type pushTargetKey struct{}

// errNoPushTarget is returned if net/http dials without the context Push sets.
var errNoPushTarget = errors.New("apns: dial is missing its push target")

// ErrHTTP2Required is returned when the default transport would reach APNs
// over anything other than HTTP/2 over TLS.
var ErrHTTP2Required = errors.New("apns: HTTP/2 over TLS is required")

// makeTransport owns the origin and HTTPS-proxy TLS handshakes. Only the
// origin receives authentication certificates and must negotiate h2.
func makeTransport(originTLS *tls.Config, cfg Config) (*http.Transport, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	tlsConfig := originTLS.Clone()
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.NextProtos = []string{"h2"}
	tlsConfig.RootCAs = cloneRoots(cfg.Transport.RootCAs)
	tlsConfig.VerifyConnection = verifyHTTP2
	proxyRoots := cloneRoots(cfg.Transport.ProxyRootCAs)
	dialTimeout := durationOr(cfg.Transport.DialTimeout, 20*time.Second)
	rawDial := cfg.Transport.DialContext
	if rawDial == nil {
		rawDial = (&net.Dialer{KeepAlive: 15 * time.Second}).DialContext
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := rawDial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if nilcheck.IsNil(conn) {
			return nil, errors.New("apns: raw dialer returned a nil connection")
		}
		if state, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok && state.ConnectionState().HandshakeComplete {
			_ = conn.Close()
			return nil, errors.New("apns: raw dialer returned a handshaken TLS connection")
		}
		return conn, nil
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	transport := &http.Transport{
		TLSHandshakeTimeout: dialTimeout,
		IdleConnTimeout:     durationOr(cfg.Transport.IdleConnTimeout, 0),
		TLSClientConfig:     tlsConfig,
		Proxy:               cfg.Transport.Proxy,
		Protocols:           protocols,
		HTTP2: &http.HTTP2Config{
			SendPingTimeout:             durationOr(cfg.Transport.HTTP2.ReadIdleTimeout, 15*time.Second),
			PingTimeout:                 durationOr(cfg.Transport.HTTP2.PingTimeout, 15*time.Second),
			WriteByteTimeout:            durationOr(cfg.Transport.HTTP2.WriteByteTimeout, 0),
			StrictMaxConcurrentRequests: cfg.Transport.HTTP2.StrictMaxConcurrentRequests,
			CountError:                  cfg.Transport.HTTP2.CountError,
		},
	}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		target, ok := ctx.Value(pushTargetKey{}).(pushTarget)
		if !ok {
			return nil, errNoPushTarget
		}
		if target.plaintext || addr == target.addr {
			return nil, ErrHTTP2Required
		}
		return target.dialProxy(ctx, dialTimeout, func(ctx context.Context) (net.Conn, error) {
			return dial(ctx, network, addr)
		})
	}
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		target, ok := ctx.Value(pushTargetKey{}).(pushTarget)
		if !ok {
			return nil, errNoPushTarget
		}
		if target.plaintext {
			return nil, ErrHTTP2Required
		}
		origin := addr == target.addr
		config := tlsConfig.Clone()
		if !origin {
			config = &tls.Config{RootCAs: proxyRoots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		config.ServerName = host
		tlsDial := func(ctx context.Context) (net.Conn, error) {
			conn, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn, config)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		}
		if !origin {
			return target.dialProxy(ctx, dialTimeout, tlsDial)
		}
		if dialTimeout != 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, dialTimeout)
			defer cancel()
		}
		return tlsDial(ctx)
	}
	return transport, nil
}

func cloneRoots(pool *x509.CertPool) *x509.CertPool {
	if pool == nil {
		return nil
	}
	return pool.Clone()
}

func newPushTarget(u *url.URL, proxied bool) pushTarget {
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	target := pushTarget{addr: net.JoinHostPort(u.Hostname(), port), plaintext: u.Scheme != "https"}
	if proxied {
		target.proxy = &proxyDialBudget{}
	}
	return target
}

func verifyHTTP2(state tls.ConnectionState) error {
	if state.NegotiatedProtocol != "h2" {
		return ErrHTTP2Required
	}
	return nil
}

// prepareRequest installs the proxy deadline trace only when proxied, so
// direct sends on warm connections pay for the target alone.
func prepareRequest(request *http.Request, proxied bool) *http.Request {
	target := newPushTarget(request.URL, proxied)
	ctx := context.WithValue(request.Context(), pushTargetKey{}, target)
	if !proxied {
		return request.WithContext(ctx)
	}
	// net/http also calls the trace after an origin handshake through a proxy.
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err == nil && state.NegotiatedProtocol == "h2" {
				target.proxy.release()
			}
		},
	})
	return request.WithContext(ctx)
}
