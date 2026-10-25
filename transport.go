package apns2

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"reflect"
	"sync"
	"time"
)

// pushTarget identifies the APNs origin of a push. The transport uses it to
// tell origin connections from proxy connections, so it survives RoundTripper
// wrappers that keep the request context.
type pushTarget struct {
	addr      string
	plaintext bool
	proxy     *proxyDialBudget
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
	if err != nil {
		return nil, err
	}
	if err := target.proxy.limit(conn, deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

type pushTargetKey struct{}

// errNoPushTarget is returned if net/http dials without the context Push sets.
var errNoPushTarget = errors.New("apns2: dial is missing its push target")

// ErrHTTP2Required is returned when the default transport would reach APNs
// over anything other than HTTP/2 over TLS.
// Use WithHTTPClient to supply a client with a different transport policy.
var ErrHTTP2Required = errors.New("apns2: HTTP/2 over TLS is required")

// newTransport returns a transport that only speaks HTTP/2 over TLS to APNs.
// Origin handshakes offer only h2 and fail unless h2 is negotiated, including
// handshakes net/http performs itself through proxies.
func newTransport(tlsConfig *tls.Config, config clientConfig) *http.Transport {
	if tlsConfig.MinVersion < tls.VersionTLS12 {
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	verify := tlsConfig.VerifyConnection
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if verify != nil {
			if err := verify(state); err != nil {
				return err
			}
		}
		return verifyHTTP2(state)
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	netDialer := &net.Dialer{Timeout: config.dialTimeout, KeepAlive: config.tcpKeepAlive}
	transport := &http.Transport{
		TLSHandshakeTimeout: config.dialTimeout,
		IdleConnTimeout:     config.idleConnTimeout,
		TLSClientConfig:     tlsConfig,
		Proxy:               config.proxy,
		Protocols:           protocols,
		HTTP2:               &http.HTTP2Config{SendPingTimeout: config.readIdleTimeout},
	}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		target, ok := ctx.Value(pushTargetKey{}).(pushTarget)
		if !ok {
			return nil, errNoPushTarget
		}
		if target.plaintext || addr == target.addr {
			return nil, ErrHTTP2Required
		}
		return target.dialProxy(ctx, config.dialTimeout, func(ctx context.Context) (net.Conn, error) {
			return netDialer.DialContext(ctx, network, addr)
		})
	}
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		cfg := transport.TLSClientConfig.Clone()
		target, ok := ctx.Value(pushTargetKey{}).(pushTarget)
		if !ok {
			return nil, errNoPushTarget
		}
		if target.plaintext {
			return nil, ErrHTTP2Required
		}
		origin := addr == target.addr
		if !origin {
			// net/http sends CONNECT using HTTP/1.1 on the HTTPS proxy connection.
			cfg = &tls.Config{
				RootCAs:    tlsConfig.RootCAs,
				MinVersion: tlsConfig.MinVersion,
				NextProtos: []string{"http/1.1"},
			}
		}
		if cfg.ServerName == "" {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			cfg.ServerName = host
		}
		if !origin {
			return target.dialProxy(ctx, config.dialTimeout, func(ctx context.Context) (net.Conn, error) {
				return dialTLSContext(ctx, config, network, addr, cfg)
			})
		}
		if config.dialTimeout != 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, config.dialTimeout)
			defer cancel()
		}
		conn, err := dialTLSContext(ctx, config, network, addr, cfg)
		if err != nil {
			return nil, err
		}
		// Custom hooks may ignore cfg, so check the negotiated protocol here too.
		state, ok := conn.(interface{ ConnectionState() tls.ConnectionState })
		if !ok || state.ConnectionState().NegotiatedProtocol != "h2" {
			_ = conn.Close()
			return nil, ErrHTTP2Required
		}
		return conn, nil
	}
	return transport
}

func newPushTarget(u *url.URL) pushTarget {
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	return pushTarget{
		addr:      net.JoinHostPort(u.Hostname(), port),
		plaintext: u.Scheme != "https",
		proxy:     &proxyDialBudget{},
	}
}

func verifyHTTP2(state tls.ConnectionState) error {
	if state.NegotiatedProtocol != "h2" {
		return ErrHTTP2Required
	}
	return nil
}

func dialTLSContext(ctx context.Context, config clientConfig, network, addr string, cfg *tls.Config) (net.Conn, error) {
	var conn net.Conn
	var err error
	if config.dialTLS != nil {
		conn, err = config.dialTLS(ctx, network, addr, cfg)
	} else {
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{KeepAlive: config.tcpKeepAlive},
			Config:    cfg,
		}
		conn, err = dialer.DialContext(ctx, network, addr)
	}
	if err != nil {
		return nil, err
	}
	if conn == nil || reflect.ValueOf(conn).Kind() == reflect.Pointer && reflect.ValueOf(conn).IsNil() {
		return nil, errors.New("apns2: TLS dialer returned a nil connection")
	}
	return conn, nil
}

func prepareRequest(request *http.Request) *http.Request {
	target := newPushTarget(request.URL)
	ctx := context.WithValue(request.Context(), pushTargetKey{}, target)
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
