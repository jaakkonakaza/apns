// Package apns2 is a go Apple Push Notification Service (APNs) provider that
// allows you to send remote notifications to your iOS, tvOS, and OS X
// apps using HTTP/2.
package apns2

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/sideshow/apns2/token"
)

// Apple HTTP/2 Development & Production urls
const (
	HostDevelopment = "https://api.sandbox.push.apple.com"
	HostProduction  = "https://api.push.apple.com"
)

// DefaultHost is a mutable var for testing purposes
var DefaultHost = HostDevelopment

var (
	// HTTPClientTimeout specifies a time limit for requests made by the
	// HTTPClient. The timeout includes connection time, any redirects,
	// and reading the response body.
	HTTPClientTimeout = 60 * time.Second

	// ReadIdleTimeout is the timeout after which a health check using a ping
	// frame will be carried out if no frame is received on the connection. If
	// zero, no health check is performed.
	ReadIdleTimeout = 15 * time.Second

	// TCPKeepAlive specifies the keep-alive period for an active network
	// connection. If zero, keep-alive probes are sent with a default value
	// (currently 15 seconds)
	TCPKeepAlive = 15 * time.Second

	// TLSDialTimeout bounds TCP connection establishment and the TLS handshake
	// together. Through a proxy it also covers the proxy dial and CONNECT.
	TLSDialTimeout = 20 * time.Second
)

// DialTLS is the default dial function for creating TLS connections for direct
// requests and HTTPS proxies. TLSDialTimeout bounds the TCP connection and TLS
// handshake together. Clients capture DialTLS when they are created.
//
// Custom hooks must perform the handshake with the provided config, return a
// connection exposing ConnectionState(), and enforce their own timeout. Hooks
// do not receive the request context: a canceled request stops waiting for the
// hook and closes the connection it returns. Set DialTLS to nil to use a
// context-aware dialer bounded by TLSDialTimeout instead.
var DialTLS = func(network, addr string, cfg *tls.Config) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   TLSDialTimeout,
		KeepAlive: TCPKeepAlive,
	}
	return tls.DialWithDialer(dialer, network, addr, cfg)
}

// Client represents a connection with the APNs
type Client struct {
	Host        string
	Certificate tls.Certificate
	Token       *token.Token
	HTTPClient  *http.Client
}

// A Context carries a deadline, a cancellation signal, and other values across
// API boundaries. Context's methods may be called by multiple goroutines
// simultaneously.
type Context interface {
	context.Context
}

// NewClient returns a new Client with an underlying http.Client configured with
// the correct APNs HTTP/2 transport settings. It does not connect to the APNs
// until the first Notification is sent via the Push method.
//
// As per the Apple APNs Provider API, you should keep a handle on this client
// so that you can keep your connections with APNs open across multiple
// notifications; don’t repeatedly open and close connections. APNs treats rapid
// connection and disconnection as a denial-of-service attack.
//
// If your use case involves multiple long-lived connections, consider using
// the ClientManager, which manages clients for you.
func NewClient(certificate tls.Certificate) *Client {
	client := newClient(&tls.Config{Certificates: []tls.Certificate{certificate}})
	client.Certificate = certificate
	return client
}

// NewTokenClient returns a new Client with an underlying http.Client configured
// with the correct APNs HTTP/2 transport settings. It does not connect to the APNs
// until the first Notification is sent via the Push method.
//
// As per the Apple APNs Provider API, you should keep a handle on this client
// so that you can keep your connections with APNs open across multiple
// notifications; don’t repeatedly open and close connections. APNs treats rapid
// connection and disconnection as a denial-of-service attack.
func NewTokenClient(token *token.Token) *Client {
	client := newClient(&tls.Config{})
	client.Token = token
	return client
}

func newClient(tlsConfig *tls.Config) *Client {
	return &Client{
		HTTPClient: &http.Client{
			Transport:     newTransport(tlsConfig),
			Timeout:       HTTPClientTimeout,
			CheckRedirect: noRedirects,
		},
		Host: DefaultHost,
	}
}

// pushTarget identifies the APNs origin of a push. The transport uses it to
// tell origin connections from proxy connections, so it survives RoundTripper
// wrappers that keep the request context.
type pushTarget struct {
	addr      string
	plaintext bool
	proxy     *proxyDialBudget
}

// proxyDialBudget bounds a proxied dial by one TLSDialTimeout. net/http times
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

// dialProxy dials a proxy for target within one TLSDialTimeout budget.
func (target pushTarget) dialProxy(ctx context.Context, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	if TLSDialTimeout == 0 {
		return dial(ctx)
	}
	deadline := time.Now().Add(TLSDialTimeout)
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

// ErrHTTP2Required is returned when a client created by NewClient or
// NewTokenClient would reach APNs over anything other than HTTP/2 over TLS.
// Replace the client's transport to talk to other endpoints.
var ErrHTTP2Required = errors.New("apns2: HTTP/2 over TLS is required")

// newTransport returns a transport that only speaks HTTP/2 over TLS to APNs.
// Origin handshakes offer only h2 and fail unless h2 is negotiated, including
// handshakes net/http performs itself through proxies.
func newTransport(tlsConfig *tls.Config) *http.Transport {
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.VerifyConnection = verifyHTTP2
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	netDialer := &net.Dialer{Timeout: TLSDialTimeout, KeepAlive: TCPKeepAlive}
	transport := &http.Transport{
		TLSHandshakeTimeout: TLSDialTimeout,
		TLSClientConfig:     tlsConfig,
		Protocols:           protocols,
		HTTP2:               &http.HTTP2Config{SendPingTimeout: ReadIdleTimeout},
	}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		target, ok := ctx.Value(pushTargetKey{}).(pushTarget)
		if !ok {
			return netDialer.DialContext(ctx, network, addr)
		}
		if target.plaintext || addr == target.addr {
			return nil, ErrHTTP2Required
		}
		return target.dialProxy(ctx, func(ctx context.Context) (net.Conn, error) {
			return netDialer.DialContext(ctx, network, addr)
		})
	}
	dialTLS := DialTLS
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		cfg := transport.TLSClientConfig.Clone()
		target, ok := ctx.Value(pushTargetKey{}).(pushTarget)
		if ok && target.plaintext {
			return nil, ErrHTTP2Required
		}
		// Without a push target only the origin is dialed here, unless Proxy is set.
		origin := !ok && transport.Proxy == nil || ok && addr == target.addr
		if !origin {
			// net/http sends CONNECT using HTTP/1.1 on the HTTPS proxy connection.
			cfg.NextProtos = []string{"http/1.1"}
			cfg.VerifyConnection = nil
		}
		if cfg.ServerName == "" {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			cfg.ServerName = host
		}
		if !origin {
			if ok {
				return target.dialProxy(ctx, func(ctx context.Context) (net.Conn, error) {
					return dialTLSContext(ctx, dialTLS, network, addr, cfg)
				})
			}
			return dialTLSContext(ctx, dialTLS, network, addr, cfg)
		}
		conn, err := dialTLSContext(ctx, dialTLS, network, addr, cfg)
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

// dialTLSContext dials with hook, or with a dialer bounded by TLSDialTimeout
// when hook is nil. Both stop waiting when ctx is done.
func dialTLSContext(ctx context.Context, hook func(string, string, *tls.Config) (net.Conn, error), network, addr string, cfg *tls.Config) (net.Conn, error) {
	if hook == nil {
		if TLSDialTimeout != 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, TLSDialTimeout)
			defer cancel()
		}
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{KeepAlive: TCPKeepAlive},
			Config:    cfg,
		}
		return dialer.DialContext(ctx, network, addr)
	}
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := hook(network, addr, cfg)
		done <- result{conn, err}
	}()
	select {
	case r := <-done:
		return r.conn, r.err
	case <-ctx.Done():
		go func() {
			if r := <-done; r.err == nil {
				_ = r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

func noRedirects(*http.Request, []*http.Request) error {
	return errors.New("apns2: redirects are not supported")
}

// Development sets the Client to use the APNs development push endpoint.
func (c *Client) Development() *Client {
	c.Host = HostDevelopment
	return c
}

// Production sets the Client to use the APNs production push endpoint.
func (c *Client) Production() *Client {
	c.Host = HostProduction
	return c
}

// Push sends a Notification to the APNs gateway. If the underlying http.Client
// is not currently connected, this method will attempt to reconnect
// transparently before sending the notification. It will return a Response
// indicating whether the notification was accepted or rejected by the APNs
// gateway, or an error if something goes wrong.
//
// Use PushWithContext if you need better cancellation and timeout control.
func (c *Client) Push(n *Notification) (*Response, error) {
	return c.PushWithContext(context.Background(), n)
}

// PushWithContext sends a Notification to the APNs gateway. Context carries a
// deadline and a cancellation signal and allows you to close long running
// requests when the context timeout is exceeded. Context must not be nil.
//
// If the underlying http.Client is not currently connected, this method will
// attempt to reconnect transparently before sending the notification. It will
// return a Response indicating whether the notification was accepted or
// rejected by the APNs gateway, or an error if something goes wrong.
func (c *Client) PushWithContext(ctx Context, n *Notification) (*Response, error) {
	if n == nil {
		return nil, errors.New("apns2: notification is nil")
	}
	if n.DeviceToken == "" {
		return nil, errors.New("apns2: device token is empty")
	}
	if _, err := hex.DecodeString(n.DeviceToken); err != nil {
		return nil, fmt.Errorf("apns2: invalid device token: %w", err)
	}
	payload, err := json.Marshal(n)
	if err != nil {
		return nil, err
	}

	requestURL := c.Host + "/3/device/" + n.DeviceToken
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	target := newPushTarget(request.URL)
	requestCtx := context.WithValue(request.Context(), pushTargetKey{}, target)
	// Dials keep the request's trace, so this fires after the origin handshake
	// even when net/http performs it through a proxy.
	requestCtx = httptrace.WithClientTrace(requestCtx, &httptrace.ClientTrace{
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err == nil && state.NegotiatedProtocol == "h2" {
				target.proxy.release()
			}
		},
	})
	request = request.WithContext(requestCtx)

	if c.Token != nil {
		if err := c.setTokenHeader(request); err != nil {
			return nil, err
		}
	}

	setHeaders(request, n)

	response, err := c.HTTPClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		// Closing a response body after reading it cannot change the push result.
		_ = response.Body.Close()
	}()

	r := &Response{}
	r.StatusCode = response.StatusCode
	r.ApnsID = response.Header.Get("apns-id")
	r.ApnsUniqueID = response.Header.Get("apns-unique-id")

	var body struct {
		Reason    string `json:"reason"`
		Timestamp Time   `json:"timestamp"`
	}
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&body); err != nil && err != io.EOF {
		return r, err
	}
	r.Reason = body.Reason
	r.Timestamp = body.Timestamp
	return r, nil
}

// CloseIdleConnections closes any underlying connections which were previously
// connected from previous requests but are now sitting idle. It will not
// interrupt any connections currently in use.
func (c *Client) CloseIdleConnections() {
	c.HTTPClient.CloseIdleConnections()
}

func (c *Client) setTokenHeader(r *http.Request) error {
	bearer, err := c.Token.GenerateIfExpiredWithError()
	if err != nil {
		return err
	}
	r.Header.Set("authorization", "bearer "+bearer)
	return nil
}

func setHeaders(r *http.Request, n *Notification) {
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	if n.Topic != "" {
		r.Header.Set("apns-topic", n.Topic)
	}
	if n.ApnsID != "" {
		r.Header.Set("apns-id", n.ApnsID)
	}
	if n.CollapseID != "" {
		r.Header.Set("apns-collapse-id", n.CollapseID)
	}
	if n.Priority > 0 {
		r.Header.Set("apns-priority", strconv.Itoa(n.Priority))
	}
	if n.Expiration.After(time.Unix(0, 0)) {
		r.Header.Set("apns-expiration", strconv.FormatInt(n.Expiration.Unix(), 10))
	}
	if n.PushType != "" {
		r.Header.Set("apns-push-type", string(n.PushType))
	} else {
		r.Header.Set("apns-push-type", string(PushTypeAlert))
	}
}
