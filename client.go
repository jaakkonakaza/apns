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
	"reflect"
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

// Client represents a connection with the APNs
type Client struct {
	Host        string
	Certificate tls.Certificate
	Token       *token.Token
	httpClient  *http.Client
}

// NewClient returns a certificate-authenticated client. By default it uses an
// HTTP client configured for APNs HTTP/2. It connects when Push is first called.
//
// As per the Apple APNs Provider API, you should keep a handle on this client
// so that you can keep your connections with APNs open across multiple
// notifications; don’t repeatedly open and close connections. APNs treats rapid
// connection and disconnection as a denial-of-service attack.
//
// If your use case involves multiple long-lived connections, consider using
// the ClientManager, which manages clients for you.
// WithHTTPClient uses the supplied client's TLS identity instead of certificate.
func NewClient(certificate tls.Certificate, options ...ClientOption) *Client {
	client := newClient(&tls.Config{Certificates: []tls.Certificate{certificate}}, options...)
	client.Certificate = certificate
	return client
}

// NewTokenClient returns a token-authenticated client. By default it uses an
// HTTP client configured for APNs HTTP/2. It connects when Push is first called.
//
// As per the Apple APNs Provider API, you should keep a handle on this client
// so that you can keep your connections with APNs open across multiple
// notifications; don’t repeatedly open and close connections. APNs treats rapid
// connection and disconnection as a denial-of-service attack.
func NewTokenClient(token *token.Token, options ...ClientOption) *Client {
	client := newClient(&tls.Config{}, options...)
	client.Token = token
	return client
}

func newClient(tlsConfig *tls.Config, options ...ClientOption) *Client {
	config := defaultClientConfig()
	for _, option := range options {
		option(&config)
	}
	if config.tlsConfig != nil {
		supplied := config.tlsConfig.Clone()
		if len(tlsConfig.Certificates) != 0 {
			supplied.Certificates = tlsConfig.Certificates
			supplied.GetClientCertificate = nil
		}
		tlsConfig = supplied
	}
	httpClient := config.httpClient
	if httpClient == nil {
		httpClient = &http.Client{
			Transport:     newTransport(tlsConfig, config),
			Timeout:       config.timeout,
			CheckRedirect: noRedirects,
		}
	}
	return &Client{httpClient: httpClient, Host: config.host}
}

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

func noRedirects(*http.Request, []*http.Request) error {
	return errors.New("apns2: redirects are not supported")
}

// Push sends a Notification to the APNs gateway. Context carries cancellation
// and deadlines and must not be nil. Push reconnects as needed and returns the
// APNs response or an error if the request could not be completed.
func (c *Client) Push(ctx context.Context, n *Notification) (*Response, error) {
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

	response, err := c.httpClient.Do(request)
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
		Timestamp *int64 `json:"timestamp"`
	}
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&body); err != nil && err != io.EOF {
		return r, err
	}
	r.Reason = body.Reason
	if body.Timestamp != nil {
		r.Timestamp = time.UnixMilli(*body.Timestamp)
	}
	return r, nil
}

// CloseIdleConnections closes any underlying connections which were previously
// connected from previous requests but are now sitting idle. It will not
// interrupt any connections currently in use.
func (c *Client) CloseIdleConnections() {
	c.httpClient.CloseIdleConnections()
}

func (c *Client) setTokenHeader(r *http.Request) error {
	bearer, err := c.Token.Bearer()
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
	if !n.Expiration.IsZero() {
		r.Header.Set("apns-expiration", strconv.FormatInt(max(0, n.Expiration.Unix()), 10))
	}
	if n.PushType != "" {
		r.Header.Set("apns-push-type", string(n.PushType))
	} else {
		r.Header.Set("apns-push-type", string(PushTypeAlert))
	}
}
