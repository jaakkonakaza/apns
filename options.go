package apns2

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ClientOption configures a client at construction time.
type ClientOption func(*clientConfig)

type clientConfig struct {
	host            string
	httpClient      *http.Client
	idleConnTimeout time.Duration
	timeout         time.Duration
	dialTimeout     time.Duration
	readIdleTimeout time.Duration
	tcpKeepAlive    time.Duration
	tlsConfig       *tls.Config
	proxy           func(*http.Request) (*url.URL, error)
	dialTLS         func(context.Context, string, string, *tls.Config) (net.Conn, error)
}

func defaultClientConfig() clientConfig {
	return clientConfig{
		host:            HostDevelopment,
		timeout:         60 * time.Second,
		dialTimeout:     20 * time.Second,
		readIdleTimeout: 15 * time.Second,
		tcpKeepAlive:    15 * time.Second,
	}
}

// WithHost sets the APNs endpoint. The default is HostDevelopment.
func WithHost(host string) ClientOption {
	return func(config *clientConfig) { config.host = host }
}

// WithTimeout sets the time limit for a complete push, including reading its response.
// The default is 60 seconds. Zero disables the timeout.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(config *clientConfig) { config.timeout = timeout }
}

// WithDialTimeout limits connection establishment, including TLS and proxy CONNECT.
// The default is 20 seconds. Zero disables the timeout.
func WithDialTimeout(timeout time.Duration) ClientOption {
	return func(config *clientConfig) { config.dialTimeout = timeout }
}

// WithReadIdleTimeout sets how long an HTTP/2 connection waits without incoming
// frames before sending a health-check ping. The default is 15 seconds.
// Zero disables idle health checks.
func WithReadIdleTimeout(timeout time.Duration) ClientOption {
	return func(config *clientConfig) { config.readIdleTimeout = timeout }
}

// WithTCPKeepAlive sets the TCP keep-alive interval. The default is 15 seconds.
// Zero uses Go's default interval and a negative interval disables keep-alive.
func WithTCPKeepAlive(interval time.Duration) ClientOption {
	return func(config *clientConfig) { config.tcpKeepAlive = interval }
}

// WithTLSConfig supplies TLS settings, cloned for each client. Certificate clients
// use the certificate passed to NewClient, ignoring GetClientCertificate.
// Connections require TLS 1.2 or later. HTTPS proxies use RootCAs but have
// independent hostname verification and do not receive origin callbacks or certificates.
func WithTLSConfig(tlsConfig *tls.Config) ClientOption {
	return func(config *clientConfig) { config.tlsConfig = tlsConfig }
}

// WithProxy sets proxy selection, for example http.ProxyURL or http.ProxyFromEnvironment.
// By default, connections are direct.
func WithProxy(proxy func(*http.Request) (*url.URL, error)) ClientOption {
	return func(config *clientConfig) { config.proxy = proxy }
}

// WithDialTLSContext sets TLS dialing for direct requests and HTTPS proxy connections.
// The dialer must honor ctx and return a handshaken connection exposing ConnectionState().
// Origin settings include verification, certificates, and ALPN configuration.
// HTTPS proxy settings include only RootCAs, minimum TLS version, proxy hostname,
// and HTTP/1.1 ALPN.
func WithDialTLSContext(dial func(context.Context, string, string, *tls.Config) (net.Conn, error)) ClientOption {
	return func(config *clientConfig) { config.dialTLS = dial }
}

// WithHTTPClient supplies the HTTP client used for pushes without changing it.
// It owns transport policy, TLS, redirects, and timeouts, so other transport and
// timeout options do not apply. Configure it before use and do not mutate it
// during pushes. For certificate authentication, configure its TLS certificate
// yourself. NewClient does not install its certificate into a supplied client.
// CloseIdleConnections also closes the supplied client's idle connections.
// Do not share it between clients that need independent identities or cleanup.
// NewClientManager rejects this option. Nil selects the default APNs HTTP/2 client.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(config *clientConfig) { config.httpClient = client }
}

// WithIdleConnTimeout limits how long an idle connection stays open.
// The default is zero, which leaves idle connections open.
func WithIdleConnTimeout(timeout time.Duration) ClientOption {
	return func(config *clientConfig) { config.idleConnTimeout = timeout }
}
