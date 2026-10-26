package apns

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Config selects an APNs environment and an owned transport policy.
// Configure callbacks before construction and make them safe for concurrent use.
type Config struct {
	Environment    Environment
	DevicePort     uint16
	RequestTimeout *time.Duration
	Transport      TransportConfig
}

// TransportConfig configures connections without replacing their TLS ownership.
// Nil root pools independently select system trust. Supplied pools are cloned.
// DialContext must honor context cancellation and return an unhandshaken connection.
// A successful return transfers connection ownership to the client. On error,
// the dialer remains responsible for closing resources it acquired.
// Decorate is trusted instrumentation which must delegate to the supplied base
// transport and preserve request contexts.
type TransportConfig struct {
	DialTimeout     *time.Duration
	IdleConnTimeout *time.Duration
	RootCAs         *x509.CertPool
	ProxyRootCAs    *x509.CertPool
	Proxy           func(*http.Request) (*url.URL, error)
	DialContext     func(context.Context, string, string) (net.Conn, error)
	Decorate        func(http.RoundTripper) http.RoundTripper
	HTTP2           HTTP2Config
}

// HTTP2Config controls HTTP/2 health checks and concurrency. Nil durations use
// library defaults. Disable health checks with ReadIdleTimeout set to zero;
// an explicit PingTimeout must be positive.
type HTTP2Config struct {
	ReadIdleTimeout             *time.Duration
	PingTimeout                 *time.Duration
	WriteByteTimeout            *time.Duration
	StrictMaxConcurrentRequests bool
	CountError                  func(string)
}

func durationOr(value *time.Duration, fallback time.Duration) time.Duration {
	if value != nil {
		return *value
	}
	return fallback
}

func requestTimeout(cfg Config) time.Duration {
	return durationOr(cfg.RequestTimeout, 60*time.Second)
}

func validateConfig(cfg Config) error {
	if cfg.Environment != Sandbox && cfg.Environment != Production {
		return errors.New("apns: environment must be Sandbox or Production")
	}
	if cfg.DevicePort != 0 && cfg.DevicePort != 443 && cfg.DevicePort != 2197 {
		return errors.New("apns: device port must be 443 or 2197")
	}
	for _, value := range []*time.Duration{cfg.RequestTimeout, cfg.Transport.DialTimeout, cfg.Transport.IdleConnTimeout, cfg.Transport.HTTP2.ReadIdleTimeout, cfg.Transport.HTTP2.WriteByteTimeout} {
		if value != nil && *value < 0 {
			return errors.New("apns: timeouts must not be negative")
		}
	}
	if value := cfg.Transport.HTTP2.PingTimeout; value != nil && *value <= 0 {
		return errors.New("apns: ping timeout must be positive")
	}
	return nil
}
