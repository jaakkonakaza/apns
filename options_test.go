package apns

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestTransportConfigDefaultsAndExplicitZero(t *testing.T) {
	for _, explicitZero := range []bool{false, true} {
		cfg := Config{Environment: Sandbox}
		if explicitZero {
			cfg.RequestTimeout = new(time.Duration(0))
			cfg.Transport.DialTimeout = new(time.Duration(0))
			cfg.Transport.IdleConnTimeout = new(time.Duration(0))
			cfg.Transport.HTTP2.ReadIdleTimeout = new(time.Duration(0))
			cfg.Transport.HTTP2.WriteByteTimeout = new(time.Duration(0))
		}
		tr, err := makeTransport(&tls.Config{}, cfg)
		if err != nil {
			t.Fatal(err)
		}
		wantRequest, wantDial, wantIdle := 60*time.Second, 20*time.Second, 15*time.Second
		if explicitZero {
			wantRequest, wantDial, wantIdle = 0, 0, 0
		}
		if requestTimeout(cfg) != wantRequest || tr.TLSHandshakeTimeout != wantDial || tr.HTTP2.SendPingTimeout != wantIdle {
			t.Fatalf("explicit zero=%t: timeout defaults differ", explicitZero)
		}
		if tr.HTTP2.PingTimeout != 15*time.Second || tr.IdleConnTimeout != 0 || tr.HTTP2.WriteByteTimeout != 0 {
			t.Fatal("unexpected ping/idle/write defaults")
		}
		if tr.Protocols.HTTP1() || !tr.Protocols.HTTP2() || tr.Protocols.UnencryptedHTTP2() {
			t.Fatal("transport must support only encrypted HTTP/2")
		}
	}
}

func TestTransportConfigRejectsInvalidValues(t *testing.T) {
	negative := -time.Nanosecond
	for name, cfg := range map[string]Config{
		"environment absent":  {},
		"environment unknown": {Environment: Environment(255)},
		"port":                {Environment: Sandbox, DevicePort: 80},
		"request":             {Environment: Sandbox, RequestTimeout: &negative},
		"dial":                {Environment: Sandbox, Transport: TransportConfig{DialTimeout: &negative}},
		"idle":                {Environment: Sandbox, Transport: TransportConfig{IdleConnTimeout: &negative}},
		"read idle":           {Environment: Sandbox, Transport: TransportConfig{HTTP2: HTTP2Config{ReadIdleTimeout: &negative}}},
		"write byte":          {Environment: Sandbox, Transport: TransportConfig{HTTP2: HTTP2Config{WriteByteTimeout: &negative}}},
		"ping negative":       {Environment: Sandbox, Transport: TransportConfig{HTTP2: HTTP2Config{PingTimeout: &negative}}},
		"ping zero":           {Environment: Sandbox, Transport: TransportConfig{HTTP2: HTTP2Config{PingTimeout: new(time.Duration(0))}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := makeTransport(&tls.Config{}, cfg); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	for _, port := range []uint16{0, 443, 2197} {
		if err := validateConfig(Config{Environment: Production, DevicePort: port}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTransportClonesConfigurationAndMapsHTTP2(t *testing.T) {
	roots, proxyRoots := x509.NewCertPool(), x509.NewCertPool()
	calls := 0
	cfg := Config{Environment: Sandbox, Transport: TransportConfig{
		RootCAs: roots, ProxyRootCAs: proxyRoots,
		DialTimeout: new(3 * time.Second), IdleConnTimeout: new(4 * time.Second),
		HTTP2: HTTP2Config{ReadIdleTimeout: new(5 * time.Second), PingTimeout: new(6 * time.Second), WriteByteTimeout: new(7 * time.Second), StrictMaxConcurrentRequests: true, CountError: func(string) { calls++ }},
	}}
	origin := &tls.Config{}
	tr, err := makeTransport(origin, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tr.TLSClientConfig == origin || tr.TLSClientConfig.RootCAs == roots {
		t.Fatal("mutable TLS input retained")
	}
	if origin.MinVersion != 0 || len(origin.NextProtos) != 0 {
		t.Fatal("caller TLS settings mutated")
	}
	if tr.TLSHandshakeTimeout != 3*time.Second || tr.IdleConnTimeout != 4*time.Second || tr.HTTP2.SendPingTimeout != 5*time.Second || tr.HTTP2.PingTimeout != 6*time.Second || tr.HTTP2.WriteByteTimeout != 7*time.Second || !tr.HTTP2.StrictMaxConcurrentRequests {
		t.Fatal("configuration not applied")
	}
	tr.HTTP2.CountError("test")
	if calls != 1 {
		t.Fatal("CountError was not forwarded")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS12 || len(tr.TLSClientConfig.NextProtos) != 1 || tr.TLSClientConfig.NextProtos[0] != "h2" {
		t.Fatal("TLS policy not installed")
	}
	if tr.TLSClientConfig.RootCAs == proxyRoots {
		t.Fatal("proxy roots selected for origin")
	}
}
