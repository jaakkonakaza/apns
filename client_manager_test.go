package apns_test

import (
	"crypto/tls"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jaakkonakaza/apns"
	"github.com/jaakkonakaza/apns/token"
)

func TestClientManagerConfiguration(t *testing.T) {
	for _, config := range []apns.ManagerConfig{
		{},
		{Host: "not-a-url"},
		{Host: apns.HostDevelopment, MaxSize: -1},
		{Host: apns.HostDevelopment, MaxAge: -time.Second},
		{Host: apns.HostDevelopment, ClientOptions: []apns.ClientOption{nil}},
		{Host: apns.HostDevelopment, ClientOptions: []apns.ClientOption{apns.WithHost("")}},
		{Host: apns.HostDevelopment, ClientOptions: []apns.ClientOption{apns.WithHTTPClient(&http.Client{})}},
		{Host: apns.HostDevelopment, ClientOptions: []apns.ClientOption{apns.WithHost(apns.HostProduction)}},
		{Host: apns.HostDevelopment, ClientOptions: []apns.ClientOption{apns.WithTimeout(-time.Second)}},
		{Host: apns.HostDevelopment, ClientOptions: []apns.ClientOption{apns.WithDialTimeout(-time.Second)}},
		{Host: apns.HostDevelopment, ClientOptions: []apns.ClientOption{apns.WithReadIdleTimeout(-time.Second)}},
		{Host: apns.HostDevelopment, ClientOptions: []apns.ClientOption{apns.WithIdleConnTimeout(-time.Second)}},
		{Host: apns.HostDevelopment, ClientOptions: []apns.ClientOption{apns.WithTLSConfig(&tls.Config{MaxVersion: tls.VersionTLS11})}},
		{Host: apns.HostDevelopment, ClientOptions: []apns.ClientOption{apns.WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS12})}},
		{Host: "http://localhost", Factory: func(tls.Certificate) (*apns.Client, error) { return nil, nil }},
	} {
		if manager, err := apns.NewClientManager(config); err == nil || manager != nil {
			t.Fatalf("invalid config returned %v, %v", manager, err)
		}
	}
}

func TestClientManagerCustomFactoriesOwnTransportPolicy(t *testing.T) {
	key, err := token.AuthKeyFromFile("token/testdata/authkey-valid.p8")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := token.New(key, "key", "team")
	if err != nil {
		t.Fatal(err)
	}
	manager, err := apns.NewClientManager(apns.ManagerConfig{
		Host:          "http://localhost",
		ClientOptions: []apns.ClientOption{apns.WithTimeout(-time.Second)},
		Factory: func(cert tls.Certificate) (*apns.Client, error) {
			return apns.NewClient(cert, apns.WithHost("http://localhost"), apns.WithHTTPClient(&http.Client{}))
		},
		TokenFactory: func(provider *token.Token, host string) (*apns.Client, error) {
			return apns.NewTokenClient(provider, apns.WithHost(host), apns.WithHTTPClient(&http.Client{}))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.CloseIdleConnections()
	if _, err := manager.Get(mockCert()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.GetByToken(provider); err != nil {
		t.Fatal(err)
	}
}

func TestClientManagerCachesCertificate(t *testing.T) {
	manager, err := apns.NewClientManager(apns.ManagerConfig{Host: apns.HostDevelopment, MaxSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.CloseIdleConnections()
	first, err := manager.Get(mockCert())
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Get(mockCert())
	if err != nil || second != first || manager.Len() != 1 || manager.Host() != apns.HostDevelopment {
		t.Fatalf("cached lookup = %p, %v, length %d", second, err, manager.Len())
	}
	if !manager.Remove(mockCert()) || manager.Len() != 0 {
		t.Fatal("certificate was not removed")
	}
}

func TestClientManagerConfigurationIsCaptured(t *testing.T) {
	config := apns.ManagerConfig{Host: apns.HostDevelopment}
	manager, err := apns.NewClientManager(config)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.CloseIdleConnections()
	config.Host = apns.HostProduction
	client, err := manager.Get(mockCert())
	if err != nil || client.Host() != apns.HostDevelopment {
		t.Fatalf("captured config client = %v, %v", client, err)
	}
}

func TestClientManagerFactoryFailures(t *testing.T) {
	failure := errors.New("load certificate")
	for _, test := range []struct {
		name    string
		factory func(tls.Certificate) (*apns.Client, error)
		want    error
	}{
		{"factory error", func(tls.Certificate) (*apns.Client, error) { return nil, failure }, failure},
		{"nil client", func(tls.Certificate) (*apns.Client, error) { return nil, nil }, apns.ErrClientUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, err := apns.NewClientManager(apns.ManagerConfig{Host: apns.HostDevelopment, Factory: test.factory})
			if err != nil {
				t.Fatal(err)
			}
			if client, err := manager.Get(mockCert()); client != nil || !errors.Is(err, test.want) {
				t.Fatalf("failed lookup = %v, %v", client, err)
			}
			if manager.Len() != 0 {
				t.Fatal("failed construction was cached")
			}
		})
	}
}

func TestClientManagerZeroValue(t *testing.T) {
	var manager apns.ClientManager
	manager.CloseIdleConnections()
	if manager.Len() != 0 || manager.Remove(mockCert()) {
		t.Fatal("zero manager contains a client")
	}
	if client, err := manager.Get(mockCert()); client != nil || !errors.Is(err, apns.ErrClientUnavailable) {
		t.Fatalf("zero manager lookup = %v, %v", client, err)
	}
}
