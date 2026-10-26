package apns2_test

import (
	"crypto/tls"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jaakkonakaza/apns2"
	"github.com/jaakkonakaza/apns2/token"
)

func TestClientManagerConfiguration(t *testing.T) {
	for _, config := range []apns2.ManagerConfig{
		{},
		{Host: "not-a-url"},
		{Host: apns2.HostDevelopment, MaxSize: -1},
		{Host: apns2.HostDevelopment, MaxAge: -time.Second},
		{Host: apns2.HostDevelopment, ClientOptions: []apns2.ClientOption{nil}},
		{Host: apns2.HostDevelopment, ClientOptions: []apns2.ClientOption{apns2.WithHost("")}},
		{Host: apns2.HostDevelopment, ClientOptions: []apns2.ClientOption{apns2.WithHTTPClient(&http.Client{})}},
		{Host: apns2.HostDevelopment, ClientOptions: []apns2.ClientOption{apns2.WithHost(apns2.HostProduction)}},
		{Host: apns2.HostDevelopment, ClientOptions: []apns2.ClientOption{apns2.WithTimeout(-time.Second)}},
		{Host: apns2.HostDevelopment, ClientOptions: []apns2.ClientOption{apns2.WithDialTimeout(-time.Second)}},
		{Host: apns2.HostDevelopment, ClientOptions: []apns2.ClientOption{apns2.WithReadIdleTimeout(-time.Second)}},
		{Host: apns2.HostDevelopment, ClientOptions: []apns2.ClientOption{apns2.WithIdleConnTimeout(-time.Second)}},
		{Host: apns2.HostDevelopment, ClientOptions: []apns2.ClientOption{apns2.WithTLSConfig(&tls.Config{MaxVersion: tls.VersionTLS11})}},
		{Host: apns2.HostDevelopment, ClientOptions: []apns2.ClientOption{apns2.WithTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS12})}},
		{Host: "http://localhost", Factory: func(tls.Certificate) (*apns2.Client, error) { return nil, nil }},
	} {
		if manager, err := apns2.NewClientManager(config); err == nil || manager != nil {
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
	manager, err := apns2.NewClientManager(apns2.ManagerConfig{
		Host:          "http://localhost",
		ClientOptions: []apns2.ClientOption{apns2.WithTimeout(-time.Second)},
		Factory: func(cert tls.Certificate) (*apns2.Client, error) {
			return apns2.NewClient(cert, apns2.WithHost("http://localhost"), apns2.WithHTTPClient(&http.Client{}))
		},
		TokenFactory: func(provider *token.Token, host string) (*apns2.Client, error) {
			return apns2.NewTokenClient(provider, apns2.WithHost(host), apns2.WithHTTPClient(&http.Client{}))
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
	manager, err := apns2.NewClientManager(apns2.ManagerConfig{Host: apns2.HostDevelopment, MaxSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.CloseIdleConnections()
	first, err := manager.Get(mockCert())
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Get(mockCert())
	if err != nil || second != first || manager.Len() != 1 || manager.Host() != apns2.HostDevelopment {
		t.Fatalf("cached lookup = %p, %v, length %d", second, err, manager.Len())
	}
	if !manager.Remove(mockCert()) || manager.Len() != 0 {
		t.Fatal("certificate was not removed")
	}
}

func TestClientManagerConfigurationIsCaptured(t *testing.T) {
	config := apns2.ManagerConfig{Host: apns2.HostDevelopment}
	manager, err := apns2.NewClientManager(config)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.CloseIdleConnections()
	config.Host = apns2.HostProduction
	client, err := manager.Get(mockCert())
	if err != nil || client.Host() != apns2.HostDevelopment {
		t.Fatalf("captured config client = %v, %v", client, err)
	}
}

func TestClientManagerFactoryFailures(t *testing.T) {
	failure := errors.New("load certificate")
	for _, test := range []struct {
		name    string
		factory func(tls.Certificate) (*apns2.Client, error)
		want    error
	}{
		{"factory error", func(tls.Certificate) (*apns2.Client, error) { return nil, failure }, failure},
		{"nil client", func(tls.Certificate) (*apns2.Client, error) { return nil, nil }, apns2.ErrClientUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, err := apns2.NewClientManager(apns2.ManagerConfig{Host: apns2.HostDevelopment, Factory: test.factory})
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
	var manager apns2.ClientManager
	manager.CloseIdleConnections()
	if manager.Len() != 0 || manager.Remove(mockCert()) {
		t.Fatal("zero manager contains a client")
	}
	if client, err := manager.Get(mockCert()); client != nil || !errors.Is(err, apns2.ErrClientUnavailable) {
		t.Fatalf("zero manager lookup = %v, %v", client, err)
	}
}
