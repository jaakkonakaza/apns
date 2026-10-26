package apns2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaakkonakaza/apns2/token"
)

func managerSigningKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func managerTokenWithKey(t *testing.T, key *ecdsa.PrivateKey, keyID, teamID string) *token.Token {
	t.Helper()
	provider, err := token.New(key, keyID, teamID)
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func managerTestToken(t *testing.T) *token.Token {
	t.Helper()
	return managerTokenWithKey(t, managerSigningKey(t), "key", "team")
}

func TestClientManagerTokenIdentityAndHost(t *testing.T) {
	key := managerSigningKey(t)
	provider := managerTokenWithKey(t, key, "key", "team")
	manager := managerForTest(t, ManagerConfig{})
	first, err := manager.GetByToken(provider)
	if err != nil {
		t.Fatal(err)
	}
	if first.Host() != HostDevelopment || first.token != provider {
		t.Fatal("token factory changed host or identity")
	}
	if _, err := provider.Bearer(); err != nil {
		t.Fatal(err)
	}
	copied := managerTokenWithKey(t, key, "key", "team")
	if same, err := manager.GetByToken(copied); err != nil || same != first {
		t.Fatalf("copied identity = %p, %v", same, err)
	}
	for _, other := range []*token.Token{
		managerTokenWithKey(t, key, "key", "other team"),
		managerTokenWithKey(t, key, "other key", "team"),
		managerTestToken(t),
	} {
		if client, err := manager.GetByToken(other); err != nil || client == nil || client == first {
			t.Fatalf("distinct identity = %p, %v", client, err)
		}
	}
	production := managerForTest(t, ManagerConfig{Host: HostProduction})
	client, err := production.GetByToken(provider)
	if err != nil || client == first || client.Host() != HostProduction {
		t.Fatalf("production client = %v, %v", client, err)
	}
	devKey, err := tokenCacheKey(provider, HostDevelopment)
	if err != nil {
		t.Fatal(err)
	}
	prodKey, err := tokenCacheKey(provider, HostProduction)
	if err != nil {
		t.Fatal(err)
	}
	if devKey == prodKey || manager.Len() != 4 {
		t.Fatal("host or signing identity was omitted from cache key")
	}
}

func TestClientManagerConcurrentTokenGet(t *testing.T) {
	provider := managerTestToken(t)
	var calls atomic.Int32
	var manager *ClientManager
	manager = managerForTest(t, ManagerConfig{TokenFactory: func(t *token.Token, host string) (*Client, error) {
		calls.Add(1)
		_ = manager.Len()
		return &Client{token: t, host: host}, nil
	}})
	clients := make(chan *Client, 32)
	var workers sync.WaitGroup
	for range cap(clients) {
		workers.Go(func() {
			client, err := manager.GetByToken(provider)
			if err != nil {
				t.Error(err)
			}
			clients <- client
		})
	}
	workers.Wait()
	close(clients)
	first := <-clients
	for client := range clients {
		if client != first {
			t.Fatal("constructed duplicate token client")
		}
	}
	if calls.Load() != 1 || manager.Len() != 1 {
		t.Fatalf("calls = %d, length = %d", calls.Load(), manager.Len())
	}
}

func TestClientManagerInvalidTokensLeaveCacheUnchanged(t *testing.T) {
	manager := managerForTest(t, ManagerConfig{})
	for _, provider := range []*token.Token{nil, {}} {
		if client, err := manager.GetByToken(provider); client != nil || !errors.Is(err, token.ErrAuthKeyNil) {
			t.Fatalf("invalid token = %v, %v", client, err)
		}
		if removed, err := manager.RemoveByToken(provider); removed || err == nil {
			t.Fatalf("invalid removal = %v, %v", removed, err)
		}
	}
	if err := manager.Add(&Client{token: &token.Token{}, host: HostDevelopment}); err == nil {
		t.Fatal("Add accepted invalid token")
	}
	if err := manager.Add(nil); err == nil {
		t.Fatal("Add accepted nil client")
	}
	if manager.Len() != 0 {
		t.Fatal("invalid identity changed cache")
	}
}

func TestClientManagerRemovesTokenAndRecreates(t *testing.T) {
	provider := managerTestToken(t)
	manager := managerForTest(t, ManagerConfig{})
	cleanup := &managerCleanupTransport{onClose: func() { _ = manager.Len() }}
	first := &Client{token: provider, host: HostDevelopment, httpClient: &http.Client{Transport: cleanup}}
	if err := manager.Add(first); err != nil {
		t.Fatal(err)
	}
	if got, err := manager.GetByToken(provider); err != nil || got != first {
		t.Fatalf("added lookup = %p, %v", got, err)
	}
	if removed, err := manager.RemoveByToken(provider); err != nil || !removed || manager.Len() != 0 || cleanup.closed.Load() != 1 {
		t.Fatalf("remove = %v, %v, length %d, closed %d", removed, err, manager.Len(), cleanup.closed.Load())
	}
	if removed, err := manager.RemoveByToken(provider); err != nil || removed {
		t.Fatalf("second removal = %v, %v", removed, err)
	}
	if fresh, err := manager.GetByToken(provider); err != nil || fresh == nil || fresh == first {
		t.Fatalf("fresh client = %p, %v", fresh, err)
	}
}

func TestClientManagerRemovalDiscardsPendingFactory(t *testing.T) {
	for _, tokenAuth := range []bool{false, true} {
		t.Run(map[bool]string{false: "certificate", true: "token"}[tokenAuth], func(t *testing.T) {
			provider := managerTestToken(t)
			certificate := managerTestCertificate(1)
			entered, release := make(chan struct{}), make(chan struct{})
			var unblock sync.Once
			defer unblock.Do(func() { close(release) })
			cleanup := &managerCleanupTransport{}
			old := managerTestClient(certificate)
			old.httpClient = &http.Client{Transport: cleanup}
			fresh := managerTestClient(certificate)
			if tokenAuth {
				old.token, fresh.token = provider, provider
			}
			var calls atomic.Int32
			factory := func() (*Client, error) {
				if calls.Add(1) == 1 {
					close(entered)
					<-release
					return old, nil
				}
				return fresh, nil
			}
			manager := managerForTest(t, ManagerConfig{
				Factory:      func(tls.Certificate) (*Client, error) { return factory() },
				TokenFactory: func(*token.Token, string) (*Client, error) { return factory() },
			})
			get := func() (*Client, error) {
				if tokenAuth {
					return manager.GetByToken(provider)
				}
				return manager.Get(certificate)
			}
			type result struct {
				client *Client
				err    error
			}
			done := make(chan result, 1)
			go func() { client, err := get(); done <- result{client, err} }()
			<-entered
			if tokenAuth {
				if removed, err := manager.RemoveByToken(provider); err != nil || !removed {
					t.Fatalf("removal = %v, %v", removed, err)
				}
			} else if !manager.Remove(certificate) {
				t.Fatal("pending certificate was not removed")
			}
			if client, err := get(); err != nil || client != fresh {
				t.Fatalf("replacement lookup = %p, %v", client, err)
			}
			unblock.Do(func() { close(release) })
			got := <-done
			if got.client != nil || !errors.Is(got.err, ErrClientRemoved) {
				t.Fatalf("removed lookup = %p, %v", got.client, got.err)
			}
			if cached, err := get(); err != nil || cached != fresh || cleanup.closed.Load() != 1 {
				t.Fatalf("fresh cache = %p, %v, old cleanup %d", cached, err, cleanup.closed.Load())
			}
		})
	}
}

func TestClientManagerTokenSharesEvictionAndExpiry(t *testing.T) {
	provider := managerTestToken(t)
	manager := managerForTest(t, ManagerConfig{MaxSize: 1, MaxAge: time.Hour, Factory: func(c tls.Certificate) (*Client, error) { return managerTestClient(c), nil }})
	cleanup := &managerCleanupTransport{}
	first := &Client{token: provider, host: HostDevelopment, httpClient: &http.Client{Transport: cleanup}}
	if err := manager.Add(first); err != nil {
		t.Fatal(err)
	}
	_, err := manager.Get(managerTestCertificate(1))
	if err != nil {
		t.Fatal(err)
	}
	if manager.Len() != 1 || cleanup.closed.Load() != 1 {
		t.Fatal("certificate did not evict token client")
	}
	if err := manager.Add(first); err != nil {
		t.Fatal(err)
	}
	manager.ll.Front().Value.(*managerItem).lastUsed = time.Now().Add(-2 * time.Hour)
	if fresh, err := manager.GetByToken(provider); err != nil || fresh == nil || fresh == first {
		t.Fatalf("expired client = %p, %v", fresh, err)
	}
	if cleanup.closed.Load() != 2 {
		t.Fatalf("expired cleanup = %d", cleanup.closed.Load())
	}
}

func TestClientManagerFactoryErrorsAndNilResults(t *testing.T) {
	provider := managerTestToken(t)
	failure := errors.New("HSM unavailable")
	for _, factory := range []func(*token.Token, string) (*Client, error){
		func(*token.Token, string) (*Client, error) { return nil, failure },
		func(*token.Token, string) (*Client, error) { return nil, nil },
	} {
		manager := managerForTest(t, ManagerConfig{TokenFactory: factory})
		client, err := manager.GetByToken(provider)
		if client != nil || err == nil || manager.Len() != 0 {
			t.Fatalf("failed construction = %p, %v", client, err)
		}
	}
}

func TestClientManagerCloseIdleConnectionsOutsideLock(t *testing.T) {
	manager := managerForTest(t, ManagerConfig{})
	for id := range 2 {
		transport := &managerCleanupTransport{onClose: func() { _ = manager.Len() }}
		client := managerTestClient(managerTestCertificate(id))
		client.httpClient = &http.Client{Transport: transport}
		if err := manager.Add(client); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() { manager.CloseIdleConnections(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("manager cleanup held its lock")
	}
	if manager.Len() != 2 {
		t.Fatal("idle cleanup evicted entries")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for _, ele := range manager.cache {
		transport := ele.Value.(*managerItem).client.httpClient.Transport.(*managerCleanupTransport)
		if transport.closed.Load() != 1 {
			t.Fatalf("cleanup calls = %d", transport.closed.Load())
		}
	}
}

func TestClientManagerRejectsFactoryIdentityMismatch(t *testing.T) {
	provider := managerTestToken(t)
	wrong := managerTestToken(t)
	manager := managerForTest(t, ManagerConfig{
		Factory:      func(tls.Certificate) (*Client, error) { return managerTestClient(managerTestCertificate(2)), nil },
		TokenFactory: func(*token.Token, string) (*Client, error) { return &Client{host: HostDevelopment, token: wrong}, nil },
	})
	if client, err := manager.Get(managerTestCertificate(1)); err == nil || client != nil {
		t.Fatalf("mismatched certificate = %p, %v", client, err)
	}
	if client, err := manager.GetByToken(provider); err == nil || client != nil {
		t.Fatalf("mismatched token = %p, %v", client, err)
	}
	if manager.Len() != 0 {
		t.Fatal("mismatched identity was cached")
	}
}

func TestClientManagerNormalizesTrailingHostSlash(t *testing.T) {
	provider := managerTestToken(t)
	for _, test := range []struct {
		host       string
		optionHost string
	}{
		{HostDevelopment + "/", HostDevelopment},
		{HostDevelopment, HostDevelopment + "/"},
		{HostDevelopment + "/", HostDevelopment + "/"},
	} {
		t.Run(test.host+"/option="+test.optionHost, func(t *testing.T) {
			manager := managerForTest(t, ManagerConfig{Host: test.host, ClientOptions: []ClientOption{WithHost(test.optionHost)}})
			if manager.Host() != HostDevelopment {
				t.Fatalf("host = %q, want %q", manager.Host(), HostDevelopment)
			}
			client, err := manager.GetByToken(provider)
			if err != nil || client == nil || client.Host() != HostDevelopment {
				t.Fatalf("normalized lookup = %v, %v", client, err)
			}
			if cached, err := manager.GetByToken(provider); err != nil || cached != client {
				t.Fatalf("normalized cache lookup = %p, %v", cached, err)
			}
		})
	}
}

func TestClientManagerCapturesTLSConfiguration(t *testing.T) {
	provider := managerTestToken(t)
	certificate := managerTestCertificate(1)
	certificate.PrivateKey = managerSigningKey(t)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13}
	manager := managerForTest(t, ManagerConfig{ClientOptions: []ClientOption{WithTLSConfig(tlsConfig)}})
	tlsConfig.MaxVersion = tls.VersionTLS11
	for _, get := range []func() (*Client, error){
		func() (*Client, error) { return manager.Get(certificate) },
		func() (*Client, error) { return manager.GetByToken(provider) },
	} {
		client, err := get()
		if err != nil {
			t.Fatalf("captured TLS configuration: %v", err)
		}
		if got := client.ownedTransport.TLSClientConfig.MaxVersion; got != tls.VersionTLS13 {
			t.Fatalf("maximum TLS version = %d, want %d", got, tls.VersionTLS13)
		}
	}
}
