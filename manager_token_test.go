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

func managerTestToken(t *testing.T) *token.Token {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &token.Token{AuthKey: key, TeamID: "team", KeyID: "key"}
}

func TestClientManagerTokenIdentityAndHost(t *testing.T) {
	provider := managerTestToken(t)
	manager := NewClientManager(WithHost(HostDevelopment))
	first, err := manager.GetByToken(provider)
	if err != nil {
		t.Fatal(err)
	}
	defer first.CloseIdleConnections()
	if first.Host != HostDevelopment || first.Token != provider {
		t.Fatal("token factory did not apply host and identity")
	}
	if _, err := provider.Bearer(); err != nil {
		t.Fatal(err)
	}
	copied := &token.Token{AuthKey: provider.AuthKey, TeamID: provider.TeamID, KeyID: provider.KeyID}
	if same, err := manager.GetByToken(copied); err != nil || same != first {
		t.Fatalf("copied identity = %p, %v, want %p", same, err, first)
	}
	for _, provider := range []*token.Token{
		{AuthKey: provider.AuthKey, TeamID: "other team", KeyID: provider.KeyID},
		{AuthKey: provider.AuthKey, TeamID: provider.TeamID, KeyID: "other key ID"},
		managerTestToken(t),
	} {
		client, err := manager.GetByToken(provider)
		if err != nil || client == nil || client == first {
			t.Fatalf("different signing identity = %p, %v", client, err)
		}
		defer client.CloseIdleConnections()
	}
	manager.Host = HostProduction
	production, err := manager.GetByToken(provider)
	if err != nil || production == nil || production == first || production.Host != HostProduction {
		t.Fatalf("production identity = %+v, %v", production, err)
	}
	defer production.CloseIdleConnections()
	manager.Host = HostDevelopment
	if same, err := manager.GetByToken(provider); err != nil || same != first {
		t.Fatal("development cache entry was overwritten")
	}
	if manager.Len() != 5 {
		t.Fatalf("cache length = %d, want 5", manager.Len())
	}
}

func TestClientManagerConcurrentTokenGet(t *testing.T) {
	provider := managerTestToken(t)
	var calls atomic.Int32
	manager := NewClientManager(WithHost(HostDevelopment))
	manager.TokenFactory = func(provider *token.Token, host string) *Client {
		calls.Add(1)
		_ = manager.Len()
		return &Client{Token: provider, Host: host}
	}
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
			t.Fatal("concurrent token lookups constructed different clients")
		}
	}
	if calls.Load() != 1 || manager.Len() != 1 {
		t.Fatalf("factory calls = %d, cache length = %d", calls.Load(), manager.Len())
	}
}

func TestClientManagerInvalidTokensLeaveCacheUnchanged(t *testing.T) {
	manager := NewClientManager(WithHost(HostDevelopment))
	wrongCurve, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range []*token.Token{nil, {}, {AuthKey: wrongCurve}} {
		if client, err := manager.GetByToken(provider); err == nil || client != nil {
			t.Errorf("invalid token returned %v, %v", client, err)
		}
		if removed, err := manager.RemoveByToken(provider); err == nil || removed {
			t.Errorf("invalid token removal returned %v, %v", removed, err)
		}
	}
	if client, err := manager.GetByToken(nil); !errors.Is(err, token.ErrAuthKeyNil) || client != nil {
		t.Fatalf("nil token returned %v, %v", client, err)
	}
	if err := manager.Add(&Client{Token: &token.Token{}}); err == nil {
		t.Fatal("Add accepted invalid token")
	}
	if err := manager.Add(nil); err == nil {
		t.Fatal("Add accepted nil client")
	}
	if manager.Len() != 0 {
		t.Fatal("invalid identity mutated the cache")
	}
}

func TestClientManagerRemovesTokenAndRecreates(t *testing.T) {
	provider := managerTestToken(t)
	manager := NewClientManager(WithHost(HostDevelopment))
	cleanup := &managerCleanupTransport{onClose: func() { _ = manager.Len() }}
	first := &Client{Token: provider, Host: HostDevelopment, httpClient: &http.Client{Transport: cleanup}}
	if err := manager.Add(first); err != nil {
		t.Fatal(err)
	}
	if cached, err := manager.GetByToken(provider); err != nil || cached != first {
		t.Fatalf("token Add returned %p, %v", cached, err)
	}
	removed, err := manager.RemoveByToken(provider)
	if err != nil || !removed || manager.Len() != 0 || cleanup.closed.Load() != 1 {
		t.Fatalf("removal = %v, %v, cache length = %d, closed = %d", removed, err, manager.Len(), cleanup.closed.Load())
	}
	if removed, err := manager.RemoveByToken(provider); err != nil || removed {
		t.Fatalf("second removal = %v, %v", removed, err)
	}
	fresh, err := manager.GetByToken(provider)
	if err != nil || fresh == nil || fresh == first {
		t.Fatalf("fresh token client = %p, %v", fresh, err)
	}
	defer fresh.CloseIdleConnections()
}

func TestClientManagerRemovalDiscardsPendingFactory(t *testing.T) {
	for _, tokenAuth := range []bool{false, true} {
		t.Run(map[bool]string{false: "certificate", true: "token"}[tokenAuth], func(t *testing.T) {
			provider := managerTestToken(t)
			certificate := managerTestCertificate(1)
			entered, release := make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			manager := NewClientManager(WithHost(HostDevelopment))
			cleanup := &managerCleanupTransport{onClose: func() { _ = manager.Len() }}
			built := &Client{Certificate: certificate, Token: provider, Host: HostDevelopment, httpClient: &http.Client{Transport: cleanup}}
			factory := func() *Client {
				close(entered)
				<-release
				return built
			}
			manager.Factory = func(tls.Certificate) *Client { return factory() }
			manager.TokenFactory = func(*token.Token, string) *Client { return factory() }
			get := func() *Client {
				if tokenAuth {
					client, err := manager.GetByToken(provider)
					if err != nil {
						t.Error(err)
					}
					return client
				}
				return manager.Get(certificate)
			}
			result := make(chan *Client, 1)
			go func() { result <- get() }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("factory did not start")
			}
			if tokenAuth {
				if removed, err := manager.RemoveByToken(provider); err != nil || !removed {
					t.Fatalf("pending token removal = %v, %v", removed, err)
				}
			} else if !manager.Remove(certificate) {
				t.Fatal("pending certificate removal failed")
			}
			close(release)
			select {
			case client := <-result:
				if client != nil {
					t.Fatal("removed factory result was returned")
				}
			case <-time.After(time.Second):
				t.Fatal("removed factory call did not finish")
			}
			if manager.Len() != 0 || cleanup.closed.Load() != 1 {
				t.Fatalf("cache length = %d, discarded cleanup = %d", manager.Len(), cleanup.closed.Load())
			}
		})
	}
}

func TestClientManagerRemovesCertificateAndRecreates(t *testing.T) {
	certificate := managerTestCertificate(1)
	manager := NewClientManager(WithHost(HostDevelopment))
	cleanup := &managerCleanupTransport{onClose: func() { _ = manager.Len() }}
	first := &Client{Certificate: certificate, httpClient: &http.Client{Transport: cleanup}}
	if err := manager.Add(first); err != nil {
		t.Fatal(err)
	}
	if !manager.Remove(certificate) || manager.Len() != 0 || cleanup.closed.Load() != 1 {
		t.Fatalf("cache length = %d, closed = %d", manager.Len(), cleanup.closed.Load())
	}
	if manager.Remove(certificate) {
		t.Fatal("missing certificate was removed twice")
	}
	fresh := manager.Get(certificate)
	if fresh == nil || fresh == first {
		t.Fatal("certificate lookup did not create a fresh client")
	}
	defer fresh.CloseIdleConnections()
}

func TestClientManagerTokenSharesEvictionAndExpiry(t *testing.T) {
	provider := managerTestToken(t)
	manager := NewClientManager(WithHost(HostDevelopment))
	manager.MaxSize = 1
	cleanup := &managerCleanupTransport{onClose: func() { _ = manager.Len() }}
	first := &Client{Token: provider, Host: HostDevelopment, httpClient: &http.Client{Transport: cleanup}}
	if err := manager.Add(first); err != nil {
		t.Fatal(err)
	}
	certificate := manager.Get(managerTestCertificate(1))
	defer certificate.CloseIdleConnections()
	if manager.Len() != 1 || cleanup.closed.Load() != 1 {
		t.Fatal("certificate lookup did not evict token client")
	}
	if err := manager.Add(first); err != nil {
		t.Fatal(err)
	}
	manager.MaxAge = time.Hour
	manager.mu.Lock()
	manager.ll.Front().Value.(*managerItem).lastUsed = time.Now().Add(-2 * time.Hour)
	manager.mu.Unlock()
	fresh, err := manager.GetByToken(provider)
	if err != nil || fresh == nil || fresh == first {
		t.Fatalf("expired token client = %p, %v", fresh, err)
	}
	defer fresh.CloseIdleConnections()
	if cleanup.closed.Load() != 2 {
		t.Fatalf("expired token client cleanup calls = %d, want 2", cleanup.closed.Load())
	}
}
