package apns

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func managerTestCertificate(id int) tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{fmt.Appendf(nil, "certificate-%d", id)}}
}

func managerTestClient(certificate tls.Certificate) *Client {
	return &Client{certificate: certificate, host: HostDevelopment}
}

func managerForTest(t *testing.T, config ManagerConfig) *ClientManager {
	t.Helper()
	if config.Host == "" {
		config.Host = HostDevelopment
	}
	manager, err := NewClientManager(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.CloseIdleConnections)
	return manager
}

func managerGet(t *testing.T, manager *ClientManager, certificate tls.Certificate) *Client {
	t.Helper()
	client, err := manager.Get(certificate)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestClientManagerConcurrentGetCreatesOneClient(t *testing.T) {
	var calls atomic.Int32
	manager := managerForTest(t, ManagerConfig{Factory: func(certificate tls.Certificate) (*Client, error) {
		calls.Add(1)
		return managerTestClient(certificate), nil
	}})
	start := make(chan struct{})
	clients := make(chan *Client, 32)
	var workers sync.WaitGroup
	for range cap(clients) {
		workers.Go(func() {
			<-start
			client, err := manager.Get(managerTestCertificate(1))
			if err != nil {
				t.Error(err)
			}
			clients <- client
		})
	}
	close(start)
	workers.Wait()
	close(clients)
	first := <-clients
	for client := range clients {
		if client != first {
			t.Fatal("lookups returned different clients for one certificate")
		}
	}
	if calls.Load() != 1 || manager.Len() != 1 {
		t.Fatalf("factory calls = %d, cache length = %d", calls.Load(), manager.Len())
	}
}

func TestClientManagerRetiresUnusedExpiredClients(t *testing.T) {
	for _, auth := range []string{"certificate", "token"} {
		for _, operation := range []string{"lookup", "cached lookup", "add", "length", "remove", "close idle"} {
			t.Run(auth+"/"+operation, func(t *testing.T) {
				manager := managerForTest(t, ManagerConfig{MaxAge: time.Hour})
				cleanup := &managerCleanupTransport{onClose: func() { _ = manager.Len() }}
				expired := managerTestClient(managerTestCertificate(1))
				expired.httpClient = &http.Client{Transport: cleanup}
				if auth == "token" {
					expired.token = managerTestToken(t)
				}
				if err := manager.Add(expired); err != nil {
					t.Fatal(err)
				}
				manager.mu.Lock()
				manager.ll.Back().Value.(*managerItem).lastUsed = time.Now().Add(-2 * time.Hour)
				manager.mu.Unlock()
				other := managerTestClient(managerTestCertificate(2))
				manager.factory = func(tls.Certificate) (*Client, error) { return other, nil }
				if operation == "cached lookup" {
					manager.mu.Lock()
					manager.addLocked(certificateCacheKey(other.certificate, other.host), other, time.Now())
					manager.mu.Unlock()
				}
				switch operation {
				case "lookup", "cached lookup":
					managerGet(t, manager, other.certificate)
				case "add":
					if err := manager.Add(other); err != nil {
						t.Fatal(err)
					}
				case "length":
					if got := manager.Len(); got != 0 {
						t.Fatalf("expired cache length = %d", got)
					}
				case "remove":
					manager.Remove(other.certificate)
				case "close idle":
					manager.CloseIdleConnections()
				}
				if got := cleanup.closed.Load(); got != 1 {
					t.Fatalf("expired client cleanup calls = %d, want 1", got)
				}
				manager.mu.Lock()
				defer manager.mu.Unlock()
				for _, ele := range manager.cache {
					if ele.Value.(*managerItem).client == expired {
						t.Fatal("unused expired identity remains cached")
					}
				}
			})
		}
	}
}

func TestClientManagerConcurrentEvictionKeepsCacheConsistent(t *testing.T) {
	manager := managerForTest(t, ManagerConfig{MaxSize: 3})
	var workers sync.WaitGroup
	for worker := range 16 {
		workers.Go(func() {
			for iteration := range 16 {
				if err := manager.Add(managerTestClient(managerTestCertificate(worker + iteration))); err != nil {
					t.Error(err)
				}
				_ = manager.Len()
			}
		})
	}
	workers.Wait()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.cache) != manager.ll.Len() || manager.ll.Len() > manager.maxSize {
		t.Fatalf("map length = %d, list length = %d, capacity = %d", len(manager.cache), manager.ll.Len(), manager.maxSize)
	}
	for element := manager.ll.Front(); element != nil; element = element.Next() {
		item := element.Value.(*managerItem)
		if manager.cache[item.key] != element {
			t.Fatal("list entry does not match cache entry")
		}
	}
}

type managerCleanupTransport struct {
	closed  atomic.Int32
	onClose func()
}

func (*managerCleanupTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("unused test transport")
}

func (transport *managerCleanupTransport) CloseIdleConnections() {
	transport.closed.Add(1)
	if transport.onClose != nil {
		transport.onClose()
	}
}

func TestClientManagerClosesRetiredClientsOutsideLock(t *testing.T) {
	for _, operation := range []string{"replace", "expire", "expire-error", "evict"} {
		t.Run(operation, func(t *testing.T) {
			manager := managerForTest(t, ManagerConfig{MaxSize: 1, MaxAge: time.Hour})
			transport := &managerCleanupTransport{onClose: func() { _ = manager.Len() }}
			first := managerTestClient(managerTestCertificate(1))
			first.httpClient = &http.Client{Transport: transport}
			if err := manager.Add(first); err != nil {
				t.Fatal(err)
			}
			if err := manager.Add(first); err != nil {
				t.Fatal(err)
			}
			if transport.closed.Load() != 0 {
				t.Fatal("re-adding a client closed its connections")
			}
			replacement := managerTestClient(first.certificate)
			manager.factory = func(tls.Certificate) (*Client, error) { return replacement, nil }
			if operation == "expire" || operation == "expire-error" {
				manager.ll.Front().Value.(*managerItem).lastUsed = time.Now().Add(-2 * time.Hour)
			}
			if operation == "expire-error" {
				manager.factory = func(tls.Certificate) (*Client, error) { return nil, errors.New("load failed") }
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				switch operation {
				case "replace":
					if err := manager.Add(replacement); err != nil {
						t.Error(err)
					}
				case "expire", "expire-error":
					_, _ = manager.Get(first.certificate)
				case "evict":
					if err := manager.Add(managerTestClient(managerTestCertificate(2))); err != nil {
						t.Error(err)
					}
				}
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("cleanup deadlocked on manager callback")
			}
			if transport.closed.Load() != 1 {
				t.Fatalf("cleanup calls = %d", transport.closed.Load())
			}
			wantLength := 1
			if operation == "expire-error" {
				wantLength = 0
			}
			if manager.Len() != wantLength {
				t.Fatalf("cache length = %d, want %d", manager.Len(), wantLength)
			}
		})
	}
}

func TestClientManagerFactoryRunsWithoutLock(t *testing.T) {
	cached := managerTestCertificate(1)
	entered, release := make(chan struct{}), make(chan struct{})
	manager := managerForTest(t, ManagerConfig{})
	manager.factory = func(certificate tls.Certificate) (*Client, error) {
		_ = manager.Len()
		close(entered)
		<-release
		return managerTestClient(certificate), nil
	}
	if err := manager.Add(managerTestClient(cached)); err != nil {
		t.Fatal(err)
	}
	built := make(chan error, 1)
	go func() { _, err := manager.Get(managerTestCertificate(2)); built <- err }()
	<-entered
	done := make(chan *Client, 1)
	go func() {
		client, err := manager.Get(cached)
		if err != nil {
			t.Error(err)
		}
		done <- client
	}()
	select {
	case client := <-done:
		if client == nil {
			t.Fatal("cached client missing")
		}
	case <-time.After(time.Second):
		t.Fatal("factory blocked unrelated lookup")
	}
	close(release)
	if err := <-built; err != nil || manager.Len() != 2 {
		t.Fatalf("factory error = %v, cache length = %d", err, manager.Len())
	}
}

func TestClientManagerConcurrentGetAndReplace(t *testing.T) {
	certificate := managerTestCertificate(1)
	manager := managerForTest(t, ManagerConfig{})
	if err := manager.Add(managerTestClient(certificate)); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		for range 1000 {
			if err := manager.Add(managerTestClient(certificate)); err != nil {
				t.Error(err)
			}
		}
	})
	workers.Go(func() {
		for range 1000 {
			if client, err := manager.Get(certificate); err != nil || client == nil {
				t.Errorf("cached lookup = %v, %v", client, err)
			}
		}
	})
	workers.Wait()
	if manager.Len() != 1 {
		t.Fatalf("cache length = %d", manager.Len())
	}
}

func TestClientManagerAddWinsOverPendingFactory(t *testing.T) {
	for _, scenario := range []string{"new", "expired", "refresh-same-client"} {
		t.Run(scenario, func(t *testing.T) {
			certificate := managerTestCertificate(1)
			entered, release := make(chan struct{}), make(chan struct{})
			var unblock sync.Once
			defer unblock.Do(func() { close(release) })
			unused, explicitTransport := &managerCleanupTransport{}, &managerCleanupTransport{}
			explicit := managerTestClient(certificate)
			explicit.httpClient = &http.Client{Transport: explicitTransport}
			constructed := managerTestClient(certificate)
			constructed.httpClient = &http.Client{Transport: unused}
			manager := managerForTest(t, ManagerConfig{MaxAge: time.Hour, Factory: func(tls.Certificate) (*Client, error) {
				close(entered)
				<-release
				if scenario == "refresh-same-client" {
					return nil, errors.New("load failed")
				}
				return constructed, nil
			}})
			if scenario != "new" {
				stale := managerTestClient(certificate)
				if scenario == "refresh-same-client" {
					stale = explicit
				}
				if err := manager.Add(stale); err != nil {
					t.Fatal(err)
				}
				manager.ll.Front().Value.(*managerItem).lastUsed = time.Now().Add(-2 * time.Hour)
			}
			result := make(chan *Client, 1)
			go func() {
				client, err := manager.Get(certificate)
				if err != nil {
					t.Error(err)
				}
				result <- client
			}()
			<-entered
			if err := manager.Add(explicit); err != nil {
				t.Fatal(err)
			}
			if got := managerGet(t, manager, certificate); got != explicit {
				t.Fatal("Add did not publish configured client")
			}
			unblock.Do(func() { close(release) })
			if got := <-result; got != explicit {
				t.Fatal("pending lookup did not return added client")
			}
			if got := managerGet(t, manager, certificate); got != explicit {
				t.Fatal("factory overwrote added client")
			}
			wantClosed := int32(0)
			if scenario == "refresh-same-client" {
				wantClosed = 1
			}
			if got := explicitTransport.closed.Load(); got != wantClosed {
				t.Errorf("explicit client cleanup calls = %d, want %d", got, wantClosed)
			}
			if scenario != "refresh-same-client" && unused.closed.Load() != 1 {
				t.Errorf("unused cleanup calls = %d", unused.closed.Load())
			}
		})
	}
}
