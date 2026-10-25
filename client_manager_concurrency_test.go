package apns2

import (
	"crypto/tls"
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

func TestClientManagerConcurrentGetCreatesOneClient(t *testing.T) {
	var calls atomic.Int32
	manager := &ClientManager{Factory: func(certificate tls.Certificate) *Client {
		calls.Add(1)
		return &Client{Certificate: certificate}
	}}
	start := make(chan struct{})
	clients := make(chan *Client, 32)
	var workers sync.WaitGroup
	for range cap(clients) {
		workers.Go(func() {
			<-start
			clients <- manager.Get(managerTestCertificate(1))
		})
	}
	close(start)
	workers.Wait()
	close(clients)
	var first *Client
	for client := range clients {
		if first == nil {
			first = client
		}
		if client != first {
			t.Fatal("lookups returned different clients for one certificate")
		}
	}
	if calls.Load() != 1 || manager.Len() != 1 {
		t.Fatalf("factory calls = %d, cache length = %d; want 1 each", calls.Load(), manager.Len())
	}
}

func TestClientManagerConcurrentEvictionKeepsCacheConsistent(t *testing.T) {
	manager := &ClientManager{MaxSize: 3}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for worker := range 16 {
		workers.Go(func() {
			<-start
			for iteration := range 16 {
				if err := manager.Add(&Client{Certificate: managerTestCertificate(worker + iteration)}); err != nil {
					t.Error(err)
				}
				_ = manager.Len()
			}
		})
	}
	close(start)
	workers.Wait()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.cache) != manager.ll.Len() || manager.ll.Len() > manager.MaxSize {
		t.Fatalf("map length = %d, list length = %d, capacity = %d", len(manager.cache), manager.ll.Len(), manager.MaxSize)
	}
	for element := manager.ll.Front(); element != nil; element = element.Next() {
		item := element.Value.(*managerItem)
		if manager.cache[item.key] != element {
			t.Fatal("list entry does not match cache entry")
		}
	}
}

func TestClientManagerConcurrentInitializationAndLen(t *testing.T) {
	var manager ClientManager
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			<-start
			if err := manager.Add(&Client{Certificate: managerTestCertificate(1)}); err != nil {
				t.Error(err)
			}
		})
		workers.Go(func() {
			<-start
			_ = manager.Len()
		})
	}
	close(start)
	workers.Wait()
	if manager.Len() != 1 {
		t.Fatalf("cache length = %d, want 1", manager.Len())
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
	for _, operation := range []string{"replace", "expire", "expire-nil", "evict"} {
		t.Run(operation, func(t *testing.T) {
			manager := &ClientManager{MaxSize: 1}
			retiredTransport := &managerCleanupTransport{onClose: func() { _ = manager.Len() }}
			first := &Client{Certificate: managerTestCertificate(1), httpClient: &http.Client{Transport: retiredTransport}}
			if err := manager.Add(first); err != nil {
				t.Error(err)
			}
			// Re-adding the same client must not close a connection that remains cached.
			if err := manager.Add(first); err != nil {
				t.Error(err)
			}
			if retiredTransport.closed.Load() != 0 {
				t.Fatal("re-adding a client closed its connections")
			}
			replacement := &Client{Certificate: first.Certificate}
			manager.Factory = func(tls.Certificate) *Client { return replacement }
			if operation == "expire" || operation == "expire-nil" {
				manager.MaxAge = time.Hour
				manager.mu.Lock()
				manager.ll.Front().Value.(*managerItem).lastUsed = time.Now().Add(-2 * time.Hour)
				manager.mu.Unlock()
			}
			if operation == "expire-nil" {
				manager.Factory = func(tls.Certificate) *Client { return nil }
			}
			done := make(chan struct{})
			go func() {
				switch operation {
				case "replace":
					if err := manager.Add(replacement); err != nil {
						t.Error(err)
					}
				case "expire", "expire-nil":
					manager.Get(first.Certificate)
				case "evict":
					if err := manager.Add(&Client{Certificate: managerTestCertificate(2)}); err != nil {
						t.Error(err)
					}
				}
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("retirement deadlocked during cleanup callback")
			}
			if retiredTransport.closed.Load() != 1 {
				t.Fatalf("cleanup calls = %d, want 1", retiredTransport.closed.Load())
			}
			expectedLength := 1
			if operation == "expire-nil" {
				expectedLength = 0
			}
			if manager.Len() != expectedLength {
				t.Fatalf("cache length = %d, want %d", manager.Len(), expectedLength)
			}
		})
	}
}

func TestClientManagerFactoryRunsWithoutLock(t *testing.T) {
	cached := managerTestCertificate(1)
	release := make(chan struct{})
	entered := make(chan struct{})
	manager := &ClientManager{}
	manager.Factory = func(certificate tls.Certificate) *Client {
		_ = manager.Len()
		close(entered)
		<-release
		return &Client{Certificate: certificate}
	}
	if err := manager.Add(&Client{Certificate: cached}); err != nil {
		t.Error(err)
	}
	built := make(chan *Client, 1)
	go func() { built <- manager.Get(managerTestCertificate(2)) }()
	<-entered
	done := make(chan *Client, 1)
	go func() { done <- manager.Get(cached) }()
	select {
	case client := <-done:
		if client == nil {
			t.Fatal("cached client missing")
		}
	case <-time.After(time.Second):
		t.Fatal("slow Factory blocked lookup of another certificate")
	}
	close(release)
	if client := <-built; client == nil || manager.Len() != 2 {
		t.Fatalf("built client = %v, cache length = %d", client, manager.Len())
	}
}

func TestClientManagerExpiredNilFactoryEvicts(t *testing.T) {
	certificate := managerTestCertificate(1)
	manager := &ClientManager{MaxAge: time.Nanosecond, Factory: func(tls.Certificate) *Client { return nil }}
	if err := manager.Add(&Client{Certificate: certificate}); err != nil {
		t.Error(err)
	}
	time.Sleep(time.Millisecond)
	if client := manager.Get(certificate); client != nil || manager.Len() != 0 {
		t.Fatalf("expired client = %v, cache length = %d", client, manager.Len())
	}
}

func TestClientManagerConcurrentGetAndReplace(t *testing.T) {
	certificate := managerTestCertificate(1)
	manager := NewClientManager()
	if err := manager.Add(&Client{Certificate: certificate}); err != nil {
		t.Error(err)
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		for range 10000 {
			if err := manager.Add(&Client{Certificate: certificate}); err != nil {
				t.Error(err)
			}
		}
	})
	workers.Go(func() {
		for range 10000 {
			if manager.Get(certificate) == nil {
				t.Error("cached client missing")
			}
		}
	})
	workers.Wait()
	if manager.Len() != 1 {
		t.Fatalf("cache length = %d, want 1", manager.Len())
	}
}

func TestClientManagerAddWinsOverPendingFactory(t *testing.T) {
	for _, scenario := range []string{"new", "expired", "refresh-same-client"} {
		t.Run(scenario, func(t *testing.T) {
			certificate := managerTestCertificate(1)
			entered, release := make(chan struct{}), make(chan struct{})
			var unblock sync.Once
			defer unblock.Do(func() { close(release) })
			unused := &managerCleanupTransport{}
			explicitTransport := &managerCleanupTransport{}
			explicit := &Client{Certificate: certificate, httpClient: &http.Client{Transport: explicitTransport}}
			constructed := &Client{Certificate: certificate, httpClient: &http.Client{Transport: unused}}
			manager := &ClientManager{MaxAge: time.Hour, Factory: func(tls.Certificate) *Client {
				close(entered)
				<-release
				if scenario == "refresh-same-client" {
					return nil
				}
				return constructed
			}}
			if scenario != "new" {
				stale := &Client{Certificate: certificate}
				if scenario == "refresh-same-client" {
					stale = explicit
				}
				if err := manager.Add(stale); err != nil {
					t.Error(err)
				}
				manager.mu.Lock()
				manager.ll.Front().Value.(*managerItem).lastUsed = time.Now().Add(-2 * time.Hour)
				manager.mu.Unlock()
			}
			result := make(chan *Client, 1)
			go func() { result <- manager.Get(certificate) }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("factory did not start")
			}
			if err := manager.Add(explicit); err != nil {
				t.Error(err)
			}
			if got := manager.Get(certificate); got != explicit {
				t.Fatal("Add did not publish configured client")
			}
			unblock.Do(func() { close(release) })
			select {
			case got := <-result:
				if got != explicit {
					t.Fatal("pending Get did not return newer configured client")
				}
			case <-time.After(time.Second):
				t.Fatal("pending Get did not complete")
			}
			if got := manager.Get(certificate); got != explicit {
				t.Fatal("factory overwrote or removed newer configured client")
			}
			if explicitTransport.closed.Load() != 0 {
				t.Error("newer configured client was closed")
			}
			if scenario != "refresh-same-client" && unused.closed.Load() != 1 {
				t.Errorf("unused factory client cleanup = %d, want 1", unused.closed.Load())
			}
		})
	}
}
