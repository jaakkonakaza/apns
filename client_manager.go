package apns2

import (
	"container/list"
	"crypto/sha1"
	"crypto/tls"
	"sync"
	"time"
)

type pendingClient struct {
	done   chan struct{}
	client *Client
	added  *Client // Latest explicit Add while Factory is running. Protected by the manager mutex.
}

type managerItem struct {
	key      [sha1.Size]byte
	client   *Client
	lastUsed time.Time
}

// ClientManager manages cached APNs clients. Set its configuration before
// concurrent use. Factory runs without the manager lock, and concurrent Gets
// for the same certificate share one Factory call. Factory may use the manager,
// but must not Get the certificate it is building.
type ClientManager struct {
	// MaxSize is the maximum number of clients allowed in the manager. When
	// this limit is reached, the least recently used client is evicted. Set
	// zero for no limit.
	MaxSize int

	// MaxAge is the maximum age of clients in the manager. Upon retrieval, if
	// a client has remained unused in the manager for this duration or longer,
	// it is replaced using Factory, or evicted if Factory returns nil. Set zero
	// to disable expiration.
	MaxAge time.Duration

	// Factory is the function which constructs clients if not found in the
	// manager.
	Factory func(certificate tls.Certificate) *Client

	cache   map[[sha1.Size]byte]*list.Element
	pending map[[sha1.Size]byte]*pendingClient
	ll      *list.List
	mu      sync.Mutex
	once    sync.Once
}

// NewClientManager returns a new ClientManager for prolonged, concurrent usage
// of multiple APNs clients. ClientManager is flexible enough to work best for
// your use case. When a client is not found in the manager, Get will return
// the result of calling Factory, which can be a Client or nil.
//
// Having multiple clients per certificate in the manager is not allowed.
//
// By default, MaxSize is 64, MaxAge is 10 minutes, and Factory always returns
// a Client with the supplied constructor options. WithHTTPClient is unsupported
// and causes a panic. Use Factory to supply a separate HTTP client for each
// certificate.
func NewClientManager(options ...ClientOption) *ClientManager {
	options = append([]ClientOption(nil), options...)
	config := defaultClientConfig()
	for _, option := range options {
		option(&config)
	}
	if config.httpClient != nil {
		panic("apns2: NewClientManager does not support WithHTTPClient, use Factory for per-certificate HTTP clients")
	}
	manager := &ClientManager{
		MaxSize: 64,
		MaxAge:  10 * time.Minute,
		Factory: func(certificate tls.Certificate) *Client { return NewClient(certificate, options...) },
	}

	manager.initInternals()

	return manager
}

// Add adds a Client to the manager. You can use this to individually configure
// Clients in the manager.
func (m *ClientManager) Add(client *Client) {
	m.initInternals()
	m.mu.Lock()
	key := cacheKey(client.Certificate)
	retired := m.addLocked(key, client, time.Now())
	if call := m.pending[key]; call != nil {
		call.added = client
	}
	m.mu.Unlock()
	closeClientIdleConnections(retired)
}

func (m *ClientManager) addLocked(key [sha1.Size]byte, client *Client, now time.Time) *Client {
	if ele, hit := m.cache[key]; hit {
		item := ele.Value.(*managerItem)
		old := item.client
		item.client = client
		item.lastUsed = now
		m.ll.MoveToFront(ele)
		if old != client {
			return old
		}
		return nil
	}
	ele := m.ll.PushFront(&managerItem{key, client, now})
	m.cache[key] = ele
	if m.MaxSize != 0 && m.ll.Len() > m.MaxSize {
		return m.removeElementLocked(m.ll.Back())
	}
	return nil
}

// Get gets a Client from the manager. If a Client is not found in the manager
// or if a Client has remained in the manager longer than MaxAge, Get will call
// the ClientManager's Factory function, store the result in the manager if
// non-nil, and return it. If Add supplies a client while Factory is running,
// Get returns the added client.
func (m *ClientManager) Get(certificate tls.Certificate) (client *Client) {
	m.initInternals()
	key := cacheKey(certificate)
	m.mu.Lock()
	var stale *Client
	if ele, hit := m.cache[key]; hit {
		item := ele.Value.(*managerItem)
		now := time.Now()
		if m.MaxAge == 0 || item.lastUsed.After(now.Add(-m.MaxAge)) {
			item.lastUsed = now
			m.ll.MoveToFront(ele)
			cached := item.client
			m.mu.Unlock()
			return cached
		}
		stale = item.client
	}
	if call, ok := m.pending[key]; ok {
		m.mu.Unlock()
		<-call.done
		return call.client
	}
	call := &pendingClient{done: make(chan struct{})}
	m.pending[key] = call
	factory := m.Factory
	m.mu.Unlock()

	completed := false
	defer func() {
		var retired *Client
		m.mu.Lock()
		delete(m.pending, key)
		if call.added != nil {
			if call.client != call.added {
				retired = call.client
			}
			call.client = call.added
		} else if call.client != nil {
			retired = m.addLocked(key, call.client, time.Now())
		} else if ele, hit := m.cache[key]; completed && hit && stale != nil && ele.Value.(*managerItem).client == stale {
			retired = m.removeElementLocked(ele)
		}
		client = call.client
		m.mu.Unlock()
		close(call.done)
		closeClientIdleConnections(retired)
	}()
	if factory != nil {
		call.client = factory(certificate)
	}
	completed = true
	return call.client
}

// Len returns the current size of the ClientManager.
func (m *ClientManager) Len() int {
	m.initInternals()
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ll.Len()
}

func (m *ClientManager) initInternals() {
	m.once.Do(func() {
		m.cache = map[[sha1.Size]byte]*list.Element{}
		m.pending = map[[sha1.Size]byte]*pendingClient{}
		m.ll = list.New()
	})
}

func (m *ClientManager) removeElementLocked(e *list.Element) *Client {
	m.ll.Remove(e)
	item := e.Value.(*managerItem)
	delete(m.cache, item.key)
	return item.client
}

func closeClientIdleConnections(client *Client) {
	if client != nil && client.httpClient != nil {
		client.CloseIdleConnections()
	}
}

func cacheKey(certificate tls.Certificate) [sha1.Size]byte {
	var data []byte

	for _, cert := range certificate.Certificate {
		data = append(data, cert...)
	}

	return sha1.Sum(data)
}
