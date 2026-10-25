package apns2

import (
	"container/list"
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jaakkonakaza/apns2/token"
)

type managerKey struct {
	certificate [sha1.Size]byte
	token       bool
	teamID      string
	keyID       string
	publicKey   string
	host        string
}

type pendingClient struct {
	done    chan struct{}
	client  *Client
	added   *Client // Latest explicit Add while Factory is running. Protected by the manager mutex.
	removed bool
}

type managerItem struct {
	key      managerKey
	client   *Client
	lastUsed time.Time
}

// ClientManager manages cached APNs clients. Set its configuration before
// concurrent use. Factories run without the manager lock, and concurrent lookups
// for the same identity share one factory call. Factories may use the manager,
// but must not look up the identity they are building.
type ClientManager struct {
	// MaxSize is the maximum number of clients allowed in the manager. When
	// this limit is reached, the least recently used client is evicted. Set
	// zero for no limit.
	MaxSize int

	// MaxAge is the maximum age of clients in the manager. Upon retrieval, if
	// a client has remained unused in the manager for this duration or longer,
	// it is replaced using the corresponding factory, or evicted if it returns nil.
	// Set zero to disable expiration, the default: Apple recommends reusing connections
	// for hours or days.
	MaxAge time.Duration

	// Factory is the function which constructs clients if not found in the
	// manager.
	Factory func(certificate tls.Certificate) *Client

	// Host is the APNs host for token clients. Configure it before concurrent use.
	Host string

	// TokenFactory constructs a token client for a signing identity and host.
	// It runs outside the manager lock. Concurrent lookups for the same identity
	// and host share one call. The result must use the supplied host.
	// A nil factory or result leaves the identity uncached.
	TokenFactory func(t *token.Token, host string) *Client

	cache   map[managerKey]*list.Element
	pending map[managerKey]*pendingClient
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
// By default, MaxSize is 64, MaxAge is zero (no expiry), and Factory always returns
// a Client with the supplied constructor options. Include WithHost, because
// clients have no default host. WithHTTPClient is unsupported
// and causes a panic. Use Factory to supply a separate HTTP client for each
// certificate, or TokenFactory for each token identity.
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
		Host:    config.host,
		Factory: func(certificate tls.Certificate) *Client { return NewClient(certificate, options...) },
		TokenFactory: func(t *token.Token, host string) *Client {
			tokenOptions := append(append([]ClientOption(nil), options...), WithHost(host))
			return NewTokenClient(t, tokenOptions...)
		},
	}

	manager.initInternals()

	return manager
}

// Add stores an individually configured certificate or token client. Token
// clients use their Host and signing identity as the cache key.
func (m *ClientManager) Add(client *Client) error {
	if client == nil {
		return errors.New("apns2: client is nil")
	}
	key := cacheKey(client.Certificate)
	if client.Token != nil {
		var err error
		key, err = tokenCacheKey(client.Token, client.Host)
		if err != nil {
			return err
		}
	}
	m.initInternals()
	m.mu.Lock()
	retired := m.addLocked(key, client, time.Now())
	if call := m.pending[key]; call != nil {
		call.added = client
	}
	m.mu.Unlock()
	closeClientIdleConnections(retired)
	return nil
}

func (m *ClientManager) addLocked(key managerKey, client *Client, now time.Time) *Client {
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
	return m.get(cacheKey(certificate), func() *Client {
		if m.Factory == nil {
			return nil
		}
		return m.Factory(certificate)
	})
}

func (m *ClientManager) get(key managerKey, factory func() *Client) (client *Client) {
	m.initInternals()
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
	m.mu.Unlock()

	completed := false
	defer func() {
		var retired *Client
		m.mu.Lock()
		if m.pending[key] == call {
			delete(m.pending, key)
		}
		if call.removed {
			retired = call.client
			call.client = nil
		} else if call.added != nil {
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
		call.client = factory()
	}
	completed = true
	return call.client
}

// GetByToken gets a token-authenticated client for the manager's Host. Tokens
// with the same team ID, key ID and public key share a client. Refreshing a
// bearer does not change its cache identity. Invalid signing keys return errors.
func (m *ClientManager) GetByToken(t *token.Token) (*Client, error) {
	key, err := tokenCacheKey(t, m.Host)
	if err != nil {
		return nil, err
	}
	return m.get(key, func() *Client {
		if m.TokenFactory == nil {
			return nil
		}
		return m.TokenFactory(t, key.host)
	}), nil
}

// Remove removes the cached certificate client and closes its idle connections.
// It also prevents a factory call already in progress from caching its result.
// That call and its waiters return nil. A later Get can create a fresh client.
func (m *ClientManager) Remove(certificate tls.Certificate) bool {
	return m.remove(cacheKey(certificate))
}

// RemoveByToken removes the token client for the signing identity and the
// manager's Host. It closes idle connections and discards pending construction,
// as Remove does. In-use requests are not interrupted.
func (m *ClientManager) RemoveByToken(t *token.Token) (bool, error) {
	key, err := tokenCacheKey(t, m.Host)
	if err != nil {
		return false, err
	}
	return m.remove(key), nil
}

func (m *ClientManager) remove(key managerKey) bool {
	m.initInternals()
	m.mu.Lock()
	var retired *Client
	if ele := m.cache[key]; ele != nil {
		retired = m.removeElementLocked(ele)
	}
	call := m.pending[key]
	if call != nil {
		call.removed = true
		delete(m.pending, key)
	}
	m.mu.Unlock()
	closeClientIdleConnections(retired)
	return retired != nil || call != nil
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
		m.cache = map[managerKey]*list.Element{}
		m.pending = map[managerKey]*pendingClient{}
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

func cacheKey(certificate tls.Certificate) managerKey {
	var data []byte

	for _, cert := range certificate.Certificate {
		data = append(data, cert...)
	}

	return managerKey{certificate: sha1.Sum(data)}
}

func tokenCacheKey(t *token.Token, host string) (managerKey, error) {
	if t == nil || t.AuthKey == nil {
		return managerKey{}, token.ErrAuthKeyNil
	}
	if t.AuthKey.Curve != elliptic.P256() {
		return managerKey{}, token.ErrAuthKeyCurve
	}
	publicKey, err := t.AuthKey.PublicKey.Bytes()
	if err != nil {
		return managerKey{}, fmt.Errorf("apns2: token public key: %w", err)
	}
	return managerKey{token: true, teamID: t.TeamID, keyID: t.KeyID, publicKey: string(publicKey), host: host}, nil
}
