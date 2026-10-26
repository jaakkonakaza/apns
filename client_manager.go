package apns

import (
	"container/list"
	"crypto/sha1"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jaakkonakaza/apns/token"
)

// ErrClientRemoved means an entry was removed while its client was being built.
var ErrClientRemoved = errors.New("apns: client removed during construction")

// ErrClientUnavailable means a factory is absent or returned no client.
var ErrClientUnavailable = errors.New("apns: client factory returned no client")

// ManagerConfig configures a cache and its client factories.
// Set configuration before calling NewClientManager. Later changes do not affect it.
type ManagerConfig struct {
	// Host is the APNs endpoint shared by cached clients.
	Host string

	// MaxSize limits cached clients. Zero means no limit.
	MaxSize int

	// MaxAge expires clients after this much time without use. Cache operations
	// retire expired entries. Zero disables expiry.
	MaxAge time.Duration

	// ClientOptions configure the default factories. Host is set by Host above.
	// WithHTTPClient is unsupported because identities need independent connections.
	// Supply a custom factory to configure an HTTP client per identity.
	ClientOptions []ClientOption

	// Factory constructs certificate clients outside the cache lock.
	// It must use Host and must not look up the identity it is constructing.
	Factory func(tls.Certificate) (*Client, error)

	// TokenFactory constructs token clients outside the cache lock.
	// It must use the supplied host and must not look up the identity it is constructing.
	TokenFactory func(*token.Token, string) (*Client, error)
}

type managerKey struct {
	certificate [sha1.Size]byte
	token       token.Identity
	tokenAuth   bool
	host        string
}

type pendingClient struct {
	done    chan struct{}
	client  *Client
	err     error
	added   *Client
	removed bool
}

type managerItem struct {
	key      managerKey
	client   *Client
	lastUsed time.Time
}

// ClientManager caches clients by certificate or token signing identity and host.
// Concurrent lookups for one identity share a factory call. Cache cleanup never
// interrupts requests in use. The zero value can be inspected but has no factories.
type ClientManager struct {
	host         string
	maxSize      int
	maxAge       time.Duration
	factory      func(tls.Certificate) (*Client, error)
	tokenFactory func(*token.Token, string) (*Client, error)

	cache   map[managerKey]*list.Element
	pending map[managerKey]*pendingClient
	ll      *list.List
	mu      sync.Mutex
	once    sync.Once
}

// NewClientManager constructs a client cache without making network connections.
// The default factories use config.Host and config.ClientOptions. Custom factories
// must return independent clients configured for the same host.
func NewClientManager(config ManagerConfig) (*ClientManager, error) {
	if err := validateHost(config.Host, true); err != nil {
		return nil, err
	}
	config.Host = strings.TrimSuffix(config.Host, "/")
	if config.MaxSize < 0 || config.MaxAge < 0 {
		return nil, errors.New("apns: cache limits must not be negative")
	}
	clientConfig, err := clientConfigForOptions(config.ClientOptions)
	if err != nil {
		return nil, err
	}
	if clientConfig.httpClient != nil {
		return nil, errors.New("apns: manager ClientOptions cannot include WithHTTPClient, use a per-identity factory")
	}
	if clientConfig.hostSet && strings.TrimSuffix(clientConfig.host, "/") != config.Host {
		return nil, errors.New("apns: manager Host conflicts with WithHost")
	}
	clientConfig.host = config.Host
	if config.Factory == nil || config.TokenFactory == nil {
		if err := validateClientConfig(clientConfig); err != nil {
			return nil, err
		}
	}
	if clientConfig.tlsConfig != nil {
		clientConfig.tlsConfig = clientConfig.tlsConfig.Clone()
	}
	manager := &ClientManager{
		host: config.Host, maxSize: config.MaxSize, maxAge: config.MaxAge,
		factory: config.Factory, tokenFactory: config.TokenFactory,
	}
	if manager.factory == nil {
		manager.factory = func(certificate tls.Certificate) (*Client, error) {
			return newCertificateClient(certificate, clientConfig)
		}
	}
	if manager.tokenFactory == nil {
		manager.tokenFactory = func(t *token.Token, host string) (*Client, error) {
			return newTokenClient(t, clientConfig)
		}
	}
	manager.initInternals()
	return manager, nil
}

// Host returns the configured APNs endpoint.
func (m *ClientManager) Host() string { return m.host }

// Add stores a configured client for this manager's host and signing identity.
func (m *ClientManager) Add(client *Client) error {
	if client == nil {
		return errors.New("apns: client is nil")
	}
	if client.host != m.host {
		return errors.New("apns: client host does not match manager host")
	}
	key := certificateCacheKey(client.certificate, client.host)
	if client.token != nil {
		var err error
		key, err = tokenCacheKey(client.token, client.host)
		if err != nil {
			return err
		}
	}
	m.initInternals()
	m.mu.Lock()
	now := time.Now()
	retired := []*Client{m.addLocked(key, client, now)}
	retired = append(retired, m.expireLocked(now)...)
	if call := m.pending[key]; call != nil {
		call.added = client
	}
	m.mu.Unlock()
	for _, old := range retired {
		closeClientIdleConnections(old)
	}
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
	if m.maxSize != 0 && m.ll.Len() > m.maxSize {
		return m.removeElementLocked(m.ll.Back())
	}
	return nil
}

// Get returns the cached certificate client or constructs it with Factory.
// Construction failures are returned to every waiter. If Add supplies a client
// while construction is running, Get returns the added client instead.
func (m *ClientManager) Get(certificate tls.Certificate) (*Client, error) {
	return m.get(certificateCacheKey(certificate, m.host), func() (*Client, error) {
		if m.factory == nil {
			return nil, ErrClientUnavailable
		}
		return m.factory(certificate)
	})
}

func (m *ClientManager) get(key managerKey, factory func() (*Client, error)) (client *Client, err error) {
	m.initInternals()
	m.mu.Lock()
	now := time.Now()
	expired := m.expireLocked(now)
	if ele, hit := m.cache[key]; hit {
		item := ele.Value.(*managerItem)
		item.lastUsed = now
		m.ll.MoveToFront(ele)
		cached := item.client
		m.mu.Unlock()
		for _, old := range expired {
			closeClientIdleConnections(old)
		}
		return cached, nil
	}
	if call, ok := m.pending[key]; ok {
		m.mu.Unlock()
		for _, old := range expired {
			closeClientIdleConnections(old)
		}
		<-call.done
		return call.client, call.err
	}
	call := &pendingClient{done: make(chan struct{})}
	m.pending[key] = call
	m.mu.Unlock()
	for _, old := range expired {
		closeClientIdleConnections(old)
	}
	defer func() {
		var retired []*Client
		m.mu.Lock()
		if m.pending[key] == call {
			delete(m.pending, key)
		}
		if call.removed {
			retired = append(retired, call.client)
			call.client, call.err = nil, ErrClientRemoved
		} else if call.added != nil {
			if call.client != call.added {
				retired = append(retired, call.client)
			}
			call.client, call.err = call.added, nil
		} else if call.err == nil && call.client != nil {
			retired = append(retired, m.addLocked(key, call.client, time.Now()))
		} else {
			retired = append(retired, call.client)
			call.client = nil
			if call.err == nil {
				call.err = ErrClientUnavailable
			}
		}
		client, err = call.client, call.err
		m.mu.Unlock()
		close(call.done)
		for _, old := range retired {
			closeClientIdleConnections(old)
		}
	}()
	call.client, call.err = factory()
	if call.err == nil && call.client != nil {
		actual := certificateCacheKey(call.client.certificate, call.client.host)
		if call.client.token != nil {
			actual, call.err = tokenCacheKey(call.client.token, call.client.host)
		}
		if call.err == nil && actual != key {
			call.err = errors.New("apns: factory client does not match the requested identity and host")
		}
	}
	return call.client, call.err
}

// GetByToken returns a client for the token's team, key ID, public key and host.
// Bearer refreshes do not change the cache identity.
func (m *ClientManager) GetByToken(t *token.Token) (*Client, error) {
	key, err := tokenCacheKey(t, m.host)
	if err != nil {
		return nil, err
	}
	return m.get(key, func() (*Client, error) {
		if m.tokenFactory == nil {
			return nil, ErrClientUnavailable
		}
		return m.tokenFactory(t, key.host)
	})
}

// Remove removes the certificate client and closes its idle connections.
// In-progress construction and its waiters receive ErrClientRemoved. A later
// lookup can construct a fresh client. Requests already in use are unaffected.
func (m *ClientManager) Remove(certificate tls.Certificate) bool {
	return m.remove(certificateCacheKey(certificate, m.host))
}

// RemoveByToken removes the signing identity's client, as Remove does.
func (m *ClientManager) RemoveByToken(t *token.Token) (bool, error) {
	key, err := tokenCacheKey(t, m.host)
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
	expired := m.expireLocked(time.Now())
	call := m.pending[key]
	if call != nil {
		call.removed = true
		delete(m.pending, key)
	}
	m.mu.Unlock()
	for _, old := range expired {
		closeClientIdleConnections(old)
	}
	closeClientIdleConnections(retired)
	return retired != nil || call != nil
}

// CloseIdleConnections closes idle connections on all cached clients.
// It retains unexpired entries and does not interrupt requests already in use.
func (m *ClientManager) CloseIdleConnections() {
	m.initInternals()
	m.mu.Lock()
	clients := m.expireLocked(time.Now())
	for _, ele := range m.cache {
		clients = append(clients, ele.Value.(*managerItem).client)
	}
	m.mu.Unlock()
	for _, client := range clients {
		closeClientIdleConnections(client)
	}
}

// Len returns the number of unexpired cached clients.
func (m *ClientManager) Len() int {
	m.initInternals()
	m.mu.Lock()
	expired := m.expireLocked(time.Now())
	length := m.ll.Len()
	m.mu.Unlock()
	for _, old := range expired {
		closeClientIdleConnections(old)
	}
	return length
}

func (m *ClientManager) expireLocked(now time.Time) []*Client {
	var expired []*Client
	if m.maxAge == 0 {
		return expired
	}
	cutoff := now.Add(-m.maxAge)
	for ele := m.ll.Back(); ele != nil; ele = m.ll.Back() {
		if ele.Value.(*managerItem).lastUsed.After(cutoff) {
			break
		}
		expired = append(expired, m.removeElementLocked(ele))
	}
	return expired
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

func certificateCacheKey(certificate tls.Certificate, host string) managerKey {
	var data []byte
	for _, cert := range certificate.Certificate {
		data = append(data, cert...)
	}
	return managerKey{certificate: sha1.Sum(data), host: host}
}

func tokenCacheKey(t *token.Token, host string) (managerKey, error) {
	identity, err := t.Identity()
	if err != nil {
		return managerKey{}, fmt.Errorf("apns: token identity: %w", err)
	}
	return managerKey{tokenAuth: true, token: identity, host: host}, nil
}
