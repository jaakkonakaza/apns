// Package cache optionally retains APNs clients for multiple signing identities.
package cache

import (
	"container/list"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jaakkonakaza/apns"
	"github.com/jaakkonakaza/apns/internal/credential"
	"github.com/jaakkonakaza/apns/token"
)

// Config fixes client policy for all entries. Zero limits select 64 entries and
// 30 minutes since last lookup. Retained client references remain usable after
// eviction, so caller activity may create new connections outside this cache.
type Config struct {
	Client     apns.Config
	MaxEntries int
	MaxAge     time.Duration
}

type key struct {
	token       token.Identity
	certificate [32]byte
	tokenAuth   bool
}

type entry struct {
	key    key
	client *apns.Client
	used   time.Time
}

// Cache is safe for concurrent use. Use New to initialize it. Lookups construct
// clients lazily without opening connections. Concurrent misses may construct
// duplicate clients, but only one is retained. No application callback runs
// while the cache mutex is held.
type Cache struct {
	mu         sync.Mutex
	config     apns.Config
	maxEntries int
	maxAge     time.Duration
	entries    map[key]*list.Element
	order      *list.List
}

// New validates cache policy without creating clients or starting background work.
// Remaining client transport policy is validated when a lookup constructs a client.
// Cached transports require finite idle retention so an active connection that
// survives eviction can close after it becomes idle. Nil selects one minute.
func New(cfg Config) (*Cache, error) {
	if cfg.Client.Environment != apns.Sandbox && cfg.Client.Environment != apns.Production {
		return nil, errors.New("apns/cache: environment is required")
	}
	if cfg.MaxEntries < 0 || cfg.MaxAge < 0 {
		return nil, errors.New("apns/cache: limits must not be negative")
	}
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = 64
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 30 * time.Minute
	}
	idle := time.Minute
	if cfg.Client.Transport.IdleConnTimeout != nil {
		idle = *cfg.Client.Transport.IdleConnTimeout
	}
	if idle <= 0 {
		return nil, errors.New("apns/cache: idle retention must be positive")
	}
	cfg.Client.Transport.IdleConnTimeout = new(idle)
	cloneDuration := func(value *time.Duration) *time.Duration {
		if value == nil {
			return nil
		}
		return new(*value)
	}
	cfg.Client.RequestTimeout = cloneDuration(cfg.Client.RequestTimeout)
	cfg.Client.Transport.DialTimeout = cloneDuration(cfg.Client.Transport.DialTimeout)
	cfg.Client.Transport.HTTP2.ReadIdleTimeout = cloneDuration(cfg.Client.Transport.HTTP2.ReadIdleTimeout)
	cfg.Client.Transport.HTTP2.PingTimeout = cloneDuration(cfg.Client.Transport.HTTP2.PingTimeout)
	cfg.Client.Transport.HTTP2.WriteByteTimeout = cloneDuration(cfg.Client.Transport.HTTP2.WriteByteTimeout)
	if cfg.Client.Transport.RootCAs != nil {
		cfg.Client.Transport.RootCAs = cfg.Client.Transport.RootCAs.Clone()
	}
	if cfg.Client.Transport.ProxyRootCAs != nil {
		cfg.Client.Transport.ProxyRootCAs = cfg.Client.Transport.ProxyRootCAs.Clone()
	}
	return &Cache{config: cfg.Client, maxEntries: cfg.MaxEntries, maxAge: cfg.MaxAge, entries: make(map[key]*list.Element), order: list.New()}, nil
}

// Token returns a client for the immutable signing identity. Share one Token
// per identity so all clients reuse the same provider bearer cache.
func (c *Cache) Token(provider *token.Token) (*apns.Client, error) {
	identity, err := provider.Identity()
	if err != nil {
		return nil, err
	}
	return c.get(key{token: identity, tokenAuth: true}, func() (*apns.Client, error) { return apns.NewTokenClient(provider, c.config) })
}

// Certificate returns a client for the certificate chain, signing public key,
// and TLS signature/OCSP/SCT metadata.
// The caller must not mutate external signing keys during use.
func (c *Cache) Certificate(cert tls.Certificate) (*apns.Client, error) {
	identity, err := certificateKey(cert)
	if err != nil {
		return nil, err
	}
	return c.get(identity, func() (*apns.Client, error) { return apns.NewCertificateClient(cert, c.config) })
}

func (c *Cache) get(k key, construct func() (*apns.Client, error)) (*apns.Client, error) {
	c.mu.Lock()
	expired := c.expireLocked(time.Now())
	if element := c.entries[k]; element != nil {
		item := element.Value.(*entry)
		item.used = time.Now()
		c.order.MoveToFront(element)
		client := item.client
		c.mu.Unlock()
		closeIdle(expired)
		return client, nil
	}
	c.mu.Unlock()
	closeIdle(expired)
	client, err := construct()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	expired = c.expireLocked(time.Now())
	if element := c.entries[k]; element != nil {
		item := element.Value.(*entry)
		item.used = time.Now()
		c.order.MoveToFront(element)
		winner := item.client
		c.mu.Unlock()
		closeIdle(append(expired, client))
		return winner, nil
	}
	c.entries[k] = c.order.PushFront(&entry{key: k, client: client, used: time.Now()})
	if c.order.Len() > c.maxEntries {
		expired = append(expired, c.removeLocked(c.order.Back()))
	}
	c.mu.Unlock()
	closeIdle(expired)
	return client, nil
}

// RemoveToken evicts an existing token entry. It does not cancel construction
// already underway or invalidate client references held by callers.
func (c *Cache) RemoveToken(provider *token.Token) (bool, error) {
	identity, err := provider.Identity()
	if err != nil {
		return false, err
	}
	return c.remove(key{token: identity, tokenAuth: true}), nil
}

// RemoveCertificate evicts an existing certificate entry.
func (c *Cache) RemoveCertificate(cert tls.Certificate) (bool, error) {
	identity, err := certificateKey(cert)
	if err != nil {
		return false, err
	}
	return c.remove(identity), nil
}

func (c *Cache) remove(k key) bool {
	c.mu.Lock()
	expired := c.expireLocked(time.Now())
	found := false
	if element := c.entries[k]; element != nil {
		expired = append(expired, c.removeLocked(element))
		found = true
	}
	c.mu.Unlock()
	closeIdle(expired)
	return found
}

// Clear removes cached entries and closes their idle connections. Active sends
// and client references held by callers remain valid. A lookup whose constructor
// is already running can insert an entry after Clear returns.
func (c *Cache) Clear() {
	c.mu.Lock()
	clients := make([]*apns.Client, 0, c.order.Len())
	for c.order.Len() != 0 {
		clients = append(clients, c.removeLocked(c.order.Back()))
	}
	c.mu.Unlock()
	closeIdle(clients)
}

// Len returns the number of entries after expiring unused entries.
func (c *Cache) Len() int {
	c.mu.Lock()
	expired := c.expireLocked(time.Now())
	n := c.order.Len()
	c.mu.Unlock()
	closeIdle(expired)
	return n
}

// CloseIdleConnections retains live entries and closes idle connections on each.
func (c *Cache) CloseIdleConnections() {
	c.mu.Lock()
	clients := c.expireLocked(time.Now())
	for _, element := range c.entries {
		clients = append(clients, element.Value.(*entry).client)
	}
	c.mu.Unlock()
	closeIdle(clients)
}

func (c *Cache) expireLocked(now time.Time) []*apns.Client {
	var clients []*apns.Client
	for element := c.order.Back(); element != nil; element = c.order.Back() {
		if now.Sub(element.Value.(*entry).used) < c.maxAge {
			break
		}
		clients = append(clients, c.removeLocked(element))
	}
	return clients
}

func (c *Cache) removeLocked(element *list.Element) *apns.Client {
	item := element.Value.(*entry)
	delete(c.entries, item.key)
	c.order.Remove(element)
	return item.client
}

func closeIdle(clients []*apns.Client) {
	for _, client := range clients {
		client.CloseIdleConnections()
	}
}

func certificateKey(cert tls.Certificate) (key, error) {
	encoded, err := credential.PublicKey(cert)
	if err != nil {
		return key{}, fmt.Errorf("apns/cache: %w", err)
	}
	hash := sha256.New()
	writeNumber := func(value uint64) {
		var data [8]byte
		binary.BigEndian.PutUint64(data[:], value)
		_, _ = hash.Write(data[:])
	}
	writePart := func(part []byte) {
		writeNumber(uint64(len(part)))
		_, _ = hash.Write(part)
	}
	writeNumber(uint64(len(cert.Certificate)))
	for _, part := range cert.Certificate {
		writePart(part)
	}
	writePart(encoded)
	writePart(cert.OCSPStaple)
	writeNumber(uint64(len(cert.SignedCertificateTimestamps)))
	for _, part := range cert.SignedCertificateTimestamps {
		writePart(part)
	}
	writeNumber(uint64(len(cert.SupportedSignatureAlgorithms)))
	for _, algorithm := range cert.SupportedSignatureAlgorithms {
		writeNumber(uint64(algorithm))
	}
	var sum [32]byte
	copy(sum[:], hash.Sum(nil))
	return key{certificate: sum}, nil
}
