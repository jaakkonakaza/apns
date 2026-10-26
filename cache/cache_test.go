package cache

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jaakkonakaza/apns"
	"github.com/jaakkonakaza/apns/certificate"
	"github.com/jaakkonakaza/apns/token"
)

func testProvider(t *testing.T, id string) *token.Token {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := token.New(key, id, "TEAM")
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func newTestCache(t *testing.T, cfg Config) *Cache {
	t.Helper()
	if cfg.Client.Environment == 0 {
		cfg.Client.Environment = apns.Sandbox
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Clear)
	return c
}

func getToken(t *testing.T, c *Cache, provider *token.Token) *apns.Client {
	t.Helper()
	client, err := c.Token(provider)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestConfiguration(t *testing.T) {
	for _, cfg := range []Config{{}, {Client: apns.Config{Environment: apns.Environment(99)}}, {Client: apns.Config{Environment: apns.Sandbox}, MaxEntries: -1}, {Client: apns.Config{Environment: apns.Sandbox}, MaxAge: -1}, {Client: apns.Config{Environment: apns.Sandbox, Transport: apns.TransportConfig{IdleConnTimeout: new(time.Duration(0))}}}} {
		if _, err := New(cfg); err == nil {
			t.Fatal("accepted invalid configuration")
		}
	}
	cfg := Config{Client: apns.Config{Environment: apns.Sandbox, RequestTimeout: new(time.Second)}}
	c := newTestCache(t, cfg)
	*cfg.Client.RequestTimeout = 2 * time.Second
	if *c.config.RequestTimeout != time.Second || *c.config.Transport.IdleConnTimeout != time.Minute || c.maxEntries != 64 || c.maxAge != 30*time.Minute {
		t.Fatal("configuration not copied/defaulted")
	}
}

func TestIdentityIsolationAndRemoval(t *testing.T) {
	c := newTestCache(t, Config{})
	first := testProvider(t, "KEY1")
	second := testProvider(t, "KEY2")
	a := getToken(t, c, first)
	if getToken(t, c, first) != a {
		t.Fatal("did not reuse client")
	}
	if getToken(t, c, second) == a {
		t.Fatal("identities aliased")
	}
	if removed, err := c.RemoveToken(first); err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if getToken(t, c, first) == a {
		t.Fatal("removed client reused")
	}
	if _, err := c.Token(nil); err == nil {
		t.Fatal("accepted nil provider")
	}
	if _, err := c.RemoveToken(nil); err == nil {
		t.Fatal("accepted nil provider removal")
	}
	cert, err := certificate.FromPEMFile("../certificate/testdata/certificate-valid.pem")
	if err != nil {
		t.Fatal(err)
	}
	certClient, err := c.Certificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.Certificate(cert)
	if err != nil || again != certClient {
		t.Fatal("certificate not reused")
	}
	if removed, err := c.RemoveCertificate(cert); err != nil || !removed {
		t.Fatal("certificate not removed")
	}
	if _, err := c.Certificate(tls.Certificate{}); err == nil {
		t.Fatal("accepted missing certificate")
	}
	c.Clear()
	if c.Len() != 0 {
		t.Fatal("clear retained clients")
	}
}

func TestLRUEvictionAndExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newTestCache(t, Config{MaxEntries: 2, MaxAge: time.Minute})
		a, b, d := testProvider(t, "A"), testProvider(t, "B"), testProvider(t, "D")
		first := getToken(t, c, a)
		second := getToken(t, c, b)
		time.Sleep(time.Second)
		if getToken(t, c, a) != first {
			t.Fatal("hit missed")
		}
		getToken(t, c, d)
		if c.Len() != 2 {
			t.Fatal("cache not bounded")
		}
		if getToken(t, c, b) == second {
			t.Fatal("LRU not evicted")
		}
		time.Sleep(time.Minute - time.Nanosecond)
		if c.Len() != 2 {
			t.Fatal("expired before boundary")
		}
		time.Sleep(time.Nanosecond)
		if c.Len() != 0 {
			t.Fatal("not expired at boundary")
		}
	})
}

func TestConcurrentLookupAndReentrantDecorator(t *testing.T) {
	provider := testProvider(t, "KEY")
	var c *Cache
	var constructors atomic.Int32
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	defer release()
	c = newTestCache(t, Config{Client: apns.Config{Environment: apns.Sandbox, Transport: apns.TransportConfig{Decorate: func(base http.RoundTripper) http.RoundTripper {
		constructors.Add(1)
		c.Len()
		<-gate
		return base
	}}}})
	const count = 16
	var wg sync.WaitGroup
	clients := make(chan *apns.Client, count)
	for range count {
		wg.Go(func() {
			client, err := c.Token(provider)
			if err != nil {
				t.Error(err)
				return
			}
			clients <- client
		})
	}
	deadline := time.Now().Add(3 * time.Second)
	for constructors.Load() < count {
		if time.Now().After(deadline) {
			t.Fatal("constructors did not reach reentrant callback")
		}
		time.Sleep(time.Millisecond)
	}
	release()
	wg.Wait()
	close(clients)
	var winner *apns.Client
	for client := range clients {
		if winner == nil {
			winner = client
		}
		if client != winner {
			t.Fatal("concurrent miss returned different retained clients")
		}
	}
	if c.Len() != 1 {
		t.Fatal("duplicate entries")
	}
}

func TestEvictionPreservesActiveSendAndEventuallyClosesIdle(t *testing.T) {
	started, release, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	defer releaseOnce()
	var startOnce, closeOnce sync.Once
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Error("not HTTP/2")
		}
		startOnce.Do(func() { close(started) })
		<-release
		_, _ = io.WriteString(w, "")
	}))
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closeOnce.Do(func() { close(closed) })
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"api.sandbox.push.apple.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	c := newTestCache(t, Config{Client: apns.Config{Environment: apns.Sandbox, Transport: apns.TransportConfig{RootCAs: roots, IdleConnTimeout: new(30 * time.Millisecond), DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}}})
	client := getToken(t, c, testProvider(t, "KEY"))
	done := make(chan error, 1)
	go func() {
		_, err := client.Push(context.Background(), apns.Request{DeviceToken: "aabbcc", Topic: "com.example", PushType: apns.PushTypeAlert, Payload: map[string]any{}})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("send did not start")
	}
	c.Clear()
	if c.Len() != 0 {
		t.Fatal("clear retained entry")
	}
	select {
	case err := <-done:
		t.Fatalf("eviction interrupted active request: %v", err)
	default:
	}
	releaseOnce()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("active send did not finish")
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("evicted connection did not close after becoming idle")
	}
}

func BenchmarkCacheHit(b *testing.B) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	provider, err := token.New(key, "KEY", "TEAM")
	if err != nil {
		b.Fatal(err)
	}
	clients, err := New(Config{Client: apns.Config{Environment: apns.Sandbox}})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(clients.Clear)
	if _, err := clients.Token(provider); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := clients.Token(provider); err != nil {
			b.Fatal(err)
		}
	}
}

type mapSigner map[string]bool

func (mapSigner) Public() crypto.PublicKey { panic("nil map signer was invoked") }
func (mapSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("nil map signer was invoked")
}

type sliceSigner []byte

func (sliceSigner) Public() crypto.PublicKey { panic("nil slice signer was invoked") }
func (sliceSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("nil slice signer was invoked")
}

type functionSigner func()

func (functionSigner) Public() crypto.PublicKey { panic("nil function signer was invoked") }
func (functionSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("nil function signer was invoked")
}

type channelSigner chan struct{}

func (channelSigner) Public() crypto.PublicKey { panic("nil channel signer was invoked") }
func (channelSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("nil channel signer was invoked")
}

func TestTypedNilCertificateSigners(t *testing.T) {
	c := newTestCache(t, Config{})
	for _, signer := range []crypto.Signer{(*ecdsa.PrivateKey)(nil), mapSigner(nil), sliceSigner(nil), functionSigner(nil), channelSigner(nil)} {
		cert := tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: signer}
		if _, err := c.Certificate(cert); err == nil {
			t.Fatalf("accepted nil signer %T", signer)
		}
		if _, err := c.RemoveCertificate(cert); err == nil {
			t.Fatalf("accepted nil signer removal %T", signer)
		}
	}
}

func TestCertificateTLSMetadataDoesNotAlias(t *testing.T) {
	c := newTestCache(t, Config{})
	original, err := certificate.FromPEMFile("../certificate/testdata/certificate-valid.pem")
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := c.Certificate(original)
	if err != nil {
		t.Fatal(err)
	}
	algorithms := original
	algorithms.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.PKCS1WithSHA256}
	ocsp := original
	ocsp.OCSPStaple = []byte("staple")
	timestamps := original
	timestamps.SignedCertificateTimestamps = [][]byte{[]byte("timestamp")}
	for _, variant := range []tls.Certificate{algorithms, ocsp, timestamps} {
		other, err := c.Certificate(variant)
		if err != nil {
			t.Fatal(err)
		}
		if other == baseline {
			t.Fatal("different certificate TLS metadata reused earlier policy")
		}
	}
	if c.Len() != 4 {
		t.Fatal("certificate variants not retained separately")
	}
}

type invalidPublicKeySigner struct{}

func (invalidPublicKeySigner) Public() crypto.PublicKey {
	return struct{ Secret string }{Secret: "sensitive-diagnostic"}
}

func (invalidPublicKeySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("invalid signer was used")
}

func TestCertificatePublicKeyErrorRetainsDiagnosticCause(t *testing.T) {
	c := newTestCache(t, Config{})
	_, err := c.Certificate(tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: invalidPublicKeySigner{}})
	if err == nil || errors.Unwrap(err) == nil {
		t.Fatal("public-key failure lost diagnostic cause")
	}
	if strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "invalidPublicKeySigner") {
		t.Fatal("public-key summary exposed diagnostic input")
	}
}
