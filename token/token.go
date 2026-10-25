package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"os"
	"sync"
	"time"
)

const (
	// TokenTimeout is how long Bearer reuses a signed token before refreshing
	// it. Apple requires refreshing no more than once every 20 minutes and no
	// less than once every 60 minutes, and rejects tokens issued more than an
	// hour ago. Bearer only refreshes expired tokens; there is no forced refresh.
	TokenTimeout = 50 * time.Minute

	// minRefresh is how often APNs allows a new token on one connection.
	minRefresh = 20 * time.Minute
)

// Possible errors when parsing a .p8 file.
var (
	ErrAuthKeyNotPem   = errors.New("token: AuthKey must be a valid .p8 PEM file")
	ErrAuthKeyNotECDSA = errors.New("token: AuthKey must be of type ecdsa.PrivateKey")
	ErrAuthKeyNil      = errors.New("token: AuthKey was nil")
	ErrAuthKeyCurve    = errors.New("token: AuthKey must use the P-256 curve")
)

// Token represents an Apple Provider Authentication Token (JSON Web Token).
// Set AuthKey, KeyID, and TeamID before sharing a token and do not change them
// during use. Share one Token per signing identity. Its methods are safe to
// call concurrently.
type Token struct {
	mu       sync.Mutex
	AuthKey  *ecdsa.PrivateKey
	KeyID    string
	TeamID   string
	issuedAt int64
	bearer   string
	restored bool
}

// AuthKeyFromFile loads a .p8 signing key from a local file and returns a
// *ecdsa.PrivateKey.
func AuthKeyFromFile(filename string) (*ecdsa.PrivateKey, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return AuthKeyFromBytes(bytes)
}

// AuthKeyFromBytes loads a .p8 signing key from an in memory byte array and
// returns an *ecdsa.PrivateKey.
func AuthKeyFromBytes(bytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, ErrAuthKeyNotPem
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if pk, ok := key.(*ecdsa.PrivateKey); ok {
		if pk.Curve != elliptic.P256() {
			return nil, ErrAuthKeyCurve
		}
		return pk, nil
	}
	return nil, ErrAuthKeyNotECDSA
}

// Bearer returns the cached token, refreshing it when necessary.
// If signing fails, it returns an empty string and the signing error.
func (t *Token) Bearer() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.bearer == "" || t.expiredLocked() {
		if err := t.generateLocked(); err != nil {
			return "", err
		}
	}
	return t.bearer, nil
}

// IssuedAt returns when the cached bearer was signed, or the zero time if
// none has been signed or restored.
func (t *Token) IssuedAt() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.bearer == "" {
		return time.Time{}
	}
	return time.Unix(t.issuedAt, 0)
}

// Restore caches a bearer signed earlier for the same AuthKey, KeyID and
// TeamID, so a short-lived process can reuse it instead of signing a new one.
// APNs rejects provider token updates more often than every 20 minutes.
// Bearer replaces the restored token once it expires. Restore does not verify
// the bearer, and ignores an issue time in the future or older than
// TokenTimeout.
func (t *Token) Restore(bearer string, issuedAt time.Time) {
	now := time.Now()
	if issuedAt.After(now) || !now.Before(issuedAt.Add(TokenTimeout)) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.bearer = bearer
	t.issuedAt = issuedAt.Unix()
	t.restored = true
}

// Invalidate drops bearer from the cache after APNs rejects it, so the next
// Bearer call signs a new token. It does nothing if bearer is no longer
// cached. It keeps a token this process signed less than 20 minutes ago:
// signing again with the same key wouldn't help, and APNs rejects tokens
// updated more often than every 20 minutes.
func (t *Token) Invalidate(bearer string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if bearer == "" || bearer != t.bearer {
		return
	}
	if !t.restored && time.Since(time.Unix(t.issuedAt, 0)) < minRefresh {
		return
	}
	t.bearer = ""
	t.issuedAt = 0
	t.restored = false
}

func (t *Token) expiredLocked() bool {
	return !time.Now().Before(time.Unix(t.issuedAt, 0).Add(TokenTimeout))
}

func (t *Token) generateLocked() error {
	if t.AuthKey == nil {
		return ErrAuthKeyNil
	}
	if t.AuthKey.Curve != elliptic.P256() {
		return ErrAuthKeyCurve
	}
	issuedAt := time.Now().Unix()
	header, err := json.Marshal(struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}{"ES256", t.KeyID})
	if err != nil {
		return err
	}
	claims, err := json.Marshal(struct {
		Issuer   string `json:"iss"`
		IssuedAt int64  `json:"iat"`
	}{t.TeamID, issuedAt})
	if err != nil {
		return err
	}
	encoding := base64.RawURLEncoding
	signingString := encoding.EncodeToString(header) + "." + encoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingString))
	r, s, err := ecdsa.Sign(rand.Reader, t.AuthKey, digest[:])
	if err != nil {
		return err
	}
	// ES256 uses two fixed-width, 32-byte integers, rather than ASN.1 DER.
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	bearer := signingString + "." + encoding.EncodeToString(signature)
	t.issuedAt = issuedAt
	t.bearer = bearer
	t.restored = false
	return nil
}
