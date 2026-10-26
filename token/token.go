// Package token creates and refreshes the provider tokens used for APNs token authentication.
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
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jaakkonakaza/apns/internal/redact"
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

// Errors returned for invalid signing credentials or snapshots.
var (
	ErrAuthKeyNotPEM   = errors.New("token: AuthKey must be a valid .p8 PEM file")
	ErrAuthKeyNotECDSA = errors.New("token: AuthKey must be of type ecdsa.PrivateKey")
	ErrAuthKeyNil      = errors.New("token: AuthKey was nil")
	ErrAuthKeyCurve    = errors.New("token: AuthKey must use the P-256 curve")
	ErrKeyIDMissing    = errors.New("token: key ID is required")
	ErrTeamIDMissing   = errors.New("token: team ID is required")
	ErrInvalidSnapshot = errors.New("token: invalid snapshot")
)

func invalidSnapshot(cause error) error {
	return redact.Error(ErrInvalidSnapshot.Error(), errors.Join(ErrInvalidSnapshot, cause))
}

// Identity identifies the signing credentials independently of a cached bearer.
// PublicKey is the SEC 1 uncompressed encoding of the P-256 public key.
// Identity is comparable and can be used as a cache key.
type Identity struct {
	TeamID    string
	KeyID     string
	PublicKey [65]byte
}

// Snapshot contains a bearer and its matching issue time for persistence.
type Snapshot struct {
	Bearer   string
	IssuedAt time.Time
}

// Token represents an Apple Provider Authentication Token (JSON Web Token).
// Its signing identity is immutable. Share one Token per identity.
// Its methods are safe to call concurrently. The zero value has no signing key.
type Token struct {
	mu       sync.Mutex
	authKey  *ecdsa.PrivateKey
	identity Identity
	issuedAt int64
	bearer   string
	restored bool
}

// New validates and copies a signing key and its identifiers. It does not sign
// a bearer until Bearer or Snapshot is called.
func New(authKey *ecdsa.PrivateKey, keyID, teamID string) (*Token, error) {
	if authKey == nil {
		return nil, ErrAuthKeyNil
	}
	if authKey.Curve != elliptic.P256() {
		return nil, ErrAuthKeyCurve
	}
	if keyID == "" {
		return nil, ErrKeyIDMissing
	}
	if teamID == "" {
		return nil, ErrTeamIDMissing
	}
	encoded, err := authKey.Bytes()
	if err != nil {
		return nil, redact.Error("token: invalid signing key", err)
	}
	copied, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), encoded)
	if err != nil {
		return nil, redact.Error("token: invalid signing key", err)
	}
	publicKey, err := copied.PublicKey.Bytes()
	if err != nil {
		return nil, redact.Error("token: invalid public key", err)
	}
	identity := Identity{TeamID: teamID, KeyID: keyID}
	copy(identity.PublicKey[:], publicKey)
	return &Token{authKey: copied, identity: identity}, nil
}

// Identity returns the token's immutable signing identity. It returns an error
// for a nil token or a token without a signing key.
func (t *Token) Identity() (Identity, error) {
	if t == nil || t.authKey == nil {
		return Identity{}, ErrAuthKeyNil
	}
	return t.identity, nil
}

// AuthKeyFromFile loads a .p8 signing key from a local file and returns a
// *ecdsa.PrivateKey.
func AuthKeyFromFile(filename string) (*ecdsa.PrivateKey, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, redact.Error("token: cannot read signing key", err)
	}
	return AuthKeyFromBytes(bytes)
}

// AuthKeyFromBytes loads a .p8 signing key from an in memory byte array and
// returns an *ecdsa.PrivateKey.
func AuthKeyFromBytes(bytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, ErrAuthKeyNotPEM
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, redact.Error("token: cannot parse signing key", err)
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
	snapshot, err := t.Snapshot()
	return snapshot.Bearer, err
}

// Snapshot returns a bearer and its matching issue time atomically, refreshing
// the bearer when necessary. Persist this pair together and pass it to Restore.
func (t *Token) Snapshot() (Snapshot, error) {
	if t == nil || t.authKey == nil {
		return Snapshot{}, ErrAuthKeyNil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.bearer == "" || t.expiredLocked() {
		if err := t.generateLocked(); err != nil {
			return Snapshot{}, err
		}
	}
	return Snapshot{Bearer: t.bearer, IssuedAt: time.Unix(t.issuedAt, 0)}, nil
}

// IssuedAt returns when the cached bearer was signed, or the zero time if
// none has been signed or restored.
func (t *Token) IssuedAt() time.Time {
	if t == nil {
		return time.Time{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.bearer == "" {
		return time.Time{}
	}
	return time.Unix(t.issuedAt, 0)
}

// Restore caches a bearer signed earlier for the same signing identity, so a
// short-lived process can reuse it instead of signing a new one.
// It verifies the signature, signing identity, and issue time before changing
// the cache. Snapshots must have whole-second issue times matching the JWT iat,
// must not be from the future, and must be younger than TokenTimeout.
// A valid snapshot never replaces an equal or newer cached bearer. Restoring
// the current bearer does not remove its locally signed refresh guard.
// Snapshot contents and unwrapped diagnostic errors are sensitive.
func (t *Token) Restore(snapshot Snapshot) error {
	if t == nil || t.authKey == nil {
		return ErrAuthKeyNil
	}
	issuedAt, err := t.verifySnapshot(snapshot)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if issuedAt.After(now) || !now.Before(issuedAt.Add(TokenTimeout)) {
		return invalidSnapshot(nil)
	}
	if t.bearer != "" && t.issuedAt >= issuedAt.Unix() {
		return nil
	}
	t.bearer = snapshot.Bearer
	t.issuedAt = issuedAt.Unix()
	t.restored = true
	return nil
}

func (t *Token) verifySnapshot(snapshot Snapshot) (time.Time, error) {
	parts := strings.Split(snapshot.Bearer, ".")
	if len(parts) != 3 {
		return time.Time{}, invalidSnapshot(nil)
	}
	encoding := base64.RawURLEncoding.Strict()
	for _, part := range parts {
		for _, c := range part {
			if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
				continue
			}
			return time.Time{}, invalidSnapshot(nil)
		}
	}
	headerBytes, err := encoding.DecodeString(parts[0])
	if err != nil {
		return time.Time{}, invalidSnapshot(err)
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ,omitzero"`
	}
	if err := json.Unmarshal(headerBytes, &header, json.RejectUnknownMembers(true)); err != nil {
		return time.Time{}, invalidSnapshot(err)
	}
	if header.Algorithm != "ES256" || header.KeyID != t.identity.KeyID {
		return time.Time{}, invalidSnapshot(nil)
	}
	claimsBytes, err := encoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, invalidSnapshot(err)
	}
	var claims struct {
		Issuer   string `json:"iss"`
		IssuedAt *int64 `json:"iat"`
	}
	if err := json.Unmarshal(claimsBytes, &claims, json.RejectUnknownMembers(true)); err != nil {
		return time.Time{}, invalidSnapshot(err)
	}
	if claims.Issuer != t.identity.TeamID || claims.IssuedAt == nil {
		return time.Time{}, invalidSnapshot(nil)
	}
	issuedAt := time.Unix(*claims.IssuedAt, 0)
	if !snapshot.IssuedAt.Equal(issuedAt) {
		return time.Time{}, invalidSnapshot(nil)
	}
	signature, err := encoding.DecodeString(parts[2])
	if err != nil {
		return time.Time{}, invalidSnapshot(err)
	}
	if len(signature) != 64 {
		return time.Time{}, invalidSnapshot(nil)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(&t.authKey.PublicKey, digest[:], r, s) {
		return time.Time{}, invalidSnapshot(nil)
	}
	return issuedAt, nil
}

// Invalidate drops bearer from the cache after APNs rejects it, so the next
// Bearer call signs a new token. It does nothing if bearer is no longer
// cached. It keeps a token this process signed less than 20 minutes ago:
// signing again with the same key wouldn't help, and APNs rejects tokens
// updated more often than every 20 minutes.
func (t *Token) Invalidate(bearer string) {
	if t == nil {
		return
	}
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
	if t.authKey == nil {
		return ErrAuthKeyNil
	}
	if t.authKey.Curve != elliptic.P256() {
		return ErrAuthKeyCurve
	}
	issuedAt := time.Now().Unix()
	header, err := json.Marshal(struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}{"ES256", t.identity.KeyID})
	if err != nil {
		return redact.Error("token: cannot encode signing identity", err)
	}
	claims, err := json.Marshal(struct {
		Issuer   string `json:"iss"`
		IssuedAt int64  `json:"iat"`
	}{t.identity.TeamID, issuedAt})
	if err != nil {
		return redact.Error("token: cannot encode signing identity", err)
	}
	encoding := base64.RawURLEncoding
	signingString := encoding.EncodeToString(header) + "." + encoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingString))
	r, s, err := ecdsa.Sign(rand.Reader, t.authKey, digest[:])
	if err != nil {
		return redact.Error("token: cannot sign provider token", err)
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
