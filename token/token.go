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
	// TokenTimeout is the period for which a token is valid.
	// If the timestamp for token issue is not within the last hour, APNs
	// rejects subsequent push messages. This is set to under an hour so that
	// we generate a new token before the existing one expires.
	TokenTimeout = 50 * time.Minute
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
// during use. Its methods are safe to call concurrently.
type Token struct {
	mu       sync.Mutex
	AuthKey  *ecdsa.PrivateKey
	KeyID    string
	TeamID   string
	issuedAt int64
	bearer   string
}

// AuthKeyFromFile loads a .p8 certificate from a local file and returns a
// *ecdsa.PrivateKey.
func AuthKeyFromFile(filename string) (*ecdsa.PrivateKey, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return AuthKeyFromBytes(bytes)
}

// AuthKeyFromBytes loads a .p8 certificate from an in memory byte array and
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

// Expired checks whether the token has expired.
func (t *Token) Expired() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.expiredLocked()
}

func (t *Token) expiredLocked() bool {
	return !time.Now().Before(time.Unix(t.issuedAt, 0).Add(TokenTimeout))
}

// Generate creates a new token.
func (t *Token) Generate() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.generateLocked()
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
	return nil
}
