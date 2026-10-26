// Package credential holds the certificate validation rules shared by client
// construction and client caching, so both accept the same certificates.
package credential

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/jaakkonakaza/apns/internal/nilcheck"
	"github.com/jaakkonakaza/apns/internal/redact"
)

// Errors returned for certificates that cannot authenticate a client.
var (
	ErrKeyRequired    = errors.New("certificate and signing key required")
	ErrUnsupportedKey = errors.New("unsupported signing key")
)

// PublicKey validates that cert carries a chain and a non-nil crypto.Signer and
// returns the signer's PKIX-encoded public key. Public key failures keep the
// cause for inspection but omit it from the message.
func PublicKey(cert tls.Certificate) ([]byte, error) {
	if len(cert.Certificate) == 0 || nilcheck.IsNil(cert.PrivateKey) {
		return nil, ErrKeyRequired
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, ErrUnsupportedKey
	}
	encoded, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, redact.Error("invalid signing public key", err)
	}
	return encoded, nil
}
