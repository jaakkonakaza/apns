// Package certificate contains functions to load an Apple APNs PKCS#12
// or PEM certificate from either an in memory byte array or a local file.
//
// Apple issues provider certificates as .cer files; export the certificate
// and its key from Keychain Access as a .p12 file to load them. Provider
// certificates are valid for a year. The loaders reject certificates outside
// their validity period with ErrCertificateExpired or ErrCertificateNotYetValid.
// A long-running process needs a renewed certificate before Leaf.NotAfter.
// Certificate connections support only a subset of push types. Token
// authentication supports all of them.
package certificate

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/jaakkonakaza/apns/internal/redact"
	"software.sslmate.com/src/go-pkcs12"
)

// Possible errors when parsing a certificate.
var (
	ErrFailedToParsePrivateKey  = errors.New("certificate: failed to parse private key")
	ErrFailedToParseCertificate = errors.New("certificate: failed to parse certificate PEM data")
	ErrNoPrivateKey             = errors.New("certificate: no private key")
	ErrNoCertificate            = errors.New("certificate: no certificate")
	ErrKeyMismatch              = errors.New("certificate: private key does not match certificate")
	ErrCertificateExpired       = errors.New("certificate: certificate has expired")
	ErrCertificateNotYetValid   = errors.New("certificate: certificate is not valid yet")
)

// FromP12File loads a PKCS#12 certificate from a local file and returns a
// tls.Certificate.
//
// Use "" as the password argument if the PKCS#12 certificate is not password
// protected.
func FromP12File(filename string, password string) (tls.Certificate, error) {
	p12bytes, err := os.ReadFile(filename)
	if err != nil {
		return tls.Certificate{}, redact.Error("certificate: cannot read certificate file", err)
	}
	return FromP12Bytes(p12bytes, password)
}

// FromP12Bytes loads a PKCS#12 certificate from an in memory byte array and
// returns a tls.Certificate.
//
// Use "" as the password argument if the PKCS#12 certificate is not password
// protected.
func FromP12Bytes(data []byte, password string) (tls.Certificate, error) {
	key, cert, chain, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return tls.Certificate{}, redact.Error("certificate: cannot decode PKCS#12 certificate", err)
	}
	if err := matchPrivateKey(cert, key); err != nil {
		return tls.Certificate{}, err
	}
	if err := checkValidity(cert); err != nil {
		return tls.Certificate{}, err
	}
	certificates := make([][]byte, 1, len(chain)+1)
	certificates[0] = cert.Raw
	for _, intermediate := range chain {
		certificates = append(certificates, intermediate.Raw)
	}
	return tls.Certificate{
		Certificate: certificates,
		PrivateKey:  key,
		Leaf:        cert,
	}, nil
}

// FromPEMFile loads a certificate chain and matching private key from a combined
// PEM file. Password-protected PEM keys are unsupported.
func FromPEMFile(filename string) (tls.Certificate, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return tls.Certificate{}, redact.Error("certificate: cannot read certificate file", err)
	}
	return FromPEMBytes(bytes)
}

// FromPEMBytes loads a certificate chain and matching private key from combined
// PEM data. It supports PKCS#1, PKCS#8, and SEC1 private keys.
// The first certificate is the leaf, followed by any intermediate certificates.
// The first private key must match the leaf. Password-protected PEM keys are unsupported.
func FromPEMBytes(data []byte) (tls.Certificate, error) {
	var certificates [][]byte
	var keyBlock *pem.Block
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certificates = append(certificates, block.Bytes)
		}
		if keyBlock == nil && strings.HasSuffix(block.Type, "PRIVATE KEY") {
			keyBlock = block
		}
	}
	if len(certificates) == 0 {
		return tls.Certificate{}, ErrNoCertificate
	}
	if keyBlock == nil {
		return tls.Certificate{}, ErrNoPrivateKey
	}
	cert, err := x509.ParseCertificate(certificates[0])
	if err != nil {
		return tls.Certificate{}, redact.Error(ErrFailedToParseCertificate.Error(), errors.Join(ErrFailedToParseCertificate, err))
	}
	if err := checkValidity(cert); err != nil {
		return tls.Certificate{}, err
	}
	key, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := matchPrivateKey(cert, key); err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: certificates, PrivateKey: key, Leaf: cert}, nil
}

func matchPrivateKey(cert *x509.Certificate, key crypto.PrivateKey) error {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return ErrFailedToParsePrivateKey
	}
	publicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return redact.Error("certificate: cannot encode signing public key", err)
	}
	certificateKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return redact.Error("certificate: cannot encode certificate public key", err)
	}
	if !bytes.Equal(publicKey, certificateKey) {
		return ErrKeyMismatch
	}
	return nil
}

// checkValidity rejects a certificate outside its validity period. Apple's
// provider certificates are valid for a year.
func checkValidity(cert *x509.Certificate) error {
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return ErrCertificateNotYetValid
	}
	if now.After(cert.NotAfter) {
		return ErrCertificateExpired
	}
	return nil
}

func parsePrivateKey(bytes []byte) (crypto.PrivateKey, error) {
	key, pkcs1Err := x509.ParsePKCS1PrivateKey(bytes)
	if pkcs1Err == nil {
		return key, nil
	}
	pkcs8Key, pkcs8Err := x509.ParsePKCS8PrivateKey(bytes)
	if pkcs8Err == nil {
		return pkcs8Key, nil
	}
	ecKey, ecErr := x509.ParseECPrivateKey(bytes)
	if ecErr == nil {
		return ecKey, nil
	}
	return nil, redact.Error(ErrFailedToParsePrivateKey.Error(), errors.Join(ErrFailedToParsePrivateKey, pkcs1Err, pkcs8Err, ecErr))
}
