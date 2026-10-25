// Package certificate contains functions to load an Apple APNs PKCS#12
// or PEM certificate from either an in memory byte array or a local file.
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

	"software.sslmate.com/src/go-pkcs12"
)

// Possible errors when parsing a certificate.
var (
	ErrFailedToParsePrivateKey  = errors.New("failed to parse private key")
	ErrFailedToParseCertificate = errors.New("failed to parse certificate PEM data")
	ErrNoPrivateKey             = errors.New("no private key")
	ErrNoCertificate            = errors.New("no certificate")
)

// FromP12File loads a PKCS#12 certificate from a local file and returns a
// tls.Certificate.
//
// Use "" as the password argument if the PKCS#12 certificate is not password
// protected.
func FromP12File(filename string, password string) (tls.Certificate, error) {
	p12bytes, err := os.ReadFile(filename)
	if err != nil {
		return tls.Certificate{}, err
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
		return tls.Certificate{}, err
	}
	// DecodeChain parses the key and certificates, but does not check that
	// the leaf belongs to the private key. Reject an invalid pair at load time.
	signer, ok := key.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, ErrFailedToParsePrivateKey
	}
	publicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return tls.Certificate{}, err
	}
	certificateKey, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	if !bytes.Equal(publicKey, certificateKey) {
		return tls.Certificate{}, errors.New("certificate: private key does not match certificate")
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

// FromPemFile loads a certificate chain and matching private key from a combined
// PEM file. Password-protected PEM keys are unsupported, the password argument
// is ignored.
func FromPemFile(filename string, password string) (tls.Certificate, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return tls.Certificate{}, err
	}
	return FromPemBytes(bytes, password)
}

// FromPemBytes loads a certificate chain and matching private key from combined
// PEM data. It supports PKCS#1, PKCS#8, and SEC1 private keys.
// Password-protected PEM keys are unsupported, the password argument is ignored.
func FromPemBytes(bytes []byte, password string) (tls.Certificate, error) {
	// Validate the same blocks tls.X509KeyPair uses: the first certificate is
	// the leaf and the first private key must match it.
	var leaf, key *pem.Block
	for rest := bytes; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if leaf == nil && block.Type == "CERTIFICATE" {
			leaf = block
		}
		if key == nil && strings.HasSuffix(block.Type, "PRIVATE KEY") {
			key = block
		}
	}
	if leaf == nil {
		return tls.Certificate{}, ErrNoCertificate
	}
	if key == nil {
		return tls.Certificate{}, ErrNoPrivateKey
	}
	if _, err := x509.ParseCertificate(leaf.Bytes); err != nil {
		return tls.Certificate{}, ErrFailedToParseCertificate
	}
	if _, err := parsePrivateKey(key.Bytes); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(bytes, bytes)
}

func parsePrivateKey(bytes []byte) (crypto.PrivateKey, error) {
	var key crypto.PrivateKey
	key, err := x509.ParsePKCS1PrivateKey(bytes)
	if err == nil {
		return key, nil
	}
	key, err = x509.ParsePKCS8PrivateKey(bytes)
	if err == nil {
		return key, nil
	}
	key, err = x509.ParseECPrivateKey(bytes)
	if err == nil {
		return key, nil
	}
	return nil, ErrFailedToParsePrivateKey
}
