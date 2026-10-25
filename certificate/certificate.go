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

// FromPemFile loads a PEM certificate from a local file and returns a
// tls.Certificate. This function is similar to the crypto/tls LoadX509KeyPair
// function, however it supports PEM files with the cert and key combined
// in the same file. It does not support password-protected key files due
// to security concerns with the deprecated PEM encryption method.
//
// The password argument is kept for backwards compatibility but is no longer used.
func FromPemFile(filename string, password string) (tls.Certificate, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return tls.Certificate{}, err
	}
	return FromPemBytes(bytes, password)
}

// FromPemBytes loads a PEM certificate from an in memory byte array and
// returns a tls.Certificate. This function is similar to the crypto/tls
// X509KeyPair function, however it supports PEM files with the cert and
// key combined, as well as password protected keys which are both common with
// APNs certificates.
//
// Use "" as the password argument if the PEM certificate is not password
// protected.
func FromPemBytes(bytes []byte, password string) (tls.Certificate, error) {
	var cert tls.Certificate
	var block *pem.Block
	for {
		block, bytes = pem.Decode(bytes)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		}
		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			key, err := unencryptPrivateKey(block, password)
			if err != nil {
				return tls.Certificate{}, err
			}
			cert.PrivateKey = key
		}
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, ErrNoCertificate
	}
	if cert.PrivateKey == nil {
		return tls.Certificate{}, ErrNoPrivateKey
	}
	if c, e := x509.ParseCertificate(cert.Certificate[0]); e == nil {
		cert.Leaf = c
	}
	return cert, nil
}

func unencryptPrivateKey(block *pem.Block, password string) (crypto.PrivateKey, error) {
	return parsePrivateKey(block.Bytes)
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
	return nil, ErrFailedToParsePrivateKey
}
