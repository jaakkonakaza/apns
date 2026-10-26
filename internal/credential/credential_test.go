package credential

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"strings"
	"testing"
)

type invalidPublicKeySigner struct{}

func (invalidPublicKeySigner) Public() crypto.PublicKey {
	return struct{ Secret string }{Secret: "sensitive-diagnostic"}
}

func (invalidPublicKeySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("invalid signer was used")
}

func TestPublicKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	want, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	got, err := PublicKey(tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: key})
	if err != nil || string(got) != string(want) {
		t.Fatalf("PublicKey = %x, %v", got, err)
	}
}

func TestPublicKeyRejectsInvalidCertificates(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cert tls.Certificate
		want error
	}{
		{tls.Certificate{PrivateKey: key}, ErrKeyRequired},
		{tls.Certificate{Certificate: [][]byte{{1}}}, ErrKeyRequired},
		{tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: (*ecdsa.PrivateKey)(nil)}, ErrKeyRequired},
		{tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: "key"}, ErrUnsupportedKey},
	} {
		if _, err := PublicKey(tc.cert); !errors.Is(err, tc.want) {
			t.Fatalf("PublicKey error = %v, want %v", err, tc.want)
		}
	}
}

func TestPublicKeyErrorRedactsCause(t *testing.T) {
	_, err := PublicKey(tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: invalidPublicKeySigner{}})
	if err == nil || errors.Unwrap(err) == nil {
		t.Fatal("public-key failure lost diagnostic cause")
	}
	if strings.Contains(err.Error(), "sensitive") {
		t.Fatal("public-key summary exposed diagnostic input")
	}
}
