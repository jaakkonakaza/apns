package certificate_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/sideshow/apns2/certificate"
	"software.sslmate.com/src/go-pkcs12"
)

func testCertificateChain(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "APNs test issuer"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(4102444800, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "APNs test client"},
		NotBefore:    root.NotBefore,
		NotAfter:     root.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, leaf, root
}

func TestPKCS12ModernFormatsAndChain(t *testing.T) {
	key, leaf, issuer := testCertificateChain(t)
	for name, encoder := range map[string]*pkcs12.Encoder{
		"SHA256 MAC and PBES2": pkcs12.Modern2023,
		"PBMAC1 and PBES2":     pkcs12.Modern2026,
	} {
		t.Run(name, func(t *testing.T) {
			data, err := encoder.Encode(key, leaf, []*x509.Certificate{issuer}, "test-password")
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := certificate.FromP12Bytes(data, "test-password")
			if err != nil {
				t.Fatal(err)
			}
			if len(loaded.Certificate) != 2 || !bytes.Equal(loaded.Certificate[0], leaf.Raw) || !bytes.Equal(loaded.Certificate[1], issuer.Raw) {
				t.Fatalf("certificate chain = %d entries, want leaf followed by issuer", len(loaded.Certificate))
			}
			if loaded.Leaf == nil || !loaded.Leaf.Equal(leaf) {
				t.Fatal("missing or incorrect parsed leaf certificate")
			}
			loadedKey, ok := loaded.PrivateKey.(*ecdsa.PrivateKey)
			if !ok || !loadedKey.Equal(key) {
				t.Fatal("decoded private key does not match the encoded key")
			}
			if invalid, err := certificate.FromP12Bytes(data, "incorrect-password"); err == nil || len(invalid.Certificate) != 0 || invalid.PrivateKey != nil {
				t.Fatal("wrong password returned a certificate or no error")
			}
		})
	}
}

func TestPKCS12RejectsMismatchedPrivateKey(t *testing.T) {
	_, leaf, _ := testCertificateChain(t)
	unrelatedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := pkcs12.Modern2023.Encode(unrelatedKey, leaf, nil, "test-password")
	if err != nil {
		t.Fatal(err)
	}
	if loaded, err := certificate.FromP12Bytes(data, "test-password"); err == nil || len(loaded.Certificate) != 0 || loaded.PrivateKey != nil {
		t.Fatal("accepted a certificate with an unrelated private key")
	}
}

func TestPEMSEC1KeyAndChain(t *testing.T) {
	key, leaf, issuer := testCertificateChain(t)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var combined []byte
	for _, cert := range []*x509.Certificate{leaf, issuer} {
		combined = append(combined, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	combined = append(combined, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	loaded, err := certificate.FromPemBytes(combined)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Certificate) != 2 || !bytes.Equal(loaded.Certificate[0], leaf.Raw) || !bytes.Equal(loaded.Certificate[1], issuer.Raw) {
		t.Fatal("SEC1 PEM loading did not preserve the certificate chain")
	}
	loadedKey, ok := loaded.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || !loadedKey.Equal(key) {
		t.Fatal("decoded private key does not match the encoded key")
	}
	if loaded.Leaf == nil || !loaded.Leaf.Equal(leaf) {
		t.Fatal("missing or incorrect parsed leaf certificate")
	}
}

func TestPEMRejectsMismatchedPrivateKey(t *testing.T) {
	_, leaf, _ := testCertificateChain(t)
	unrelatedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(unrelatedKey)
	if err != nil {
		t.Fatal(err)
	}
	combined := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	combined = append(combined, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	loaded, err := certificate.FromPemBytes(combined)
	if err == nil || len(loaded.Certificate) != 0 || loaded.PrivateKey != nil {
		t.Fatal("accepted a certificate with an unrelated private key")
	}
}

func TestPEMRejectsMalformedCertificate(t *testing.T) {
	key, _, _ := testCertificateChain(t)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	combined := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")})
	combined = append(combined, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	loaded, err := certificate.FromPemBytes(combined)
	if !errors.Is(err, certificate.ErrFailedToParseCertificate) {
		t.Fatalf("error = %v, want ErrFailedToParseCertificate", err)
	}
	if len(loaded.Certificate) != 0 || loaded.PrivateKey != nil {
		t.Fatal("malformed certificate returned credentials")
	}
}

func TestPEMUsesFirstPrivateKey(t *testing.T) {
	key, leaf, _ := testCertificateChain(t)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	combined := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	combined = append(combined, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	combined = append(combined, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("trailing garbage")})...)
	loaded, err := certificate.FromPemBytes(combined)
	if err != nil {
		t.Fatal(err)
	}
	if loadedKey, ok := loaded.PrivateKey.(*ecdsa.PrivateKey); !ok || !loadedKey.Equal(key) {
		t.Fatal("loaded key is not the first private key")
	}
}
