package certificate_test

import (
	"crypto/tls"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jaakkonakaza/apns/certificate"
	"software.sslmate.com/src/go-pkcs12"
)

func assertSafeError(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a credential-loading error")
	}
	for _, formatted := range []string{err.Error(), fmt.Sprintf("%s", err), fmt.Sprintf("%v", err)} {
		for _, secret := range secrets {
			if strings.Contains(formatted, secret) {
				t.Fatal("credential input appeared in normal error formatting")
			}
		}
	}
}

func TestFileErrorsRedactPathsAndPreservePathError(t *testing.T) {
	const pathSecret = "private-certificate-path"
	path := filepath.Join(t.TempDir(), pathSecret)
	for name, load := range map[string]func(string) (tls.Certificate, error){
		"PEM": certificate.FromPEMFile,
		"PKCS12": func(path string) (tls.Certificate, error) {
			return certificate.FromP12File(path, "private-password")
		},
	} {
		t.Run(name, func(t *testing.T) {
			loaded, err := load(path)
			assertSafeError(t, err, path, pathSecret, "private-password")
			if pathError, ok := errors.AsType[*os.PathError](err); !errors.Is(err, os.ErrNotExist) || !ok || pathError.Path != path {
				t.Fatal("safe file error lost the original PathError")
			}
			if len(loaded.Certificate) != 0 || loaded.PrivateKey != nil {
				t.Fatal("failed file load returned credentials")
			}
		})
	}
}

func TestPKCS12ErrorsRedactPasswordAndPreserveCause(t *testing.T) {
	const password = "private-password-sentinel"
	data, err := os.ReadFile("testdata/certificate-valid-encrypted.p12")
	if err != nil {
		t.Fatal(err)
	}
	_, err = certificate.FromP12Bytes(data, password)
	assertSafeError(t, err, password)
	if !errors.Is(err, pkcs12.ErrIncorrectPassword) || errors.Unwrap(err) == nil {
		t.Fatal("safe PKCS12 error lost the incorrect-password cause")
	}
	const rawSecret = "private-pkcs12-data"
	_, err = certificate.FromP12Bytes([]byte(rawSecret), password)
	assertSafeError(t, err, rawSecret, password)
	if errors.Unwrap(err) == nil {
		t.Fatal("safe PKCS12 parse error lost its decoder cause")
	}
}

func TestPEMParseErrorsRedactInputsAndPreserveCause(t *testing.T) {
	const rawSecret = "private-key-DER-sentinel"
	_, leaf, _ := testCertificateChain(t)
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte(rawSecret)})...)
	_, err := certificate.FromPEMBytes(data)
	assertSafeError(t, err, rawSecret)
	if _, ok := errors.AsType[asn1.StructuralError](err); !errors.Is(err, certificate.ErrFailedToParsePrivateKey) || !ok {
		t.Fatal("safe PEM key error lost its sentinel or ASN.1 cause")
	}
	data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte(rawSecret)})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte(rawSecret)})...)
	_, err = certificate.FromPEMBytes(data)
	assertSafeError(t, err, rawSecret)
	if !errors.Is(err, certificate.ErrFailedToParseCertificate) || errors.Unwrap(err) == nil {
		t.Fatal("safe PEM certificate error lost its sentinel or X.509 cause")
	}
}
