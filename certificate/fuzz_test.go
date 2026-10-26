package certificate_test

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"os"
	"testing"

	"github.com/jaakkonakaza/apns2/certificate"
)

func FuzzFromPEMBytes(f *testing.F) {
	f.Add([]byte{})
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid DER")}))
	for _, name := range []string{"certificate-valid.pem", "certificate-valid-pkcs8.pem", "certificate-no-key.pem", "certificate-no-certificate.pem"} {
		data, err := os.ReadFile("testdata/" + name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
		f.Add(append(bytes.Clone(data), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("trailing invalid key")})...))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		loaded, err := certificate.FromPEMBytes(data)
		if err != nil {
			if len(loaded.Certificate) != 0 || loaded.PrivateKey != nil || loaded.Leaf != nil {
				t.Fatal("failed load returned credentials")
			}
			return
		}
		if loaded.Leaf == nil || len(loaded.Certificate) == 0 || !bytes.Equal(loaded.Certificate[0], loaded.Leaf.Raw) {
			t.Fatal("loaded chain does not start with its parsed leaf")
		}
		pair, err := tls.X509KeyPair(data, data)
		if err != nil {
			t.Fatalf("loaded credentials cannot be used as a TLS key pair: %v", err)
		}
		if len(pair.Certificate) != len(loaded.Certificate) {
			t.Fatal("loader changed certificate chain length")
		}
		for i, raw := range pair.Certificate {
			if !bytes.Equal(raw, loaded.Certificate[i]) {
				t.Fatal("loader changed certificate chain order or bytes")
			}
		}
	})
}
