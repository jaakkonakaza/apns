package certificate_test

import (
	"crypto/tls"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/sideshow/apns2/certificate"
)

// PKCS#12

func TestValidCertificateFromP12File(t *testing.T) {
	cer, err := certificate.FromP12File("testdata/certificate-valid.p12", "")
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got, want := cer, (tls.Certificate{}); reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want different from %#v", got, want)
	}
}

func TestValidCertificateFromP12Bytes(t *testing.T) {
	bytes, _ := os.ReadFile("testdata/certificate-valid.p12")
	cer, err := certificate.FromP12Bytes(bytes, "")
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got, want := cer, (tls.Certificate{}); reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want different from %#v", got, want)
	}
}

func TestEncryptedValidCertificateFromP12File(t *testing.T) {
	cer, err := certificate.FromP12File("testdata/certificate-valid-encrypted.p12", "password")
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got, want := cer, (tls.Certificate{}); reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want different from %#v", got, want)
	}
}

func TestNoSuchFileP12File(t *testing.T) {
	cer, err := certificate.FromP12File("", "")
	if got, want := err.Error(), errors.New("open : no such file or directory").Error(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := cer, (tls.Certificate{}); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestBadPasswordP12File(t *testing.T) {
	cer, err := certificate.FromP12File("testdata/certificate-valid-encrypted.p12", "")
	if got, want := cer, (tls.Certificate{}); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := err.Error(), errors.New("pkcs12: decryption password incorrect").Error(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

// PEM

func TestValidCertificateFromPemFile(t *testing.T) {
	cer, err := certificate.FromPemFile("testdata/certificate-valid.pem")
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got, want := cer, (tls.Certificate{}); reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want different from %#v", got, want)
	}
}

func TestValidCertificateFromPemBytes(t *testing.T) {
	bytes, _ := os.ReadFile("testdata/certificate-valid.pem")
	cer, err := certificate.FromPemBytes(bytes)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got, want := cer, (tls.Certificate{}); reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want different from %#v", got, want)
	}
}

func TestValidCertificateFromPemFileWithPKCS8PrivateKey(t *testing.T) {
	cer, err := certificate.FromPemFile("testdata/certificate-valid-pkcs8.pem")
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got, want := cer, (tls.Certificate{}); reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want different from %#v", got, want)
	}
}

func TestValidCertificateFromPemBytesWithPKCS8PrivateKey(t *testing.T) {
	bytes, _ := os.ReadFile("testdata/certificate-valid-pkcs8.pem")
	cer, err := certificate.FromPemBytes(bytes)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got, want := cer, (tls.Certificate{}); reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want different from %#v", got, want)
	}
}

func TestUnsupportedEncryptedCertificateFromPemFile(t *testing.T) {
	cer, err := certificate.FromPemFile("testdata/certificate-legacy-encrypted-unsupported.pem")
	if got, want := cer, (tls.Certificate{}); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := err, certificate.ErrFailedToParsePrivateKey; !errors.Is(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestNoSuchFilePemFile(t *testing.T) {
	cer, err := certificate.FromPemFile("")
	if got, want := cer, (tls.Certificate{}); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := err.Error(), errors.New("open : no such file or directory").Error(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestBadKeyPemFile(t *testing.T) {
	cer, err := certificate.FromPemFile("testdata/certificate-bad-key.pem")
	if got, want := cer, (tls.Certificate{}); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := err, certificate.ErrFailedToParsePrivateKey; !errors.Is(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestNoKeyPemFile(t *testing.T) {
	cer, err := certificate.FromPemFile("testdata/certificate-no-key.pem")
	if got, want := cer, (tls.Certificate{}); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := err, certificate.ErrNoPrivateKey; !errors.Is(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestNoCertificatePemFile(t *testing.T) {
	cer, err := certificate.FromPemFile("testdata/certificate-no-certificate.pem")
	if got, want := cer, (tls.Certificate{}); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := err, certificate.ErrNoCertificate; !errors.Is(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}
