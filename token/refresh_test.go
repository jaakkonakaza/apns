package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestAuthKeyRejectsWrongCurve(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := AuthKeyFromBytes(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
			if loaded != nil || !errors.Is(err, ErrAuthKeyCurve) {
				t.Fatalf("loaded key = %v, error = %v; want ErrAuthKeyCurve", loaded, err)
			}
		})
	}
}

func TestRefreshReturnsSigningError(t *testing.T) {
	wrongCurve, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		key  *ecdsa.PrivateKey
		want error
	}{
		{"nil key", nil, ErrAuthKeyNil},
		{"wrong curve", wrongCurve, ErrAuthKeyCurve},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Token{authKey: tc.key, issuedAt: 1, bearer: "expired"}
			bearer, err := provider.Bearer()
			if bearer != "" || !errors.Is(err, tc.want) {
				t.Fatalf("refresh = %q, %v; want empty bearer, %v", bearer, err, tc.want)
			}
			if provider.issuedAt != 1 || provider.bearer != "expired" {
				t.Fatal("failed signing changed cached state")
			}
		})
	}
}

func TestRefreshGeneratesMissingBearer(t *testing.T) {
	key, err := AuthKeyFromFile("testdata/authkey-valid.p8")
	if err != nil {
		t.Fatal(err)
	}
	provider := &Token{authKey: key, issuedAt: time.Now().Unix()}
	bearer, err := provider.Bearer()
	if err != nil || bearer == "" {
		t.Fatalf("refresh = %q, %v", bearer, err)
	}
	cached, err := provider.Bearer()
	if err != nil || cached != bearer {
		t.Fatalf("cached refresh = %q, %v; want %q", cached, err, bearer)
	}
}

func TestBearerRefreshesExpiredToken(t *testing.T) {
	key, err := AuthKeyFromFile("testdata/authkey-valid.p8")
	if err != nil {
		t.Fatal(err)
	}
	provider := &Token{authKey: key, issuedAt: time.Now().Add(-TokenTimeout).Unix(), bearer: "expired"}
	bearer, err := provider.Bearer()
	if err != nil || bearer == "" || bearer == "expired" {
		t.Fatalf("Bearer() = %q, %v", bearer, err)
	}
	if provider.expiredLocked() {
		t.Fatal("refreshed token is expired")
	}
	cached, err := provider.Bearer()
	if err != nil || cached != bearer {
		t.Fatalf("cached Bearer() = %q, %v, want %q", cached, err, bearer)
	}
}

func TestConcurrentTokenMethods(t *testing.T) {
	key, err := AuthKeyFromFile("testdata/authkey-valid.p8")
	if err != nil {
		t.Fatal(err)
	}
	provider := &Token{authKey: key, identity: Identity{KeyID: "key", TeamID: "team"}}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 20 {
				if bearer, err := provider.Bearer(); bearer == "" || err != nil {
					t.Errorf("refresh = %q, %v", bearer, err)
				}
				if provider.IssuedAt().IsZero() {
					t.Error("IssuedAt() is zero after Bearer")
				}
			}
		})
	}
	wg.Wait()
}
