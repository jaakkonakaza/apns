package token_test

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

	"github.com/sideshow/apns2/token"
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
			loaded, err := token.AuthKeyFromBytes(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
			if loaded != nil || !errors.Is(err, token.ErrAuthKeyCurve) {
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
		{"nil key", nil, token.ErrAuthKeyNil},
		{"wrong curve", wrongCurve, token.ErrAuthKeyCurve},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &token.Token{AuthKey: tc.key, IssuedAt: 1, Bearer: "expired"}
			bearer, err := provider.GenerateIfExpiredWithError()
			if bearer != "" || !errors.Is(err, tc.want) {
				t.Fatalf("refresh = %q, %v; want empty bearer, %v", bearer, err, tc.want)
			}
			if provider.IssuedAt != 1 || provider.Bearer != "expired" {
				t.Fatal("failed signing changed cached state")
			}
			if bearer := provider.GenerateIfExpired(); bearer != "" {
				t.Fatalf("legacy refresh returned expired bearer %q", bearer)
			}
		})
	}
}

func TestRefreshGeneratesMissingBearer(t *testing.T) {
	key, err := token.AuthKeyFromFile("testdata/authkey-valid.p8")
	if err != nil {
		t.Fatal(err)
	}
	provider := &token.Token{AuthKey: key, IssuedAt: time.Now().Unix()}
	bearer, err := provider.GenerateIfExpiredWithError()
	if err != nil || bearer == "" {
		t.Fatalf("refresh = %q, %v", bearer, err)
	}
	cached, err := provider.GenerateIfExpiredWithError()
	if err != nil || cached != bearer {
		t.Fatalf("cached refresh = %q, %v; want %q", cached, err, bearer)
	}
}

func TestConcurrentTokenMethods(t *testing.T) {
	key, err := token.AuthKeyFromFile("testdata/authkey-valid.p8")
	if err != nil {
		t.Fatal(err)
	}
	provider := &token.Token{AuthKey: key, KeyID: "key", TeamID: "team"}
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			for range 20 {
				if ok, err := provider.Generate(); !ok || err != nil {
					t.Errorf("Generate = %t, %v", ok, err)
				}
				if bearer, err := provider.GenerateIfExpiredWithError(); bearer == "" || err != nil {
					t.Errorf("refresh = %q, %v", bearer, err)
				}
				_ = provider.Expired()
			}
		})
	}
	wg.Wait()
}
