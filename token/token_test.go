package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// AuthToken

func TestValidTokenFromP8File(t *testing.T) {
	_, err := AuthKeyFromFile("testdata/authkey-valid.p8")
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestValidTokenFromP8Bytes(t *testing.T) {
	bytes, _ := os.ReadFile("testdata/authkey-valid.p8")
	_, err := AuthKeyFromBytes(bytes)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestNoSuchFileP8File(t *testing.T) {
	token, err := AuthKeyFromFile("")
	if got, want := err.Error(), errors.New("open : no such file or directory").Error(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got := token; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestInvalidP8File(t *testing.T) {
	_, err := AuthKeyFromFile("testdata/authkey-invalid.p8")
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
}

func TestInvalidPKCS8P8File(t *testing.T) {
	_, err := AuthKeyFromFile("testdata/authkey-invalid-pkcs8.p8")
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
}

func TestInvalidECDSAP8File(t *testing.T) {
	_, err := AuthKeyFromFile("testdata/authkey-invalid-ecdsa.p8")
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
}

// Expiry & Generation

func TestExpired(t *testing.T) {
	token := &Token{}
	if !token.expiredLocked() {
		t.Error("Expired() = false, want true")
	}
}

func TestNotExpired(t *testing.T) {
	token := &Token{
		issuedAt: time.Now().Unix(),
	}
	if token.expiredLocked() {
		t.Error("Expired() = true, want false")
	}
}

func TestExpiresBeforeAnHour(t *testing.T) {
	token := &Token{
		issuedAt: time.Now().Add(-50 * time.Minute).Unix(),
	}
	if !token.expiredLocked() {
		t.Error("Expired() = false, want true")
	}
}

func TestBearerRefresh(t *testing.T) {
	authKey, _ := AuthKeyFromFile("testdata/authkey-valid.p8")
	token := &Token{
		authKey: authKey,
	}
	if _, err := token.Bearer(); err != nil {
		t.Fatal(err)
	}
	if got, want := token.issuedAt, time.Now().Unix(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestBearerWithNoAuthKey(t *testing.T) {
	token := &Token{}
	_, err := token.Bearer()
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
}

func TestBearerWithInvalidAuthKey(t *testing.T) {
	pubkeyCurve := elliptic.P521()
	privatekey, _ := ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
	token := &Token{
		authKey: privatekey,
	}
	_, err := token.Bearer()
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
}

func TestBearerSignsToken(t *testing.T) {
	key, err := AuthKeyFromFile("testdata/authkey-valid.p8")
	if err != nil {
		t.Fatal(err)
	}
	provider := &Token{
		authKey:  key,
		identity: Identity{KeyID: "key\"\\\n日本語", TeamID: "team\"\\\n日本語"},
	}
	before := time.Now().Unix()
	if _, err := provider.Bearer(); err != nil {
		t.Fatalf("Bearer() = %v", err)
	}
	if provider.issuedAt < before || provider.issuedAt > time.Now().Unix() {
		t.Fatalf("unexpected issue time: %d", provider.issuedAt)
	}
	parts := strings.Split(provider.bearer, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	decode := func(segment string) []byte {
		t.Helper()
		if strings.Contains(segment, "=") {
			t.Fatal("JWT segment contains base64 padding")
		}
		decoded, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	var header map[string]string
	if err := json.Unmarshal(decode(parts[0]), &header); err != nil {
		t.Fatal(err)
	}
	if len(header) != 2 || header["alg"] != "ES256" || header["kid"] != provider.identity.KeyID {
		t.Errorf("unexpected JWT header: %#v", header)
	}
	var claims struct {
		Issuer   string `json:"iss"`
		IssuedAt int64  `json:"iat"`
	}
	if err := json.Unmarshal(decode(parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != provider.identity.TeamID || claims.IssuedAt != provider.issuedAt {
		t.Errorf("unexpected JWT claims: %#v", claims)
	}
	signature := decode(parts[2])
	if len(signature) != 64 {
		t.Fatalf("signature length = %d, want 64", len(signature))
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Fatal("JWT signature verification failed")
	}
	digest = sha256.Sum256([]byte(parts[0] + "." + parts[1] + "tampered"))
	if ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Fatal("JWT signature accepted tampered claims")
	}
	if bearer, err := provider.Bearer(); err != nil || bearer != provider.bearer {
		t.Errorf("cached token = %q; want %q", bearer, provider.bearer)
	}
}

func TestRestoreReusesFreshBearer(t *testing.T) {
	key, err := AuthKeyFromFile("testdata/authkey-valid.p8")
	if err != nil {
		t.Fatal(err)
	}
	provider := &Token{authKey: key, identity: Identity{KeyID: "KEY", TeamID: "TEAM"}}
	if !provider.IssuedAt().IsZero() {
		t.Fatal("new token reports an issue time")
	}
	issuedAt := time.Now().Add(-time.Minute).Truncate(time.Second)
	provider.Restore("cached.bearer.value", issuedAt)
	if bearer, err := provider.Bearer(); err != nil || bearer != "cached.bearer.value" {
		t.Fatalf("Bearer() = %q, %v, want restored bearer", bearer, err)
	}
	if !provider.IssuedAt().Equal(issuedAt) {
		t.Errorf("IssuedAt() = %v, want %v", provider.IssuedAt(), issuedAt)
	}
}

func TestRestoreReplacesExpiredBearer(t *testing.T) {
	key, err := AuthKeyFromFile("testdata/authkey-valid.p8")
	if err != nil {
		t.Fatal(err)
	}
	provider := &Token{authKey: key, identity: Identity{KeyID: "KEY", TeamID: "TEAM"}}
	provider.Restore("stale.bearer.value", time.Now().Add(-TokenTimeout))
	bearer, err := provider.Bearer()
	if err != nil || bearer == "stale.bearer.value" {
		t.Fatalf("Bearer() = %q, %v, want a newly signed bearer", bearer, err)
	}
	if time.Since(provider.IssuedAt()) > time.Minute {
		t.Errorf("IssuedAt() = %v, want now", provider.IssuedAt())
	}
}

func TestRestoreIgnoresUnusableIssueTimes(t *testing.T) {
	for name, issuedAt := range map[string]time.Time{
		"future":  time.Now().Add(time.Hour),
		"expired": time.Now().Add(-TokenTimeout),
	} {
		provider := &Token{}
		provider.Restore("cached.bearer.value", issuedAt)
		if provider.bearer != "" {
			t.Errorf("%s: Restore cached a bearer", name)
		}
	}
}

func TestInvalidate(t *testing.T) {
	key, err := AuthKeyFromFile("testdata/authkey-valid.p8")
	if err != nil {
		t.Fatal(err)
	}
	fresh := &Token{authKey: key}
	bearer, err := fresh.Bearer()
	if err != nil {
		t.Fatal(err)
	}
	fresh.Invalidate(bearer)
	if fresh.bearer != bearer {
		t.Error("Invalidate dropped a token signed less than 20 minutes ago")
	}

	old := &Token{authKey: key, bearer: "old", issuedAt: time.Now().Add(-25 * time.Minute).Unix()}
	old.Invalidate("other")
	if old.bearer != "old" {
		t.Error("Invalidate dropped a bearer that wasn't the rejected one")
	}
	old.Invalidate("old")
	if old.bearer != "" {
		t.Error("Invalidate kept a rejected token older than 20 minutes")
	}

	restored := &Token{authKey: key}
	restored.Restore("restored", time.Now())
	restored.Invalidate("restored")
	if restored.bearer != "" {
		t.Error("Invalidate kept a rejected restored token")
	}
}
