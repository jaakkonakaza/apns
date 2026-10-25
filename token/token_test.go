package token_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sideshow/apns2/token"
)

// AuthToken

func TestValidTokenFromP8File(t *testing.T) {
	_, err := token.AuthKeyFromFile("testdata/authkey-valid.p8")
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestValidTokenFromP8Bytes(t *testing.T) {
	bytes, _ := os.ReadFile("testdata/authkey-valid.p8")
	_, err := token.AuthKeyFromBytes(bytes)
	if got := err; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestNoSuchFileP8File(t *testing.T) {
	token, err := token.AuthKeyFromFile("")
	if got, want := err.Error(), errors.New("open : no such file or directory").Error(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got := token; got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestInvalidP8File(t *testing.T) {
	_, err := token.AuthKeyFromFile("testdata/authkey-invalid.p8")
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
}

func TestInvalidPKCS8P8File(t *testing.T) {
	_, err := token.AuthKeyFromFile("testdata/authkey-invalid-pkcs8.p8")
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
}

func TestInvalidECDSAP8File(t *testing.T) {
	_, err := token.AuthKeyFromFile("testdata/authkey-invalid-ecdsa.p8")
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
}

// Expiry & Generation

func TestExpired(t *testing.T) {
	token := &token.Token{}
	if !token.Expired() {
		t.Error("token.Expired() = false, want true")
	}
}

func TestNotExpired(t *testing.T) {
	token := &token.Token{
		IssuedAt: time.Now().Unix(),
	}
	if token.Expired() {
		t.Error("token.Expired() = true, want false")
	}
}

func TestExpiresBeforeAnHour(t *testing.T) {
	token := &token.Token{
		IssuedAt: time.Now().Add(-50 * time.Minute).Unix(),
	}
	if !token.Expired() {
		t.Error("token.Expired() = false, want true")
	}
}

func TestGenerateIfExpired(t *testing.T) {
	authKey, _ := token.AuthKeyFromFile("testdata/authkey-valid.p8")
	token := &token.Token{
		AuthKey: authKey,
	}
	token.GenerateIfExpired()
	if got, want := token.IssuedAt, time.Now().Unix(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestGenerateWithNoAuthKey(t *testing.T) {
	token := &token.Token{}
	bool, err := token.Generate()
	if bool {
		t.Error("bool = true, want false")
	}
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
}

func TestGenerateWithInvalidAuthKey(t *testing.T) {
	pubkeyCurve := elliptic.P521()
	privatekey, _ := ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
	token := &token.Token{
		AuthKey: privatekey,
	}
	bool, err := token.Generate()
	if bool {
		t.Error("bool = true, want false")
	}
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
}

func TestGenerateSignedToken(t *testing.T) {
	key, err := token.AuthKeyFromFile("testdata/authkey-valid.p8")
	if err != nil {
		t.Fatal(err)
	}
	provider := &token.Token{
		AuthKey: key,
		KeyID:   "key\"\\\n日本語",
		TeamID:  "team\"\\\n日本語",
	}
	before := time.Now().Unix()
	ok, err := provider.Generate()
	if err != nil || !ok {
		t.Fatalf("Generate() = %v, %v", ok, err)
	}
	if provider.IssuedAt < before || provider.IssuedAt > time.Now().Unix() {
		t.Fatalf("unexpected issue time: %d", provider.IssuedAt)
	}
	parts := strings.Split(provider.Bearer, ".")
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
	if len(header) != 2 || header["alg"] != "ES256" || header["kid"] != provider.KeyID {
		t.Errorf("unexpected JWT header: %#v", header)
	}
	var claims struct {
		Issuer   string `json:"iss"`
		IssuedAt int64  `json:"iat"`
	}
	if err := json.Unmarshal(decode(parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != provider.TeamID || claims.IssuedAt != provider.IssuedAt {
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
	if bearer := provider.GenerateIfExpired(); bearer != provider.Bearer {
		t.Errorf("cached token = %q; want %q", bearer, provider.Bearer)
	}
}
