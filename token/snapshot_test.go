package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewRejectsInvalidCredentials(t *testing.T) {
	key, err := AuthKeyFromFile("testdata/authkey-valid.p8")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		key         *ecdsa.PrivateKey
		keyID, team string
		want        error
	}{
		{"missing key", nil, "key", "team", ErrAuthKeyNil},
		{"missing key ID", key, "", "team", ErrKeyIDMissing},
		{"missing team ID", key, "key", "", ErrTeamIDMissing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := New(tc.key, tc.keyID, tc.team)
			if provider != nil || !errors.Is(err, tc.want) {
				t.Fatalf("New() = %v, %v, want nil, %v", provider, err, tc.want)
			}
		})
	}
	wrongCurve, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if provider, err := New(wrongCurve, "key", "team"); provider != nil || !errors.Is(err, ErrAuthKeyCurve) {
		t.Fatalf("wrong curve = %v, %v", provider, err)
	}
}

func TestNewCopiesSigningIdentity(t *testing.T) {
	key, err := AuthKeyFromFile("testdata/authkey-valid.p8")
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	provider, err := New(key, "key", "team")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := provider.Identity()
	if err != nil {
		t.Fatal(err)
	}
	if identity.TeamID != "team" || identity.KeyID != "key" || string(identity.PublicKey[:]) != string(public) {
		t.Fatalf("Identity() = %+v", identity)
	}
	// Changing the supplied key after construction must not change the token.
	key.Curve = elliptic.P384()
	if _, err := provider.Bearer(); err != nil {
		t.Fatalf("caller key mutation changed signing: %v", err)
	}
	identity.KeyID = "changed"
	identity.PublicKey[0] = 0
	actual, err := provider.Identity()
	if err != nil || actual.KeyID != "key" || string(actual.PublicKey[:]) != string(public) {
		t.Fatalf("caller identity mutation changed token: %+v, %v", actual, err)
	}
}

func TestSnapshotMatchesSignedIssueTime(t *testing.T) {
	key, err := AuthKeyFromFile("testdata/authkey-valid.p8")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := New(key, "key", "team")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := provider.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(snapshot.Bearer, ".")
	if len(parts) != 3 {
		t.Fatal("snapshot is not a signed bearer")
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		IssuedAt int64 `json:"iat"`
	}
	if err := json.Unmarshal(data, &claims); err != nil {
		t.Fatal(err)
	}
	if snapshot.IssuedAt.Unix() != claims.IssuedAt {
		t.Fatalf("snapshot issue time = %v, signed issue time = %d", snapshot.IssuedAt, claims.IssuedAt)
	}
}

func TestSnapshotKeepsRestoredPairsTogether(t *testing.T) {
	key, err := AuthKeyFromFile("testdata/authkey-valid.p8")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := New(key, "key", "team")
	if err != nil {
		t.Fatal(err)
	}
	first := signSnapshot(t, key, `{"alg":"ES256","kid":"key"}`, `{"iss":"team","iat":`+strconv.FormatInt(time.Now().Add(-2*time.Minute).Unix(), 10)+`}`)
	second := signSnapshot(t, key, `{"alg":"ES256","kid":"key"}`, `{"iss":"team","iat":`+strconv.FormatInt(first.IssuedAt.Add(time.Minute).Unix(), 10)+`}`)
	if err := provider.Restore(first); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Go(func() {
		for range 1000 {
			if err := provider.Restore(first); err != nil {
				t.Error(err)
			}
			if err := provider.Restore(second); err != nil {
				t.Error(err)
			}
		}
	})
	for range 4 {
		workers.Go(func() {
			for range 1000 {
				snapshot, err := provider.Snapshot()
				if err != nil {
					t.Error(err)
					return
				}
				matchesFirst := snapshot.Bearer == first.Bearer && snapshot.IssuedAt.Equal(first.IssuedAt)
				matchesSecond := snapshot.Bearer == second.Bearer && snapshot.IssuedAt.Equal(second.IssuedAt)
				if !matchesFirst && !matchesSecond {
					t.Errorf("snapshot mixed independently restored values: %+v", snapshot)
					return
				}
			}
		})
	}
	workers.Wait()
}

func TestUnconfiguredTokensReturnErrors(t *testing.T) {
	for _, provider := range []*Token{nil, {}} {
		if snapshot, err := provider.Snapshot(); snapshot != (Snapshot{}) || !errors.Is(err, ErrAuthKeyNil) {
			t.Fatalf("Snapshot() = %+v, %v", snapshot, err)
		}
		if bearer, err := provider.Bearer(); bearer != "" || !errors.Is(err, ErrAuthKeyNil) {
			t.Fatalf("Bearer() = %q, %v", bearer, err)
		}
		if identity, err := provider.Identity(); identity != (Identity{}) || !errors.Is(err, ErrAuthKeyNil) {
			t.Fatalf("Identity() = %+v, %v", identity, err)
		}
	}
}
