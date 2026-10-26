package token

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// signSnapshot constructs independent signed fixtures, including malformed
// headers and claims that the production encoder never produces.
func signSnapshot(t testing.TB, key *ecdsa.PrivateKey, header, claims string) Snapshot {
	t.Helper()
	encoding := base64.RawURLEncoding
	input := encoding.EncodeToString([]byte(header)) + "." + encoding.EncodeToString([]byte(claims))
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	var body struct {
		IssuedAt int64 `json:"iat"`
	}
	_ = json.Unmarshal([]byte(claims), &body)
	return Snapshot{Bearer: input + "." + encoding.EncodeToString(signature), IssuedAt: time.Unix(body.IssuedAt, 0)}
}

func configuredProvider(t testing.TB) *Token {
	t.Helper()
	key, err := AuthKeyFromFile("testdata/authkey-valid.p8")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := New(key, "KEY", "TEAM")
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func TestRestoreValidSnapshot(t *testing.T) {
	source := configuredProvider(t)
	snapshot, err := source.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	receiver := configuredProvider(t)
	if err := receiver.Restore(snapshot); err != nil {
		t.Fatal(err)
	}
	got, err := receiver.Snapshot()
	if err != nil || got != snapshot {
		t.Fatal("restored snapshot changed its bearer or issue time")
	}
	receiver.Invalidate(snapshot.Bearer)
	if !receiver.IssuedAt().IsZero() {
		t.Fatal("rejected restored bearer was retained")
	}
}

func TestRestoreRejectsInvalidSnapshotsWithoutChangingCache(t *testing.T) {
	provider := configuredProvider(t)
	existing, err := provider.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	iat := strconv.FormatInt(time.Now().Unix(), 10)
	header := `{"alg":"ES256","kid":"KEY"}`
	claims := `{"iss":"TEAM","iat":` + iat + `}`
	valid := signSnapshot(t, provider.authKey, header, claims)
	otherKey, err := ecdsa.GenerateKey(provider.authKey.Curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, snapshot := range map[string]Snapshot{
		"empty":               {},
		"wrong segment count": {Bearer: "secret"},
		"base64 header":       {Bearer: "!.secret.secret"},
		"base64 claims":       {Bearer: strings.Split(valid.Bearer, ".")[0] + ".!.secret"},
		"wrong algorithm":     signSnapshot(t, provider.authKey, `{"alg":"HS256","kid":"KEY"}`, claims),
		"missing algorithm":   signSnapshot(t, provider.authKey, `{"kid":"KEY"}`, claims),
		"wrong key ID":        signSnapshot(t, provider.authKey, `{"alg":"ES256","kid":"other"}`, claims),
		"wrong issuer":        signSnapshot(t, provider.authKey, header, `{"iss":"other","iat":`+iat+`}`),
		"missing issuer":      signSnapshot(t, provider.authKey, header, `{"iat":`+iat+`}`),
		"missing iat":         signSnapshot(t, provider.authKey, header, `{"iss":"TEAM"}`),
		"null iat":            signSnapshot(t, provider.authKey, header, `{"iss":"TEAM","iat":null}`),
		"fractional iat":      signSnapshot(t, provider.authKey, header, `{"iss":"TEAM","iat":1.5}`),
		"string iat":          signSnapshot(t, provider.authKey, header, `{"iss":"TEAM","iat":"`+iat+`"}`),
		"overflow iat":        signSnapshot(t, provider.authKey, header, `{"iss":"TEAM","iat":9223372036854775808}`),
		"maximum iat":         signSnapshot(t, provider.authKey, header, `{"iss":"TEAM","iat":9223372036854775807}`),
		"minimum iat":         signSnapshot(t, provider.authKey, header, `{"iss":"TEAM","iat":-9223372036854775808}`),
		"duplicate algorithm": signSnapshot(t, provider.authKey, `{"alg":"ES256","alg":"ES256","kid":"KEY"}`, claims),
		"duplicate iat":       signSnapshot(t, provider.authKey, header, `{"iss":"TEAM","iat":`+iat+`,"iat":`+iat+`}`),
		"critical header":     signSnapshot(t, provider.authKey, `{"alg":"ES256","kid":"KEY","crit":["private"]}`, claims),
		"case mismatch":       signSnapshot(t, provider.authKey, `{"Alg":"ES256","kid":"KEY"}`, claims),
		"other signing key":   signSnapshot(t, otherKey, header, claims),
		"issue time mismatch": {Bearer: valid.Bearer, IssuedAt: valid.IssuedAt.Add(time.Second)},
		"fractional snapshot": {Bearer: valid.Bearer, IssuedAt: valid.IssuedAt.Add(time.Nanosecond)},
		"short signature":     {Bearer: valid.Bearer[:strings.LastIndex(valid.Bearer, ".")+1] + "AA", IssuedAt: valid.IssuedAt},
		"invalid signature":   {Bearer: valid.Bearer[:strings.LastIndex(valid.Bearer, ".")+1] + strings.Repeat("A", 86), IssuedAt: valid.IssuedAt},
		"embedded newline":    {Bearer: valid.Bearer[:1] + "\n" + valid.Bearer[1:], IssuedAt: valid.IssuedAt},
	} {
		t.Run(name, func(t *testing.T) {
			if err := provider.Restore(snapshot); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("Restore error = %v, want ErrInvalidSnapshot", err)
			}
			got, err := provider.Snapshot()
			if err != nil || got != existing {
				t.Fatal("invalid restore changed cached token")
			}
		})
	}
}

func TestRestoreTimeBoundaries(t *testing.T) {
	for name, elapsed := range map[string]time.Duration{
		"future":        -time.Second,
		"before expiry": TokenTimeout - time.Nanosecond,
		"at expiry":     TokenTimeout,
		"after expiry":  TokenTimeout + time.Nanosecond,
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				provider := configuredProvider(t)
				iat := time.Now()
				if elapsed < 0 {
					iat = iat.Add(-elapsed)
				} else {
					time.Sleep(elapsed)
				}
				snapshot := signSnapshot(t, provider.authKey, `{"alg":"ES256","kid":"KEY"}`, `{"iss":"TEAM","iat":`+strconv.FormatInt(iat.Unix(), 10)+`}`)
				err := provider.Restore(snapshot)
				if elapsed >= 0 && elapsed < TokenTimeout {
					if err != nil || provider.IssuedAt().IsZero() {
						t.Fatalf("valid restore failed: %v", err)
					}
				} else if !errors.Is(err, ErrInvalidSnapshot) || !provider.IssuedAt().IsZero() {
					t.Fatalf("unusable snapshot accepted: %v", err)
				}
			})
		})
	}
}

func TestFreshTokenInvalidationBoundaries(t *testing.T) {
	for name, elapsed := range map[string]time.Duration{
		"before": minRefresh - time.Nanosecond,
		"at":     minRefresh,
		"after":  minRefresh + time.Nanosecond,
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				provider := configuredProvider(t)
				snapshot, err := provider.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				time.Sleep(elapsed)
				provider.Invalidate("")
				provider.Invalidate("different-bearer")
				if !provider.IssuedAt().Equal(snapshot.IssuedAt) {
					t.Fatal("empty or mismatched rejection cleared cache")
				}
				provider.Invalidate(snapshot.Bearer)
				if cleared := provider.IssuedAt().IsZero(); cleared != (elapsed >= minRefresh) {
					t.Fatalf("cache cleared = %v at %v", cleared, elapsed)
				}
			})
		})
	}
}

func TestRefreshBoundariesAndDelayedRejection(t *testing.T) {
	for name, elapsed := range map[string]time.Duration{
		"before": TokenTimeout - time.Nanosecond,
		"at":     TokenTimeout,
		"after":  TokenTimeout + time.Nanosecond,
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				provider := configuredProvider(t)
				first, err := provider.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				time.Sleep(elapsed)
				second, err := provider.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				if refreshed := second.Bearer != first.Bearer; refreshed != (elapsed >= TokenTimeout) {
					t.Fatalf("refreshed = %v at %v", refreshed, elapsed)
				}
				if elapsed >= TokenTimeout {
					provider.Invalidate(first.Bearer)
					got, err := provider.Snapshot()
					if err != nil || got != second {
						t.Fatal("late rejection of A changed bearer B or its issue time")
					}
				}
			})
		})
	}
}

func TestRestoreCannotDowngradeOrRemoveFreshGuard(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		provider := configuredProvider(t)
		old, err := provider.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if err := provider.Restore(old); err != nil {
			t.Fatal(err)
		}
		provider.Invalidate(old.Bearer)
		if provider.IssuedAt().IsZero() {
			t.Fatal("restoring same bearer removed fresh locally minted guard")
		}
		time.Sleep(minRefresh)
		provider.Invalidate(old.Bearer)
		current, err := provider.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if err := provider.Restore(old); err != nil {
			t.Fatal(err)
		}
		got, err := provider.Snapshot()
		if err != nil || got != current {
			t.Fatal("older valid restore rolled cache backward")
		}
	})
}

func TestConcurrentRestoreRefreshAndInvalidation(t *testing.T) {
	provider := configuredProvider(t)
	snapshot, err := provider.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 12 {
		workers.Go(func() {
			for range 100 {
				if err := provider.Restore(snapshot); err != nil {
					t.Error(err)
				}
				provider.Invalidate(snapshot.Bearer)
				got, err := provider.Snapshot()
				if err != nil || got != snapshot {
					t.Error("concurrent token operation broke the fresh bearer/issue-time pair")
				}
			}
		})
	}
	workers.Wait()
}

func TestTokenErrorsAreSafeAndPreserveDiagnostics(t *testing.T) {
	const secret = "private-signing-secret"
	_, err := AuthKeyFromFile(t.TempDir() + "/" + secret)
	if _, ok := errors.AsType[*os.PathError](err); !errors.Is(err, os.ErrNotExist) || !ok {
		t.Fatal("safe file error lost diagnostics")
	}
	for _, formatted := range []string{err.Error(), fmt.Sprintf("%s", err), fmt.Sprintf("%v", err)} {
		if strings.Contains(formatted, secret) {
			t.Fatal("safe file error leaked its path")
		}
	}
	provider := configuredProvider(t)
	snapshot := signSnapshot(t, provider.authKey, `{"alg":"ES256","kid":"KEY","`+secret+`":true}`, `{"iss":"TEAM","iat":0}`)
	err = provider.Restore(snapshot)
	if !errors.Is(err, ErrInvalidSnapshot) || errors.Unwrap(err) == nil {
		t.Fatal("safe restore error lost its diagnostic chain")
	}
	if strings.Contains(fmt.Sprint(err), secret) || strings.Contains(fmt.Sprint(err), snapshot.Bearer) {
		t.Fatal("safe restore error leaked JWT input")
	}
}

func TestConcurrentRefreshAtExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		provider := configuredProvider(t)
		old, err := provider.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(TokenTimeout)
		var workers sync.WaitGroup
		results := make(chan Snapshot, 20)
		for range 20 {
			workers.Go(func() {
				if err := provider.Restore(old); !errors.Is(err, ErrInvalidSnapshot) {
					t.Error("expired concurrent restore was accepted")
				}
				provider.Invalidate(old.Bearer)
				snapshot, err := provider.Snapshot()
				if err != nil {
					t.Error(err)
					return
				}
				results <- snapshot
			})
		}
		workers.Wait()
		close(results)
		current, err := provider.Snapshot()
		if err != nil || current.Bearer == old.Bearer || !current.IssuedAt.Equal(time.Now()) {
			t.Fatal("expiry did not produce a new matching snapshot")
		}
		for got := range results {
			if got != current {
				t.Fatal("concurrent expiry generated inconsistent bearer/issue-time pairs")
			}
		}
	})
}

func TestRestoreOnUnconfiguredToken(t *testing.T) {
	for _, provider := range []*Token{nil, {}} {
		if err := provider.Restore(Snapshot{}); !errors.Is(err, ErrAuthKeyNil) {
			t.Fatalf("Restore error = %v, want ErrAuthKeyNil", err)
		}
		provider.Invalidate("anything")
		if !provider.IssuedAt().IsZero() {
			t.Fatal("unconfigured token has an issue time")
		}
	}
}

func BenchmarkCachedBearer(b *testing.B) {
	provider := configuredProvider(b)
	if _, err := provider.Bearer(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := provider.Bearer(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSigning(b *testing.B) {
	provider := configuredProvider(b)
	b.ReportAllocs()
	for b.Loop() {
		provider.mu.Lock()
		err := provider.generateLocked()
		provider.mu.Unlock()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzRestore(f *testing.F) {
	provider := configuredProvider(f)
	original, err := provider.Snapshot()
	if err != nil {
		f.Fatal(err)
	}
	for _, bearer := range []string{"", ".", "a.b.c", "!.!.!", original.Bearer} {
		f.Add(bearer, original.IssuedAt.Unix())
	}
	f.Fuzz(func(t *testing.T, bearer string, issuedAt int64) {
		if err := provider.Restore(Snapshot{Bearer: bearer, IssuedAt: time.Unix(issuedAt, 0)}); err != nil && !errors.Is(err, ErrInvalidSnapshot) {
			t.Fatalf("unexpected restore error: %v", err)
		}
		got, err := provider.Snapshot()
		if err != nil || got != original {
			t.Fatal("untrusted snapshot replaced the current fresh token")
		}
	})
}
