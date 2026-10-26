package apns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"uuid"

	"github.com/jaakkonakaza/apns/token"
)

type readCloser struct {
	io.Reader
	closed *atomic.Bool
}

func (b *readCloser) Close() error { b.closed.Store(true); return nil }

type failReader struct{ cause error }

func (r failReader) Read([]byte) (int, error) { return 0, r.cause }

func TestRedirectsPreserveOriginalMetadataAndNeverResend(t *testing.T) {
	locations := []string{"/relative", "https://api.sandbox.push.apple.com/other", "https://child.api.sandbox.push.apple.com/other", "https://other.example/other", "http://api.sandbox.push.apple.com/other", "", "https://%gh/redirect-secret"}
	for _, status := range []int{301, 302, 303, 307, 308} {
		for i, location := range locations {
			t.Run(fmt.Sprintf("%d/%d", status, i), func(t *testing.T) {
				var calls atomic.Int32
				var closed atomic.Bool
				c := testClient(t, apiProvider(t), func(r *http.Request) (*http.Response, error) {
					if calls.Add(1) != 1 {
						t.Error("followed redirect and exposed origin credentials")
						return testResponse(200, ""), nil
					}
					if r.Header.Get("authorization") == "" {
						t.Error("initial authentication missing")
					}
					response := testResponse(status, "untrusted-body-secret")
					if location != "" {
						response.Header.Set("Location", location)
					}
					response.Body = &readCloser{Reader: strings.NewReader("untrusted-body-secret"), closed: &closed}
					return response, nil
				})
				r, err := c.Push(context.Background(), testRequest())
				responseErr, ok := errors.AsType[*ResponseError](err)
				if !ok || r.StatusCode != status || responseErr.Response.StatusCode != status || r.APNSID != "push-id" || r.RequestID != "request-id" || r.APNSUniqueID != "unique-id" {
					t.Fatalf("response=%+v error=%v", r, err)
				}
				if calls.Load() != 1 || !closed.Load() {
					t.Fatalf("calls=%d body closed=%v", calls.Load(), closed.Load())
				}
				for _, secret := range []string{"aabb", "redirect-secret", "untrusted-body-secret", location} {
					if secret != "" && strings.Contains(err.Error(), secret) {
						t.Fatalf("error leaked sensitive data %q", secret)
					}
				}
				if strings.Contains(location, "%gh") && responseErr.Unwrap() == nil {
					t.Fatal("lost malformed-Location diagnostic cause")
				}
			})
		}
	}
}

func TestConcurrentRedirectMetadataStaysWithRequest(t *testing.T) {
	const count = 24
	arrived := make(chan struct{}, count)
	release := make(chan struct{})
	c := testClient(t, apiProvider(t), func(r *http.Request) (*http.Response, error) {
		arrived <- struct{}{}
		<-release
		response := testResponse(307, "")
		response.Header.Set("apns-id", r.Header.Get("apns-id"))
		response.Header.Set("Location", "https://%gh/private")
		return response, nil
	})
	var wg sync.WaitGroup
	for range count {
		wg.Go(func() {
			id := uuid.New()
			request := testRequest()
			request.ID = &id
			r, err := c.Push(context.Background(), request)
			if _, ok := errors.AsType[*ResponseError](err); !ok || r.APNSID != id.String() {
				t.Errorf("response correlation crossed requests: got=%q want=%q error=%v", r.APNSID, id.String(), err)
			}
		})
	}
	for range count {
		<-arrived
	}
	close(release)
	wg.Wait()
}

func restoredProvider(t *testing.T) *token.Token {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	original, err := token.New(key, "key", "team")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := original.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := token.New(key, "key", "team")
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Restore(snapshot); err != nil {
		t.Fatal(err)
	}
	return restored
}

func TestDelayedProviderRejectionCannotInvalidateReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		provider := apiProvider(t)
		a, err := provider.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		started := make(chan string, 1)
		release := make(chan struct{})
		done := make(chan error, 1)
		c := testClient(t, provider, func(r *http.Request) (*http.Response, error) {
			started <- r.Header.Get("authorization")
			<-release
			return testResponse(403, `{"reason":"InvalidProviderToken"}`), nil
		})
		go func() { _, err := c.Push(context.Background(), testRequest()); done <- err }()
		if used := <-started; used != "bearer "+a.Bearer {
			t.Fatal("request used unexpected bearer")
		}
		time.Sleep(50 * time.Minute)
		b, err := provider.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if b.Bearer == a.Bearer {
			t.Fatal("provider failed to refresh")
		}
		close(release)
		if _, ok := errors.AsType[*Rejection](<-done); !ok {
			t.Fatal("missing typed rejection")
		}
		after, err := provider.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if after.Bearer != b.Bearer || !after.IssuedAt.Equal(b.IssuedAt) {
			t.Fatal("old rejection replaced current bearer/issue-time pair")
		}
	})
}

func TestProviderInvalidationRequiresCompleteRecognized403(t *testing.T) {
	for _, reason := range []string{"InvalidProviderToken", "ExpiredProviderToken"} {
		for _, status := range []int{200, 307, 400, 403, 410, 429, 500} {
			t.Run(fmt.Sprintf("%s/%d", reason, status), func(t *testing.T) {
				provider := restoredProvider(t)
				before, err := provider.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				calls := 0
				c := testClient(t, provider, func(*http.Request) (*http.Response, error) {
					calls++
					return testResponse(status, `{"reason":"`+reason+`","timestamp":"ignored except 410"}`), nil
				})
				_, _ = c.Push(context.Background(), testRequest())
				cleared := provider.IssuedAt().IsZero()
				if cleared != (status == 403) {
					t.Fatalf("status=%d cache cleared=%v", status, cleared)
				}
				if !cleared {
					after, err := provider.Snapshot()
					if err != nil {
						t.Fatal(err)
					}
					if after.Bearer != before.Bearer || !after.IssuedAt.Equal(before.IssuedAt) {
						t.Fatal("non-provider rejection mutated cache")
					}
				}
				if calls != 1 {
					t.Fatalf("automatic retry: calls=%d", calls)
				}
			})
		}
	}
	for _, test := range []struct {
		name, body string
		readErr    error
	}{
		{name: "unknown", body: `{"reason":"unknown-secret"}`},
		{name: "malformed", body: `{"reason":"InvalidProviderToken",`},
		{name: "oversized", body: `{"reason":"InvalidProviderToken","padding":"` + strings.Repeat("x", int(maxResponseBytes)) + `"}`},
		{name: "body read", readErr: errors.New("body-secret")},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := restoredProvider(t)
			before, _ := provider.Snapshot()
			c := testClient(t, provider, func(*http.Request) (*http.Response, error) {
				r := testResponse(403, test.body)
				if test.readErr != nil {
					r.Body = io.NopCloser(failReader{test.readErr})
				}
				return r, nil
			})
			response, err := c.Push(context.Background(), testRequest())
			if response.StatusCode != 403 || err == nil {
				t.Fatalf("response=%+v err=%v", response, err)
			}
			after, _ := provider.Snapshot()
			if after.Bearer != before.Bearer || !after.IssuedAt.Equal(before.IssuedAt) {
				t.Fatal("incomplete/unrecognized rejection invalidated token")
			}
		})
	}
}

type marshalerError struct{ cause error }

func (m marshalerError) MarshalJSON() ([]byte, error) { return nil, m.cause }

func TestErrorSummariesRedactSensitiveCausesAndPreserveInspection(t *testing.T) {
	const secret = "secret-sentinel-private-value"
	sentinel := errors.New(secret)
	tests := []struct {
		name      string
		rt        apiRoundTripper
		request   func() Request
		wantCause error
		wantURL   bool
	}{
		{name: "transport", rt: func(*http.Request) (*http.Response, error) {
			return nil, &url.Error{Op: "Post", URL: "https://" + secret + "/token", Err: sentinel}
		}, wantCause: sentinel, wantURL: true},
		{name: "encoding", request: func() Request { r := testRequest(); r.Payload = marshalerError{sentinel}; return r }, wantCause: sentinel},
		{name: "validation", request: func() Request { r := testRequest(); r.DeviceToken = secret; return r }},
		{name: "unknown reason", rt: func(*http.Request) (*http.Response, error) { return testResponse(400, `{"reason":"`+secret+`"}`), nil }},
		{name: "response body", rt: func(*http.Request) (*http.Response, error) {
			r := testResponse(201, "")
			r.Body = io.NopCloser(failReader{sentinel})
			return r, nil
		}, wantCause: sentinel},
		{name: "rejection body", rt: func(*http.Request) (*http.Response, error) {
			r := testResponse(400, "")
			r.Body = io.NopCloser(failReader{sentinel})
			return r, nil
		}, wantCause: sentinel},
		{name: "malformed redirect", rt: func(*http.Request) (*http.Response, error) {
			r := testResponse(307, "")
			r.Header.Set("Location", "https://%gh/"+secret)
			return r, nil
		}, wantURL: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rt := test.rt
			if rt == nil {
				rt = func(*http.Request) (*http.Response, error) {
					t.Error("local failure reached HTTP")
					return testResponse(200, ""), nil
				}
			}
			c := testClient(t, apiProvider(t), rt)
			request := testRequest()
			if test.request != nil {
				request = test.request()
			}
			_, err := c.Push(context.Background(), request)
			if err == nil {
				t.Fatal("missing error")
			}
			for _, formatted := range []string{err.Error(), fmt.Sprintf("%s", err), fmt.Sprintf("%v", err)} {
				if strings.Contains(formatted, secret) {
					t.Fatalf("unsafe normal error summary %q", formatted)
				}
			}
			if test.wantCause != nil && !errors.Is(err, test.wantCause) {
				t.Fatal("lost sentinel diagnostic cause")
			}
			if test.wantURL {
				if _, ok := errors.AsType[*url.Error](err); !ok {
					t.Fatal("lost url.Error diagnostic")
				}
			}
			if test.name == "unknown reason" {
				rejection, ok := errors.AsType[*Rejection](err)
				if !ok || string(rejection.Reason) != secret {
					t.Fatal("unknown reason unavailable programmatically")
				}
			}
		})
	}
}

func TestCancellationCauseSurvivesSafeWrapper(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		c := testClient(t, apiProvider(t), func(*http.Request) (*http.Response, error) { return nil, cause })
		r, err := c.Push(context.Background(), testRequest())
		if !errors.Is(err, cause) || r.StatusCode != 0 {
			t.Fatalf("response=%+v err=%v", r, err)
		}
	}
}

// APNs accepted the push once 200 arrives, so a failed or oversized body read
// must not report a failure that a caller would retry into a duplicate.
func TestAcceptanceSurvivesSuccessBodyFailures(t *testing.T) {
	for name, body := range map[string]io.Reader{
		"read error": failReader{errors.New("stream reset")},
		"oversized":  strings.NewReader(strings.Repeat("x", maxResponseBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			var closed atomic.Bool
			c := testClient(t, apiProvider(t), func(*http.Request) (*http.Response, error) {
				r := testResponse(200, "")
				r.Body = &readCloser{Reader: body, closed: &closed}
				return r, nil
			})
			r, err := c.Push(context.Background(), testRequest())
			if err != nil || r.StatusCode != 200 || r.APNSID != "push-id" {
				t.Fatalf("accepted push reported response=%+v error=%v", r, err)
			}
			if !closed.Load() {
				t.Fatal("success body not closed")
			}
		})
	}
}
