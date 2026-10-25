package apns2_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apns "github.com/sideshow/apns2"
	"github.com/sideshow/apns2/token"
)

func TestResponseMetadataSurvivesDecodeError(t *testing.T) {
	for _, status := range []int{http.StatusGone, http.StatusServiceUnavailable} {
		for _, body := range []string{"{", `{"timestamp":"invalid"}`} {
			t.Run(fmt.Sprintf("status=%d/body=%s", status, body), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("apns-id", "request-id")
					w.Header().Set("apns-unique-id", "unique-id")
					w.WriteHeader(status)
					_, _ = w.Write([]byte(body))
				}))
				defer server.Close()
				response, err := mockClient(server.URL).Push(context.Background(), mockNotification())
				if err == nil {
					t.Fatal("malformed response returned no error")
				}
				if response == nil || response.StatusCode != status || response.ApnsID != "request-id" || response.ApnsUniqueID != "unique-id" {
					t.Fatalf("response metadata lost: %+v", response)
				}
			})
		}
	}
}

func TestResponseBodyCannotReplaceHTTPMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("apns-id", "request-id")
		w.Header().Set("apns-unique-id", "unique-id")
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"StatusCode":200,"ApnsID":"body-id","ApnsUniqueID":"body-unique-id","reason":"Unregistered","timestamp":1458114061260}`))
	}))
	defer server.Close()
	response, err := mockClient(server.URL).Push(context.Background(), mockNotification())
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusGone || response.ApnsID != "request-id" || response.ApnsUniqueID != "unique-id" {
		t.Fatalf("body replaced metadata: %+v", response)
	}
	if response.Reason != "Unregistered" || response.Timestamp.UnixMilli() != 1458114061260 {
		t.Fatalf("incorrect body fields: %+v", response)
	}
}

func TestDeviceTokenValidation(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.RawQuery != "" || !strings.HasPrefix(r.URL.Path, "/3/device/") {
			t.Errorf("unexpected URL %s", r.URL)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := mockClient(server.URL)
	for _, value := range []string{"", "a", "zz", "dead/beef", "dead?beef", "dead#beef", "de ad"} {
		n := mockNotification()
		n.DeviceToken = value
		if _, err := client.Push(context.Background(), n); err == nil {
			t.Errorf("accepted invalid device token %q", value)
		}
	}
	if _, err := client.Push(context.Background(), nil); err == nil {
		t.Error("accepted nil notification")
	}
	if requests.Load() != 0 {
		t.Fatalf("invalid tokens caused %d requests", requests.Load())
	}
	for _, value := range []string{"00", "aAbB", strings.Repeat("ab", 40)} {
		n := mockNotification()
		n.DeviceToken = value
		if _, err := client.Push(context.Background(), n); err != nil {
			t.Errorf("rejected hexadecimal token %q: %v", value, err)
		}
	}
	if requests.Load() != 3 {
		t.Errorf("valid tokens caused %d requests, want 3", requests.Load())
	}
}

func TestPushReturnsTokenSigningError(t *testing.T) {
	client := apns.NewTokenClient(&token.Token{}, apns.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("push reached transport after token signing failed")
		return nil, errors.New("unexpected request")
	})}))
	if _, err := client.Push(context.Background(), mockNotification()); !errors.Is(err, token.ErrAuthKeyNil) {
		t.Fatalf("push error = %v, want ErrAuthKeyNil", err)
	}
}

func TestZeroExpirationOmitsHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, present := r.Header["Apns-Expiration"]; present {
			t.Error("zero expiration sent an expiration header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if _, err := mockClient(server.URL).Push(context.Background(), mockNotification()); err != nil {
		t.Fatal(err)
	}
}

func TestPreEpochExpirationSendsZero(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("apns-expiration"); got != "0" {
			t.Errorf("expiration = %q, want 0", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	n := mockNotification()
	n.Expiration = time.Unix(-1, 0)
	if _, err := mockClient(server.URL).Push(context.Background(), n); err != nil {
		t.Fatal(err)
	}
}
