package apns2_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	apns "github.com/sideshow/apns2"
)

func TestClientCustomHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	for _, tokenAuth := range []bool{false, true} {
		t.Run(map[bool]string{false: "certificate", true: "token"}[tokenAuth], func(t *testing.T) {
			options := []apns.ClientOption{apns.WithHost(server.URL), apns.WithHTTPClient(server.Client())}
			client := apns.NewClient(mockCert(), options...)
			if tokenAuth {
				client = apns.NewTokenClient(mockToken(), options...)
			}
			defer client.CloseIdleConnections()
			response, err := client.Push(context.Background(), mockNotification())
			if err != nil || response == nil || !response.Sent() {
				t.Fatalf("custom HTTP push = %v, %v", response, err)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClientPreservesTransportErrorDuringCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	transportErr := errors.New("TLS handshake failed")
	client := apns.NewTokenClient(mockToken(), apns.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		cancel()
		return nil, transportErr
	})}))
	_, err := client.Push(ctx, mockNotification())
	if _, ok := errors.AsType[*url.Error](err); !ok {
		t.Fatalf("error = %T %v, want *url.Error", err, err)
	}
	if !errors.Is(err, transportErr) {
		t.Fatalf("error = %v, want original transport failure", err)
	}
}

func TestClientPreservesDeadlineErrorWrapper(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	client := apns.NewTokenClient(mockToken(), apns.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}))
	_, err := client.Push(ctx, mockNotification())
	if _, ok := errors.AsType[*url.Error](err); !ok {
		t.Fatalf("error = %T %v, want *url.Error", err, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want deadline exceeded", err)
	}
}
