package apns2_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	apns "github.com/jaakkonakaza/apns2"
)

// Unit Tests

func TestResponseSent(t *testing.T) {
	if got, want := apns.StatusSent, http.StatusOK; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := (&apns.Response{StatusCode: 200}).Sent(), true; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := (&apns.Response{StatusCode: 400}).Sent(), false; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestResponseTimestamp(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       time.Time
		wantError  bool
	}{
		{"milliseconds", `{"reason":"Unregistered","timestamp":1458114061260}`, time.UnixMilli(1458114061260), false},
		{"epoch", `{"timestamp":0}`, time.Unix(0, 0), false},
		{"absent", `{}`, time.Time{}, false},
		{"null", `{"timestamp":null}`, time.Time{}, false},
		{"invalid", `{"timestamp":"2016-01-16 17:44:04 +1300"}`, time.Time{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusGone)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			response, err := mockClient(server.URL).Push(context.Background(), mockNotification())
			if (err != nil) != tc.wantError {
				t.Fatalf("Push error = %v", err)
			}
			if response == nil || !response.Timestamp.Equal(tc.want) {
				t.Fatalf("response = %+v, want timestamp %v", response, tc.want)
			}
		})
	}
}
