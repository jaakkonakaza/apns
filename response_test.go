package apns

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDeviceTokenInvalidationTimestamp(t *testing.T) {
	for _, test := range []struct {
		name, body string
		want       time.Time
		decodeErr  bool
	}{
		{"milliseconds", `{"reason":"Unregistered","timestamp":1458114061260}`, time.UnixMilli(1458114061260), false},
		{"epoch", `{"reason":"Unregistered","timestamp":0}`, time.UnixMilli(0), false},
		{"absent", `{"reason":"Unregistered"}`, time.Time{}, false},
		{"null", `{"reason":"Unregistered","timestamp":null}`, time.Time{}, false},
		{"fraction", `{"reason":"Unregistered","timestamp":1.5}`, time.Time{}, true},
		{"decimal integer", `{"reason":"Unregistered","timestamp":1.0}`, time.Time{}, true},
		{"exponent", `{"reason":"Unregistered","timestamp":1e3}`, time.Time{}, true},
		{"string", `{"reason":"Unregistered","timestamp":"1458114061260"}`, time.Time{}, true},
		{"boolean", `{"reason":"Unregistered","timestamp":true}`, time.Time{}, true},
		{"overflow", `{"reason":"Unregistered","timestamp":9223372036854775808}`, time.Time{}, true},
		{"negative overflow", `{"reason":"Unregistered","timestamp":-9223372036854775809}`, time.Time{}, true},
		{"no unit guessing", `{"reason":"Unregistered","timestamp":1458114061}`, time.UnixMilli(1458114061), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := testClient(t, apiProvider(t), func(*http.Request) (*http.Response, error) { return testResponse(410, test.body), nil })
			response, err := c.Push(context.Background(), testRequest())
			rejection, ok := errors.AsType[*Rejection](err)
			if !ok || response.StatusCode != 410 || rejection.Response.StatusCode != 410 || !rejection.DeviceTokenInvalidatedAt.Equal(test.want) {
				t.Fatalf("response=%+v rejection=%+v err=%v", response, rejection, err)
			}
			if (rejection.Unwrap() != nil) != test.decodeErr {
				t.Fatalf("decode cause=%v want error=%v", rejection.Unwrap(), test.decodeErr)
			}
			if string(rejection.Reason) != "Unregistered" || response.APNSID != "push-id" || response.RequestID != "request-id" || response.Header.Get("Retry-After") != "60" {
				t.Fatal("decode lost independently valid metadata/reason")
			}
		})
	}
}

func TestNon410TimestampDoesNotBecomeDeviceInvalidation(t *testing.T) {
	for _, status := range []int{200, 400, 403, 429, 500} {
		c := testClient(t, apiProvider(t), func(*http.Request) (*http.Response, error) {
			return testResponse(status, `{"reason":"Unregistered","timestamp":1458114061260}`), nil
		})
		response, err := c.Push(context.Background(), testRequest())
		if response.StatusCode != status {
			t.Fatal("status lost")
		}
		if status == 200 {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		rejection, ok := errors.AsType[*Rejection](err)
		if !ok || !rejection.DeviceTokenInvalidatedAt.IsZero() {
			t.Fatalf("non410 timestamp populated device invalidation: %+v %v", rejection, err)
		}
	}
}

func TestResponseClassificationsAndBoundedBodies(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"acceptance", 200, "", "nil"},
		{"irrelevant successful reason", 200, `{"reason":"InvalidProviderToken"}`, "nil"},
		{"irrelevant successful malformed body", 200, "not-json", "nil"},
		{"unknown reason", 400, `{"reason":"future-reason"}`, "rejection"},
		{"empty rejection", 403, "", "rejection"},
		{"malformed rejection", 429, "{", "rejection cause"},
		{"oversized rejection", 500, strings.Repeat("x", int(maxResponseBytes)+1), "rejection cause"},
		{"oversized acceptance", 200, strings.Repeat("x", int(maxResponseBytes)+1), "nil"},
		{"unexpected success", 201, "", "response"},
		{"unexpected empty success", 204, "", "response"},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := testResponse(test.status, test.body)
			c := testClient(t, apiProvider(t), func(*http.Request) (*http.Response, error) { return original, nil })
			response, err := c.Push(context.Background(), testRequest())
			if response.StatusCode != test.status || response.APNSID != "push-id" || response.APNSUniqueID != "unique-id" || response.RequestID != "request-id" {
				t.Fatalf("response metadata lost %+v", response)
			}
			switch test.want {
			case "nil":
				if err != nil {
					t.Fatal(err)
				}
			case "rejection", "rejection cause":
				r, ok := errors.AsType[*Rejection](err)
				if !ok {
					t.Fatalf("expected rejection got %T", err)
				}
				if test.want == "rejection cause" && r.Unwrap() == nil {
					t.Fatal("missing body diagnostic")
				}
			case "response", "response cause":
				r, ok := errors.AsType[*ResponseError](err)
				if !ok {
					t.Fatalf("expected response error got %T", err)
				}
				if test.want == "response cause" && r.Unwrap() == nil {
					t.Fatal("missing body diagnostic")
				}
			}
			original.Header.Set("Retry-After", "changed")
			if response.Header.Get("Retry-After") != "60" {
				t.Fatal("response headers were not cloned")
			}
		})
	}
	for _, status := range []int{201, 400} {
		cause := errors.New("read-secret")
		c := testClient(t, apiProvider(t), func(*http.Request) (*http.Response, error) {
			r := testResponse(status, "")
			r.Body = io.NopCloser(failReader{cause})
			return r, nil
		})
		response, err := c.Push(context.Background(), testRequest())
		if response.StatusCode != status || !errors.Is(err, cause) {
			t.Fatalf("body failure metadata/cause lost response=%+v error=%v", response, err)
		}
	}
}

// Device and broadcast reasons share one type so they compare with Rejection.Reason.
var _ = [...]Reason{ReasonBadDeviceToken, ReasonUnregistered, ReasonExpiredProviderToken, ReasonBadChannelID, ReasonChannelNotRegistered}
