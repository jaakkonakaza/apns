package apns2_test

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	apns "github.com/sideshow/apns2"
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

func TestIntTimestampParse(t *testing.T) {
	response := &apns.Response{}
	payload := "{\"reason\":\"Unregistered\", \"timestamp\":1458114061260}"
	if got := json.Unmarshal([]byte(payload), &response); got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got, want := response.Timestamp.Unix(), int64(1458114061260)/1000; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestInvalidTimestampParse(t *testing.T) {
	response := &apns.Response{}
	payload := "{\"reason\":\"Unregistered\", \"timestamp\": \"2016-01-16 17:44:04 +1300\"}"
	err := json.Unmarshal([]byte(payload), &response)
	if got := err; got == nil {
		t.Error("unexpected nil")
	}
}
