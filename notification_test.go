package apns2_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jaakkonakaza/apns2"
)

func TestMarshalJSON(t *testing.T) {
	scenarios := []struct {
		in  any
		out []byte
		err error
	}{
		{`{"a": "b"}`, []byte(`{"a": "b"}`), nil},
		{[]byte(`{"a": "b"}`), []byte(`{"a": "b"}`), nil},
		{struct {
			A string `json:"a"`
		}{"b"}, []byte(`{"a":"b"}`), nil},
	}

	notification := &apns2.Notification{}

	for _, scenario := range scenarios {
		notification.Payload = scenario.in
		payloadBytes, err := notification.MarshalJSON()

		if got, want := payloadBytes, scenario.out; !bytes.Equal(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := err, scenario.err; !errors.Is(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}
