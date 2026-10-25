package apns2_test

import (
	"reflect"
	"testing"

	"github.com/sideshow/apns2"
)

func TestMarshalJSON(t *testing.T) {
	scenarios := []struct {
		in  interface{}
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

		if got, want := payloadBytes, scenario.out; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
		if got, want := err, scenario.err; !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}
