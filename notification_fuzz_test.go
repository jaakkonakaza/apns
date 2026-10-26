package apns2_test

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"testing"

	apns "github.com/jaakkonakaza/apns2"
)

func FuzzNotificationMarshalJSON(f *testing.F) {
	for _, seed := range []string{
		`{"aps":{"alert":"hello"}}`,
		`{"aps":{"content-state":{},"attributes":{}}}`,
		`{"aps":{"badge":0},"custom":[true,null,"日本語"]}`,
		`{"mdm":"push-magic"}`,
		`{"aps":{},"aps":{"alert":"duplicate"}}`,
		`{"aps":{}} {"trailing":true}`,
		`null`,
		`[1,2]`,
		``,
		`{"aps":`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// These forms all represent the payload itself, without notification metadata.
		payloads := []any{string(data), bytes.Clone(data)}
		if len(data) != 0 {
			payloads = append(payloads, jsontext.Value(data))
		}
		var first []byte
		var firstErr error
		for i, value := range payloads {
			notification := &apns.Notification{
				DeviceToken: "metadata-device-token",
				Topic:       "metadata-topic",
				PushType:    apns.PushTypeAlert,
				Payload:     value,
			}
			got, err := json.Marshal(notification)
			if i == 0 {
				first, firstErr = got, err
			} else if (err != nil) != (firstErr != nil) || err == nil && !bytes.Equal(got, first) {
				t.Fatalf("payload representation %T changed encoding: %q, %v versus %q, %v", value, got, err, first, firstErr)
			}
			if err == nil && !jsontext.Value(got).IsValid() {
				t.Fatalf("successful marshal returned invalid JSON: %q", got)
			}
			if len(data) != 0 {
				want, wantErr := json.Marshal(jsontext.Value(data))
				if (err != nil) != (wantErr != nil) || err == nil && !bytes.Equal(got, want) {
					t.Fatalf("notification changed raw payload: got %q, %v, want %q, %v", got, err, want, wantErr)
				}
			}
		}
	})
}
