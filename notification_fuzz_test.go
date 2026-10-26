package apns

import (
	"bytes"
	"encoding/json/jsontext"
	"testing"
)

func FuzzRawPayload(f *testing.F) {
	for _, seed := range []string{`{}`, `{"aps":{"badge":0},"custom":[true,null,"日本語"]}`, `{"mdm":"magic"}`, `{"aps":{},"aps":{}}`, `{} {}`, `null`, `[]`, ``, `{"aps":`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		encoded, err := marshalPayload(jsontext.Value(data), 5120)
		if err != nil {
			return
		}
		if len(encoded) > 5120 || !jsontext.Value(encoded).IsValid() || len(bytes.TrimSpace(encoded)) == 0 || bytes.TrimSpace(encoded)[0] != '{' {
			t.Fatalf("accepted invalid payload %q", encoded)
		}
	})
}
