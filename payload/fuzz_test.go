package payload_test

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"testing"
	"unicode/utf8"

	"github.com/jaakkonakaza/apns2/payload"
)

func FuzzPayloadSerialization(f *testing.F) {
	for _, seed := range []struct {
		data string
		mode uint8
	}{
		{`{}`, 0},
		{`{"counter":7}`, 0},
		{`{"a":1,"a":2}`, 1},
		{`null`, 0},
		{`[1,2]`, 1},
		{``, 2},
		{`{}`, 3},
		{`{"custom":true}`, 4},
		{`{"conflict":true}`, 5},
		{`magic`, 6},
	} {
		f.Add([]byte(seed.data), seed.mode)
	}
	f.Fuzz(func(t *testing.T, data []byte, mode uint8) {
		mode %= 7
		var p payload.Payload
		switch mode {
		case 0:
			p.ContentState(jsontext.Value(data))
		case 1:
			p.Attributes(jsontext.Value(data))
		case 2:
			p.ContentState((*activityState)(nil)).Attributes(map[string]any(nil))
		case 3:
			p.ContentState(struct{}{}).Attributes(map[string]any{})
		case 4:
			p.ContentState("ignored").Custom("aps", jsontext.Value(data))
		case 5:
			p.MDM(string(data)).Custom("other", true)
		case 6:
			p.MDM(string(data))
		}
		encoded, err := json.Marshal(p)
		if mode == 5 {
			if err == nil {
				t.Fatal("MDM payload with another key was accepted")
			}
			return
		}
		if err != nil {
			if mode == 2 || mode == 3 || mode == 6 && utf8.Valid(data) {
				t.Fatal(err)
			}
			return
		}
		var root map[string]jsontext.Value
		if err := json.Unmarshal(encoded, &root); err != nil || root == nil {
			t.Fatalf("successful payload is not a JSON object: %s (%v)", encoded, err)
		}
		if mode == 6 {
			if _, present := root["mdm"]; !present || len(root) != 1 {
				t.Fatalf("MDM shape = %s", encoded)
			}
			return
		}
		if mode == 4 {
			return
		}
		var aps map[string]jsontext.Value
		if err := json.Unmarshal(root["aps"], &aps); err != nil || aps == nil {
			t.Fatalf("aps is not a JSON object: %s (%v)", encoded, err)
		}
		for _, field := range []string{"content-state", "attributes"} {
			if value, present := aps[field]; present && !bytes.HasPrefix(bytes.TrimSpace(value), []byte("{")) {
				t.Fatalf("%s is not an object: %s", field, value)
			}
		}
		if mode == 2 && len(aps) != 0 {
			t.Fatalf("typed nil fields were not omitted: %s", encoded)
		}
		if mode == 3 && (string(aps["content-state"]) != `{}` || string(aps["attributes"]) != `{}`) {
			t.Fatalf("explicit empty objects were not preserved: %s", encoded)
		}
	})
}
