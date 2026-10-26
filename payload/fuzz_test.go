package payload_test

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"testing"
	"time"

	"github.com/jaakkonakaza/apns/payload"
)

func FuzzPayloadSerialization(f *testing.F) {
	for _, s := range []string{`{}`, `{"counter":7}`, `{"a":1,"a":2}`, `null`, `[]`, `"text"`, `{} {}`, "{\"a\":\"\xff\"}"} {
		f.Add([]byte(s), uint8(0))
	}
	f.Add([]byte("magic"), uint8(1))
	f.Add([]byte("notice"), uint8(2))
	f.Fuzz(func(t *testing.T, data []byte, mode uint8) {
		var p any
		switch mode % 3 {
		case 0:
			p = payload.ActivityStart[jsontext.Value, jsontext.Value]{Timestamp: time.Unix(1, 0), AttributesType: "Type", Attributes: jsontext.Value(data), State: jsontext.Value(data), Alert: payload.ActivityAlert{Body: payload.Text("started")}}
		case 1:
			p = payload.MDM{PushMagic: string(data)}
		case 2:
			p = payload.Notification{APS: payload.APS{Alert: &payload.Alert{Body: string(data)}, Badge: new(0)}, Custom: map[string]any{"data": string(data)}}
		}
		encoded, err := json.Marshal(p)
		if err != nil {
			return
		}
		if !jsontext.Value(encoded).IsValid() {
			t.Fatalf("successful encoding is invalid: %q", encoded)
		}
		var root map[string]jsontext.Value
		if err := json.Unmarshal(encoded, &root); err != nil || root == nil {
			t.Fatalf("not a root object: %s (%v)", encoded, err)
		}
		if mode%3 == 1 {
			if len(root) != 1 || root["mdm"] == nil {
				t.Fatalf("invalid MDM envelope: %s", encoded)
			}
			return
		}
		var aps map[string]jsontext.Value
		if err := json.Unmarshal(root["aps"], &aps); err != nil || aps == nil {
			t.Fatalf("not an APS object: %s (%v)", encoded, err)
		}
		if mode%3 == 0 {
			for _, name := range []string{"content-state", "attributes"} {
				var object map[string]jsontext.Value
				if err := json.Unmarshal(aps[name], &object); err != nil || object == nil {
					t.Fatalf("required %s not an object: %s", name, encoded)
				}
			}
		}
	})
}

func BenchmarkNotificationEncoding(b *testing.B) {
	p := payload.Notification{APS: payload.APS{Alert: &payload.Alert{Title: "Order ready", Body: "Collect your order"}, Badge: new(0), Sound: &payload.Sound{Name: "default"}}, Custom: map[string]any{"orderID": "123"}}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := json.Marshal(p); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkActivityEncoding(b *testing.B) {
	p := payload.ActivityUpdate[activityState]{Timestamp: time.Unix(1685952000, 0), State: activityState{Counter: 7, Message: "ready"}}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := json.Marshal(p); err != nil {
			b.Fatal(err)
		}
	}
}
