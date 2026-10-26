package payload_test

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/jaakkonakaza/apns2/payload"
)

type activityState struct {
	Counter int    `json:"counter"`
	Message string `json:"message"`
}

type activityAttributes struct {
	Name string `json:"name"`
}

func TestLiveActivityTypedObjects(t *testing.T) {
	p := payload.NewPayload().
		ContentState(activityState{Counter: 7, Message: "ready"}).
		Attributes(&activityAttributes{Name: "game"})
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"aps":{"content-state":{"counter":7,"message":"ready"},"attributes":{"name":"game"}}}`
	if string(data) != want {
		t.Fatalf("payload = %s, want %s", data, want)
	}
}

func TestLiveActivityObjectPresence(t *testing.T) {
	for _, field := range []struct {
		name string
		set  func(*payload.Payload, any) *payload.Payload
	}{
		{"content-state", (*payload.Payload).ContentState},
		{"attributes", (*payload.Payload).Attributes},
	} {
		t.Run(field.name, func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				value   any
				present bool
			}{
				{"nil", nil, false},
				{"nil struct pointer", (*activityState)(nil), false},
				{"nil map", map[string]any(nil), false},
				{"nil slice", []string(nil), false},
				{"empty struct", struct{}{}, true},
				{"empty map", map[string]any{}, true},
				{"raw object", jsontext.Value(`{}`), true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					p := field.set(payload.NewPayload(), map[string]any{"previous": true})
					data, err := json.Marshal(field.set(p, tc.value))
					if err != nil {
						t.Fatal(err)
					}
					want := `{"aps":{}}`
					if tc.present {
						want = fmt.Sprintf(`{"aps":{"%s":{}}}`, field.name)
					}
					if string(data) != want {
						t.Fatalf("payload = %s, want %s", data, want)
					}
				})
			}
		})
	}
}

func TestLiveActivityRejectsNonObjects(t *testing.T) {
	for _, field := range []struct {
		name string
		set  func(*payload.Payload, any) *payload.Payload
	}{
		{"content-state", (*payload.Payload).ContentState},
		{"attributes", (*payload.Payload).Attributes},
	} {
		for _, tc := range []struct {
			name  string
			value any
		}{
			{"string", "{}"},
			{"number", 7},
			{"array", []int{1, 2}},
			{"empty array", []int{}},
			{"null marshaler", jsontext.Value(`null`)},
			{"invalid raw JSON", jsontext.Value(`{}{}`)},
			{"duplicate keys", jsontext.Value(`{"a":1,"a":2}`)},
			{"unencodable field", map[string]any{"value": math.NaN()}},
		} {
			t.Run(field.name+"/"+tc.name, func(t *testing.T) {
				if _, err := json.Marshal(field.set(payload.NewPayload(), tc.value)); err == nil || !strings.Contains(err.Error(), field.name) {
					t.Fatalf("marshal error = %v, want %s object error", err, field.name)
				}
			})
		}
	}
}

func TestTypedNilDoesNotConflictWithMDM(t *testing.T) {
	p := payload.NewPayload().ContentState((*activityState)(nil)).Attributes(map[string]any(nil)).MDM("magic")
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"mdm":"magic"}` {
		t.Fatalf("payload = %s", data)
	}
}

func TestCustomAPSOverridesObjectValidation(t *testing.T) {
	p := payload.NewPayload().ContentState("ignored").Attributes(7).Custom("aps", map[string]any{"custom": true})
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"aps":{"custom":true}}` {
		t.Fatalf("payload = %s", data)
	}
}
