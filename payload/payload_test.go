package payload_test

import (
	"bytes"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jaakkonakaza/apns/payload"
)

var eventTime = time.Unix(1685952000, 999999999)

type activityState struct {
	Counter int    `json:"counter"`
	Message string `json:"message"`
}
type activityAttributes struct {
	Name string `json:"name"`
}

func encoded(t *testing.T, v any, opts ...json.Options) []byte {
	t.Helper()
	data, err := json.Marshal(v, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decoded(t *testing.T, data []byte) map[string]jsontext.Value {
	t.Helper()
	var v map[string]jsontext.Value
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func equalJSON(t *testing.T, got []byte, want string) {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want), &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestNotificationFields(t *testing.T) {
	p := payload.Notification{APS: payload.APS{
		Alert: &payload.Alert{Title: "hello", Subtitle: "sub", Body: "body", LaunchImage: "launch.png"}, Badge: new(0),
		Sound: &payload.Sound{Name: "default"}, Category: "conversation", ThreadID: "thread", ContentAvailable: true,
		MutableContent: true, InterruptionLevel: payload.InterruptionLevelTimeSensitive, RelevanceScore: new(0.0),
		TargetContentID: "window", FilterCriteria: "work", ContentChanged: true,
		Extensions: map[string]any{"future-apple-field": true},
	}, Custom: map[string]any{"orderID": "123", "unicode": "日本語 🎉"}}
	equalJSON(t, encoded(t, p), `{"aps":{"alert":{"title":"hello","subtitle":"sub","body":"body","launch-image":"launch.png"},"badge":0,"sound":"default","category":"conversation","thread-id":"thread","content-available":1,"mutable-content":1,"interruption-level":"time-sensitive","relevance-score":0,"target-content-id":"window","filter-criteria":"work","content-changed":true,"future-apple-field":true},"orderID":"123","unicode":"日本語 🎉"}`)
	equalJSON(t, encoded(t, payload.Notification{}), `{"aps":{}}`)
	equalJSON(t, encoded(t, payload.Background{Custom: map[string]any{"test": "id"}}), `{"aps":{"content-available":1},"test":"id"}`)
	equalJSON(t, encoded(t, payload.MDM{PushMagic: "magic"}), `{"mdm":"magic"}`)
	if _, err := json.Marshal(payload.MDM{}); err == nil {
		t.Fatal("empty MDM accepted")
	}
}

func TestOrdinaryAlertLocalization(t *testing.T) {
	p := payload.Notification{APS: payload.APS{Alert: &payload.Alert{
		LocKey: "body-key", LocArgs: []string{"one"}, TitleLocKey: "title-key", TitleLocArgs: []string{"two"},
		SubtitleLocKey: "subtitle-key", SubtitleLocArgs: []string{"three"},
	}}}
	equalJSON(t, encoded(t, p), `{"aps":{"alert":{"loc-key":"body-key","loc-args":["one"],"title-loc-key":"title-key","title-loc-args":["two"],"subtitle-loc-key":"subtitle-key","subtitle-loc-args":["three"]}}}`)
	for _, a := range []payload.Alert{
		{Title: "text", TitleLocKey: "key"},
		{Subtitle: "text", SubtitleLocKey: "key"},
		{Body: "text", LocKey: "key"},
		{TitleLocArgs: []string{"arg"}},
		{SubtitleLocArgs: []string{"arg"}},
		{LocArgs: []string{"arg"}},
	} {
		if _, err := json.Marshal(a); err == nil {
			t.Fatalf("invalid alert accepted: %#v", a)
		}
	}
}

func TestOrdinaryRelevanceScoreRange(t *testing.T) {
	for _, score := range []float64{-0.1, 1.1, math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := json.Marshal(payload.Notification{APS: payload.APS{RelevanceScore: new(score)}}); err == nil {
			t.Fatalf("ordinary relevance score accepted: %v", score)
		}
	}
	for _, score := range []float64{0, 0.5, 1} {
		encoded(t, payload.Notification{APS: payload.APS{RelevanceScore: new(score)}})
	}
	encoded(t, payload.ActivityUpdate[any]{Timestamp: eventTime, State: struct{}{}, RelevanceScore: new(100.0)})
}

func TestSounds(t *testing.T) {
	for _, tc := range []struct {
		s    payload.Sound
		want string
	}{
		{payload.Sound{Name: "bell.caf"}, `"bell.caf"`},
		{payload.Sound{Name: "default", Critical: true}, `{"critical":1,"name":"default"}`},
		{payload.Sound{Name: "bell.caf", Critical: true, Volume: new(0.0)}, `{"critical":1,"name":"bell.caf","volume":0}`},
		{payload.Sound{Name: "bell.caf", Critical: true, Volume: new(0.8)}, `{"critical":1,"name":"bell.caf","volume":0.8}`},
	} {
		equalJSON(t, encoded(t, tc.s), tc.want)
	}
	for _, s := range []payload.Sound{{}, {Name: "bell", Volume: new(0.5)}, {Name: "bell", Critical: true, Volume: new(-0.1)}, {Name: "bell", Critical: true, Volume: new(1.1)}, {Name: "bell", Critical: true, Volume: new(math.NaN())}, {Name: "bell", Critical: true, Volume: new(math.Inf(1))}} {
		if _, err := json.Marshal(s); err == nil {
			t.Fatalf("invalid sound accepted: %#v", s)
		}
	}
}

func TestActivities(t *testing.T) {
	state := activityState{7, "ready"}
	attrs := activityAttributes{"game"}
	p := payload.ActivityStart[activityAttributes, activityState]{
		Timestamp: eventTime, AttributesType: "GameAttributes", Attributes: attrs, State: state,
		Alert: payload.ActivityAlert{Title: payload.Localized("TITLE", "Team"), Body: payload.Text("Started"), Sound: "ping.caf"}, StaleDate: new(time.Unix(1685952100, 0)), Updates: payload.TokenUpdates(), Custom: map[string]any{"lab-test-id": "start"},
	}
	equalJSON(t, encoded(t, p), `{"aps":{"timestamp":1685952000,"event":"start","attributes-type":"GameAttributes","attributes":{"name":"game"},"content-state":{"counter":7,"message":"ready"},"alert":{"title":{"loc-key":"TITLE","loc-args":["Team"]},"body":"Started","sound":"ping.caf"},"stale-date":1685952100,"input-push-token":1},"lab-test-id":"start"}`)
	p.Updates = payload.ChannelUpdates("channel")
	aps := decoded(t, decoded(t, encoded(t, p))["aps"])
	if string(aps["input-push-channel"]) != `"channel"` || aps["input-push-token"] != nil {
		t.Fatalf("conflicting start destinations: %s", encoded(t, p))
	}
	p.Updates = payload.NormalUpdates()
	aps = decoded(t, decoded(t, encoded(t, p))["aps"])
	if aps["input-push-channel"] != nil || aps["input-push-token"] != nil {
		t.Fatal("normal updates emitted destination")
	}
	p.Updates = payload.ChannelUpdates("")
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("empty channel accepted")
	}
	equalJSON(t, encoded(t, payload.ActivityUpdate[activityState]{Timestamp: eventTime, State: state, Alert: &payload.ActivityAlert{Body: payload.Localized("BODY", "arg")}, RelevanceScore: new(100.0)}), `{"aps":{"timestamp":1685952000,"event":"update","content-state":{"counter":7,"message":"ready"},"alert":{"body":{"loc-key":"BODY","loc-args":["arg"]}},"relevance-score":100}}`)
	equalJSON(t, encoded(t, payload.ActivityEnd[activityState]{Timestamp: eventTime, State: state, DismissalDate: new(time.Unix(0, 0))}), `{"aps":{"timestamp":1685952000,"event":"end","content-state":{"counter":7,"message":"ready"},"dismissal-date":0}}`)
}

func TestRequiredObjects(t *testing.T) {
	for _, value := range []any{struct{}{}, map[string]any{}, jsontext.Value(`{}`), &struct{}{}} {
		p := payload.ActivityStart[any, any]{Timestamp: eventTime, AttributesType: "Empty", Attributes: value, State: value, Alert: payload.ActivityAlert{Title: payload.Text("start")}}
		aps := decoded(t, decoded(t, encoded(t, p))["aps"])
		if string(aps["attributes"]) != "{}" || string(aps["content-state"]) != "{}" {
			t.Fatalf("empty objects not preserved: %s", encoded(t, p))
		}
	}
	for _, value := range []any{nil, (*activityState)(nil), map[string]any(nil), []int(nil), "{}", 7, true, []int{}, jsontext.Value(`null`), jsontext.Value(`[]`), jsontext.Value(`{}{}`), jsontext.Value(`{"a":1,"a":2}`), map[string]any{"a": math.NaN()}} {
		for _, which := range []string{"content-state", "attributes"} {
			p := payload.ActivityStart[any, any]{Timestamp: eventTime, AttributesType: "Type", Attributes: map[string]any{}, State: map[string]any{}, Alert: payload.ActivityAlert{Body: payload.Text("start")}}
			if which == "content-state" {
				p.State = value
			} else {
				p.Attributes = value
			}
			if _, err := json.Marshal(p); err == nil || !strings.Contains(err.Error(), which) {
				t.Fatalf("%s accepted %T or wrong error: %v", which, value, err)
			}
		}
	}
}

func TestActivityRequirements(t *testing.T) {
	for _, p := range []any{
		payload.ActivityStart[any, any]{Timestamp: eventTime, AttributesType: "Type", Attributes: struct{}{}, State: struct{}{}},
		payload.ActivityStart[any, any]{Timestamp: eventTime, Attributes: struct{}{}, State: struct{}{}, Alert: payload.ActivityAlert{Body: payload.Text("start")}},
		payload.ActivityUpdate[any]{State: struct{}{}},
		payload.ActivityEnd[any]{State: struct{}{}},
		payload.ActivityUpdate[any]{Timestamp: eventTime, State: struct{}{}, StaleDate: new(time.Time{})},
		payload.ActivityEnd[any]{Timestamp: eventTime, State: struct{}{}, DismissalDate: new(time.Time{})},
		payload.ActivityUpdate[any]{Timestamp: eventTime, State: struct{}{}, Alert: &payload.ActivityAlert{}},
		payload.ActivityAlert{Body: payload.Localized("")},
	} {
		if _, err := json.Marshal(p); err == nil {
			t.Fatalf("invalid activity accepted: %#v", p)
		}
	}
	// Unix epoch is a valid explicit protocol timestamp, unlike Go's zero time.
	equalJSON(t, encoded(t, payload.ActivityUpdate[any]{Timestamp: time.Unix(0, 999999999), State: struct{}{}}), `{"aps":{"timestamp":0,"event":"update","content-state":{}}}`)
}

func TestReservedNames(t *testing.T) {
	for _, p := range []any{
		payload.Notification{Custom: map[string]any{"aps": map[string]any{}}},
		payload.Background{Custom: map[string]any{"aps": map[string]any{}}},
		payload.Notification{APS: payload.APS{Extensions: map[string]any{"badge": 0}}},
		payload.ActivityUpdate[any]{Timestamp: eventTime, State: struct{}{}, Custom: map[string]any{"aps": nil}},
	} {
		if _, err := json.Marshal(p); err == nil {
			t.Fatalf("reserved name accepted: %#v", p)
		}
	}
	for _, name := range []string{"timestamp", "event", "content-state", "attributes", "attributes-type", "stale-date", "dismissal-date", "input-push-token", "input-push-channel", "alert", "relevance-score"} {
		p := payload.ActivityUpdate[any]{Timestamp: eventTime, State: struct{}{}, Extensions: map[string]any{name: nil}}
		if _, err := json.Marshal(p); err == nil {
			t.Fatalf("reserved activity member %s accepted", name)
		}
		p.Extensions = nil
		p.Custom = map[string]any{name: nil}
		if _, err := json.Marshal(p); err == nil {
			t.Fatalf("reserved root activity member %s accepted", name)
		}
	}
	// Protocol-looking root application metadata does not overwrite the APS fields.
	equalJSON(t, encoded(t, payload.Notification{Custom: map[string]any{"mdm": "metadata"}}), `{"aps":{},"mdm":"metadata"}`)
}

func TestDateEpochs(t *testing.T) {
	for _, tc := range []struct {
		date time.Time
		want string
	}{
		{time.Unix(978307200, 0), `0`},
		{time.Unix(978307200, 250000000), `0.25`},
		{time.Unix(978307199, 500000000), `-0.5`},
		{time.Unix(0, 0), `-978307200`},
	} {
		equalJSON(t, encoded(t, payload.ActivityDate{Time: tc.date}), tc.want)
	}
	if _, err := json.Marshal(payload.ActivityDate{}); err == nil {
		t.Fatal("zero activity date accepted")
	}
	type state struct {
		Date   payload.ActivityDate `json:"date"`
		Normal time.Time            `json:"normal"`
	}
	p := payload.ActivityUpdate[state]{Timestamp: time.Unix(978307200, 0), State: state{payload.ActivityDate{Time: time.Unix(978307200, 250000000)}, time.Unix(978307200, 0).UTC()}}
	equalJSON(t, encoded(t, p), `{"aps":{"timestamp":978307200,"event":"update","content-state":{"date":0.25,"normal":"2001-01-01T00:00:00Z"}}}`)
}

func TestJSONV1Bridge(t *testing.T) {
	values := []any{payload.Notification{APS: payload.APS{Alert: &payload.Alert{Title: "title"}, Badge: new(0), Sound: &payload.Sound{Name: "default"}}}, payload.Background{}, payload.MDM{PushMagic: "magic"}, payload.ActivityStart[any, any]{Timestamp: eventTime, AttributesType: "Type", Attributes: map[string]any{}, State: struct{}{}, Alert: payload.ActivityAlert{Title: payload.Localized("TITLE", "arg")}, Updates: payload.TokenUpdates()}, payload.ActivityUpdate[any]{Timestamp: eventTime, State: struct{}{}}, payload.ActivityEnd[any]{Timestamp: eventTime, State: struct{}{}}, payload.ActivityDate{Time: eventTime}}
	for _, v := range values {
		a := encoded(t, v)
		b, err := jsonv1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		equalJSON(t, b, string(a))
	}
}

func TestApplicationOptionsDoNotChangeProtocol(t *testing.T) {
	calls := 0
	marshalers := json.MarshalFunc(func(v activityState) ([]byte, error) {
		calls++
		return []byte(`{"custom-state":"ok","counter":0}`), nil
	})
	p := payload.ActivityStart[map[string]any, activityState]{Timestamp: time.Unix(0, 0), AttributesType: "Type", Attributes: map[string]any{}, State: activityState{}, Alert: payload.ActivityAlert{Title: payload.Text("title")}, Updates: payload.TokenUpdates(), Custom: map[string]any{"data": activityState{}}}
	data := encoded(t, p, json.WithMarshalers(marshalers), json.StringifyNumbers(true), json.OmitZeroStructFields(true))
	if calls != 2 {
		t.Fatalf("application encoders called %d times, want once each", calls)
	}
	equalJSON(t, data, `{"aps":{"timestamp":0,"event":"start","attributes-type":"Type","attributes":{},"content-state":{"custom-state":"ok","counter":0},"alert":{"title":"title"},"input-push-token":1},"data":{"custom-state":"ok","counter":0}}`)
	q := payload.Notification{APS: payload.APS{Badge: new(0), RelevanceScore: new(0.0), ContentAvailable: true, MutableContent: true}, Custom: map[string]any{"number": 7}}
	equalJSON(t, encoded(t, q, json.StringifyNumbers(true), json.OmitZeroStructFields(true)), `{"aps":{"badge":0,"relevance-score":0,"content-available":1,"mutable-content":1},"number":"7"}`)
	// App options apply to state members, but never stringify the outer event timestamp.
	equalJSON(t, encoded(t, payload.ActivityUpdate[activityState]{Timestamp: time.Unix(0, 0), State: activityState{Counter: 7}}, json.StringifyNumbers(true)), `{"aps":{"timestamp":0,"event":"update","content-state":{"counter":"7","message":""}}}`)
}

func TestStrictRawApplicationContent(t *testing.T) {
	for _, v := range []jsontext.Value{jsontext.Value(`{"a":1,"a":2}`), jsontext.Value("{\"a\":\"\xff\"}"), jsontext.Value(`{} {}`)} {
		p := payload.ActivityUpdate[any]{Timestamp: eventTime, State: v}
		if _, err := json.Marshal(p); err == nil {
			t.Fatalf("invalid raw state accepted: %q", v)
		}
		if _, err := json.Marshal(p, jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true)); err == nil {
			t.Fatalf("permissive options bypassed strict body validation: %q", v)
		}
	}
}

type failingState struct{}

var errState = errors.New("state sentinel")

func (failingState) MarshalJSONTo(*jsontext.Encoder) error { return errState }
func TestEncodingErrorCause(t *testing.T) {
	_, err := json.Marshal(payload.ActivityUpdate[failingState]{Timestamp: eventTime, State: failingState{}})
	if !errors.Is(err, errState) {
		t.Fatalf("cause lost: %v", err)
	}
	if strings.Contains(err.Error(), errState.Error()) {
		t.Fatalf("application cause leaked through normal error formatting: %v", err)
	}
}

func TestConstructorCopiesLocalizationArguments(t *testing.T) {
	args := []string{"original"}
	text := payload.Localized("key", args...)
	args[0] = "changed"
	if !bytes.Contains(encoded(t, text), []byte("original")) {
		t.Fatal("constructor retained mutable args")
	}
}
