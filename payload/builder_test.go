package payload_test

import (
	"encoding/json/v2"
	"reflect"
	"testing"
	"time"

	. "github.com/jaakkonakaza/apns2/payload"
)

func TestEmptyPayload(t *testing.T) {
	payload := NewPayload()
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestAlert(t *testing.T) {
	payload := NewPayload().Alert("hello")
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"alert":"hello"}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestBadge(t *testing.T) {
	payload := NewPayload().Badge(1)
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"badge":1}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestBadgeZero(t *testing.T) {
	payload := NewPayload().Badge(0)
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"badge":0}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestUnsetBadge(t *testing.T) {
	payload := NewPayload().Badge(1).UnsetBadge()
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestSound(t *testing.T) {
	payload := NewPayload().Sound("Default.caf")
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"sound":"Default.caf"}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestContentAvailable(t *testing.T) {
	payload := NewPayload().ContentAvailable()
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"content-available":1}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestMutableContent(t *testing.T) {
	payload := NewPayload().MutableContent()
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"mutable-content":1}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCustom(t *testing.T) {
	payload := NewPayload().Custom("key", "val")
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{},"key":"val"}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCustomKeysAreSorted(t *testing.T) {
	payload := NewPayload().Custom("zeta", 1).Custom("alpha", map[string]any{"b": 2, "a": 1})
	for range 20 {
		b, _ := json.Marshal(payload)
		if got, want := string(b), `{"alpha":{"a":1,"b":2},"aps":{},"zeta":1}`; got != want {
			t.Fatalf("got %#v, want %#v", got, want)
		}
	}
}

func TestCustomMap(t *testing.T) {
	payload := NewPayload().Custom("key", map[string]any{
		"map": 1,
	})
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{},"key":{"map":1}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestAlertTitle(t *testing.T) {
	payload := NewPayload().AlertTitle("hello")
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"alert":{"title":"hello"}}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestAlertTitleLocKey(t *testing.T) {
	payload := NewPayload().AlertTitleLocKey("GAME_PLAY_REQUEST_FORMAT")
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"alert":{"title-loc-key":"GAME_PLAY_REQUEST_FORMAT"}}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestAlertLocArgs(t *testing.T) {
	payload := NewPayload().AlertLocArgs([]string{"Jenna", "Frank"})
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"alert":{"loc-args":["Jenna","Frank"]}}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestAlertTitleLocArgs(t *testing.T) {
	payload := NewPayload().AlertTitleLocArgs([]string{"Jenna", "Frank"})
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"alert":{"title-loc-args":["Jenna","Frank"]}}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestAlertSubtitle(t *testing.T) {
	payload := NewPayload().AlertSubtitle("hello")
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"alert":{"subtitle":"hello"}}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestAlertSubtitleLocKey(t *testing.T) {
	payload := NewPayload().AlertSubtitleLocKey("Notification.Key.TestSubtitle")
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"alert":{"subtitle-loc-key":"Notification.Key.TestSubtitle"}}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestAlertSubtitleLocArgs(t *testing.T) {
	payload := NewPayload().AlertSubtitleLocArgs([]string{"one", "two"})
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"alert":{"subtitle-loc-args":["one","two"]}}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestAlertBody(t *testing.T) {
	payload := NewPayload().AlertBody("body")
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"alert":{"body":"body"}}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestAlertLaunchImage(t *testing.T) {
	payload := NewPayload().AlertLaunchImage("Default.png")
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"alert":{"launch-image":"Default.png"}}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestAlertLocKey(t *testing.T) {
	payload := NewPayload().AlertLocKey("LOC")
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"alert":{"loc-key":"LOC"}}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCategory(t *testing.T) {
	payload := NewPayload().Category("NEW_MESSAGE_CATEGORY")
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"category":"NEW_MESSAGE_CATEGORY"}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestContentState(t *testing.T) {
	payload := NewPayload().ContentState(map[string]any{"my_int": 13, "my_string": "foo"})
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"content-state":{"my_int":13,"my_string":"foo"}}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestLiveActivityEmptyDictionaries(t *testing.T) {
	// Empty Codable state and attribute types still need their required keys.
	payload := NewPayload().ContentState(map[string]any{}).Attributes(map[string]any{})
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"aps":{"content-state":{},"attributes":{}}}`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	payload.ContentState(nil).Attributes(nil)
	b, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"aps":{}}`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestDismissalDate(t *testing.T) {
	timestamp := time.Date(2023, 1, 27, 12, 14, 0o0, 0o0, time.UTC)
	payload := NewPayload().DismissalDate(timestamp)
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"dismissal-date":1674821640}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestStaleDate(t *testing.T) {
	timestamp := time.Date(2023, 1, 27, 12, 14, 0o0, 0o0, time.UTC)
	payload := NewPayload().StaleDate(timestamp)
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"stale-date":1674821640}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestEventEnd(t *testing.T) {
	payload := NewPayload().Event(LiveActivityEventEnd)
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"event":"end"}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestEventUpdate(t *testing.T) {
	payload := NewPayload().Event(LiveActivityEventUpdate)
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"event":"update"}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestTimestamp(t *testing.T) {
	timestamp := time.Date(2023, 1, 27, 12, 14, 0o0, 0o0, time.UTC)
	payload := NewPayload().Timestamp(timestamp)
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"timestamp":1674821640}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestAttributesType(t *testing.T) {
	attributesType := "AdventureAttributes"
	payload := NewPayload().AttributesType(attributesType)
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"attributes-type":"AdventureAttributes"}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestAttributes(t *testing.T) {
	attributes := map[string]any{
		"currentHealthLevel": 100,
		"eventDescription":   "Adventure has begun!",
	}
	payload := NewPayload().Attributes(attributes)
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"attributes":{"currentHealthLevel":100,"eventDescription":"Adventure has begun!"}}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestMDM(t *testing.T) {
	payload := NewPayload().MDM("996ac527-9993-4a0a-8528-60b2b3c2f52b")
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"mdm":"996ac527-9993-4a0a-8528-60b2b3c2f52b"}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestThreadID(t *testing.T) {
	payload := NewPayload().ThreadID("THREAD_ID")
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"thread-id":"THREAD_ID"}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestInterruptionLevelPassive(t *testing.T) {
	payload := NewPayload().InterruptionLevel(InterruptionLevelPassive)
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"interruption-level":"passive"}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestInterruptionLevelActive(t *testing.T) {
	payload := NewPayload().InterruptionLevel(InterruptionLevelActive)
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"interruption-level":"active"}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestInterruptionLevelTimeSensitive(t *testing.T) {
	payload := NewPayload().InterruptionLevel(InterruptionLevelTimeSensitive)
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"interruption-level":"time-sensitive"}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestInterruptionLevelCritical(t *testing.T) {
	payload := NewPayload().InterruptionLevel(InterruptionLevelCritical)
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"interruption-level":"critical"}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestRelevanceScore(t *testing.T) {
	payload := NewPayload().RelevanceScore(0.1)
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"relevance-score":0.1}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestRelevanceScoreZero(t *testing.T) {
	payload := NewPayload().RelevanceScore(0)
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"relevance-score":0}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestUnsetRelevanceScore(t *testing.T) {
	payload := NewPayload().RelevanceScore(0.1).UnsetRelevanceScore()
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{}}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCombined(t *testing.T) {
	payload := NewPayload().Alert("hello").Badge(1).Sound("Default.caf").InterruptionLevel(InterruptionLevelActive).RelevanceScore(0.1).Custom("key", "val")
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"alert":"hello","badge":1,"interruption-level":"active","relevance-score":0.1,"sound":"Default.caf"},"key":"val"}`; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestSoundDeliveryIsExplicit(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload *Payload
		want    string
	}{
		{"regular", NewPayload().Sound("bell.caf"), `{"aps":{"sound":"bell.caf"}}`},
		{"system", NewPayload().Sound("default"), `{"aps":{"sound":"default"}}`},
		{"critical", NewPayload().CriticalSound("bell", 0.8), `{"aps":{"sound":{"critical":1,"name":"bell","volume":0.8}}}`},
		{"silent critical", NewPayload().CriticalSound("bell", 0), `{"aps":{"sound":{"critical":1,"name":"bell","volume":0}}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			b, err := json.Marshal(test.payload)
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != test.want {
				t.Errorf("payload = %s, want %s", b, test.want)
			}
		})
	}
}

func TestLiveActivityDatePresence(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*Payload, time.Time) *Payload
	}{
		{"dismissal-date", (*Payload).DismissalDate},
		{"stale-date", (*Payload).StaleDate},
		{"timestamp", (*Payload).Timestamp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.set(NewPayload(), time.Unix(0, 999999999))
			b, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if want := `{"aps":{"` + tc.name + `":0}}`; string(b) != want {
				t.Fatalf("got %s, want %s", b, want)
			}
			b, err = json.Marshal(tc.set(p, time.Time{}))
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != `{"aps":{}}` {
				t.Fatalf("zero time was not omitted: %s", b)
			}
		})
	}
}

func TestAlertStringBecomesBody(t *testing.T) {
	payload := NewPayload().Alert("hello").AlertTitle("title")
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"alert":{"body":"hello","title":"title"}}}`; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCustomAPSReplacesDictionary(t *testing.T) {
	payload := NewPayload().Custom("aps", map[string]any{"x": 1}).Badge(1)
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"aps":{"x":1}}`; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestZeroValuePayload(t *testing.T) {
	var payload Payload
	payload.Badge(1).Custom("key", "val")
	b, _ := json.Marshal(&payload)
	if got, want := string(b), `{"aps":{"badge":1},"key":"val"}`; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestLiveActivityStart(t *testing.T) {
	for _, useChannel := range []bool{false, true} {
		payload := NewPayload().
			AlertTitle("Game started").
			ContentState(map[string]any{}).
			Event(LiveActivityEventStart).
			Timestamp(time.Unix(1685952000, 0)).
			AttributesType("GameAttributes").
			Attributes(map[string]any{"team": "A"})
		input := `"input-push-token":1`
		if useChannel {
			payload.InputPushChannel("dHN0LXNyY2gtY2hubA==")
			input = `"input-push-channel":"dHN0LXNyY2gtY2hubA=="`
		} else {
			payload.InputPushToken()
		}
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		want := `{"aps":{"alert":{"title":"Game started"},"content-state":{},"event":"start","timestamp":1685952000,"attributes-type":"GameAttributes","attributes":{"team":"A"},` + input + `}}`
		if got := string(b); got != want {
			t.Errorf("got %#v, want %#v", got, want)
		}
	}
}

func TestFocusAndWidgetKeys(t *testing.T) {
	payload := NewPayload().TargetContentID("window-1").FilterCriteria("work").ContentChanged()
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"target-content-id":"window-1","filter-criteria":"work","content-changed":true}}`; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestLiveActivityRelevanceScore(t *testing.T) {
	payload := NewPayload().RelevanceScore(100)
	b, _ := json.Marshal(payload)
	if got, want := string(b), `{"aps":{"relevance-score":100}}`; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestMDMRejectsOtherKeys(t *testing.T) {
	for name, payload := range map[string]*Payload{
		"aps field":  NewPayload().MDM("magic").Badge(1),
		"custom key": NewPayload().MDM("magic").Custom("key", "val"),
	} {
		if _, err := json.Marshal(payload); err == nil {
			t.Errorf("%s: MDM payload with other keys was accepted", name)
		}
	}
}

func TestLiveActivityAlert(t *testing.T) {
	payload := NewPayload().
		AlertTitleLocalized("%@ is knocked down!", "Power Panda").
		AlertBodyLocalized("Use a potion to heal %@!", "Power Panda").
		AlertSound("HeroDown.mp4")
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"aps":{"alert":{"body":{"loc-key":"Use a potion to heal %@!","loc-args":["Power Panda"]},"title":{"loc-key":"%@ is knocked down!","loc-args":["Power Panda"]},"sound":"HeroDown.mp4"}}}`
	if got := string(b); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCustomMDMKeyIsNotMDM(t *testing.T) {
	payload := NewPayload().Alert("hi").Custom("mdm", "metadata")
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"aps":{"alert":"hi"},"mdm":"metadata"}`; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestPayloadByValue(t *testing.T) {
	var payload Payload
	payload.Alert("hi")
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"aps":{"alert":"hi"}}`; got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
}
