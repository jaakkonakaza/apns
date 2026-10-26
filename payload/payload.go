// Package payload provides validated APNs payload values.
package payload

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"math"
	"reflect"
	"slices"
	"time"
)

// InterruptionLevel controls notification presentation.
type InterruptionLevel string

const (
	InterruptionLevelPassive       InterruptionLevel = "passive"
	InterruptionLevelActive        InterruptionLevel = "active"
	InterruptionLevelTimeSensitive InterruptionLevel = "time-sensitive"
	InterruptionLevelCritical      InterruptionLevel = "critical"
)

// Notification combines the Apple envelope with application-owned root members.
type Notification struct {
	APS    APS
	Custom map[string]any
}

// APS contains ordinary notification fields. Optional numbers preserve explicit zero.
type APS struct {
	Alert             *Alert
	Badge             *int
	Sound             *Sound
	Category          string
	ThreadID          string
	ContentAvailable  bool
	MutableContent    bool
	InterruptionLevel InterruptionLevel
	RelevanceScore    *float64
	TargetContentID   string
	FilterCriteria    string
	ContentChanged    bool
	Extensions        map[string]any
}

// Alert represents ordinary notification text and localization keys.
// Literal text and its corresponding localization key are mutually exclusive.
type Alert struct {
	Title           string   `json:"title,omitempty"`
	Subtitle        string   `json:"subtitle,omitempty"`
	Body            string   `json:"body,omitempty"`
	LaunchImage     string   `json:"launch-image,omitempty"`
	LocKey          string   `json:"loc-key,omitempty"`
	LocArgs         []string `json:"loc-args,omitempty"`
	TitleLocKey     string   `json:"title-loc-key,omitempty"`
	TitleLocArgs    []string `json:"title-loc-args,omitempty"`
	SubtitleLocKey  string   `json:"subtitle-loc-key,omitempty"`
	SubtitleLocArgs []string `json:"subtitle-loc-args,omitempty"`
}

// Sound encodes an ordinary sound string or a critical sound dictionary.
// Volume is permitted only for a critical sound and must be between zero and one.
type Sound struct {
	Name     string
	Critical bool
	Volume   *float64
}

// Background always requests background delivery without visible APS fields.
type Background struct{ Custom map[string]any }

// MDM is the root-only management payload.
type MDM struct{ PushMagic string }

// ActivityText is literal or localized text created with Text or Localized.
type ActivityText struct {
	kind  uint8
	value string
	args  []string
}

func Text(text string) ActivityText { return ActivityText{kind: 1, value: text} }
func Localized(key string, args ...string) ActivityText {
	return ActivityText{kind: 2, value: key, args: slices.Clone(args)}
}

// ActivityAlert places sound with its Live Activity alert text.
type ActivityAlert struct {
	Title ActivityText
	Body  ActivityText
	Sound string
}

// StartUpdates selects how a remotely started activity receives future updates.
// Its zero value uses the platform's normal behavior.
type StartUpdates struct {
	kind    uint8
	channel string
}

func NormalUpdates() StartUpdates                { return StartUpdates{} }
func TokenUpdates() StartUpdates                 { return StartUpdates{kind: 1} }
func ChannelUpdates(channel string) StartUpdates { return StartUpdates{kind: 2, channel: channel} }

// ActivityStart starts an activity whose attributes and state match the app types.
type ActivityStart[A, S any] struct {
	Timestamp      time.Time
	AttributesType string
	Attributes     A
	State          S
	Alert          ActivityAlert
	StaleDate      *time.Time
	Updates        StartUpdates
	RelevanceScore *float64
	Custom         map[string]any
	Extensions     map[string]any
}

// ActivityUpdate updates an existing token or channel destination.
type ActivityUpdate[S any] struct {
	Timestamp      time.Time
	State          S
	StaleDate      *time.Time
	Alert          *ActivityAlert
	RelevanceScore *float64
	Custom         map[string]any
	Extensions     map[string]any
}

// ActivityEnd supplies the final state and optional dismissal time.
type ActivityEnd[S any] struct {
	Timestamp      time.Time
	State          S
	DismissalDate  *time.Time
	RelevanceScore *float64
	Custom         map[string]any
	Extensions     map[string]any
}

// ActivityDate encodes an application date using Swift Date's default 2001 epoch.
// It does not change the encoding of other time.Time fields.
type ActivityDate struct{ Time time.Time }

var apsNames = map[string]bool{
	"alert": true, "badge": true, "sound": true, "category": true, "thread-id": true,
	"content-available": true, "mutable-content": true, "interruption-level": true,
	"relevance-score": true, "target-content-id": true, "filter-criteria": true,
	"content-changed": true, "timestamp": true, "event": true, "attributes-type": true,
	"attributes": true, "content-state": true, "stale-date": true, "dismissal-date": true,
	"input-push-token": true, "input-push-channel": true,
}

type object map[string]jsontext.Value

type encodingError struct{ cause error }

func (e *encodingError) Error() string { return "payload: JSON encoding failed" }
func (e *encodingError) Unwrap() error { return e.cause }

func fixed(value any) (jsontext.Value, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, &encodingError{cause: err}
	}
	return data, nil
}

func application(value any, opts json.Options) (jsontext.Value, error) {
	var b bytes.Buffer
	if err := json.MarshalEncode(jsontext.NewEncoder(&b), value, opts,
		jsontext.AllowDuplicateNames(false), jsontext.AllowInvalidUTF8(false)); err != nil {
		return nil, &encodingError{cause: err}
	}
	data := jsontext.Value(bytes.TrimSpace(b.Bytes()))
	if !data.IsValid() {
		return nil, errors.New("payload: invalid application JSON")
	}
	return data, nil
}

func requiredObject(value any, name string, opts json.Options) (jsontext.Value, error) {
	if value == nil {
		return nil, fmt.Errorf("payload: %s must be a nonnil JSON object", name)
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Interface, reflect.Func, reflect.Chan:
		if v.IsNil() {
			return nil, fmt.Errorf("payload: %s must be a nonnil JSON object", name)
		}
	}
	data, err := application(value, opts)
	if err != nil {
		return nil, fmt.Errorf("payload: encoding %s: %w", name, err)
	}
	if len(data) == 0 || data[0] != '{' {
		return nil, fmt.Errorf("payload: %s must be a JSON object", name)
	}
	return data, nil
}

func (o object) set(name string, value any) error {
	data, err := fixed(value)
	if err == nil {
		o[name] = data
	}
	return err
}

func (o object) extensions(values map[string]any, reserved map[string]bool, opts json.Options) error {
	for _, name := range slices.Sorted(maps.Keys(values)) {
		if reserved[name] {
			return errors.New("payload: custom member collides with a reserved protocol name")
		}
		data, err := application(values[name], opts)
		if err != nil {
			return err
		}
		o[name] = data
	}
	return nil
}

func (o object) write(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(o)) {
		if err := enc.WriteToken(jsontext.String(name)); err != nil {
			return err
		}
		if err := enc.WriteValue(o[name]); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

func (o object) bytes() (jsontext.Value, error) {
	var b bytes.Buffer
	if err := o.write(jsontext.NewEncoder(&b)); err != nil {
		return nil, err
	}
	return jsontext.Value(bytes.TrimSpace(b.Bytes())), nil
}

func envelope(enc *jsontext.Encoder, aps object, custom map[string]any) error {
	data, err := aps.bytes()
	if err != nil {
		return err
	}
	root := object{"aps": data}
	if err := root.extensions(custom, map[string]bool{"aps": true}, enc.Options()); err != nil {
		return err
	}
	return root.write(enc)
}

func activityEnvelope(enc *jsontext.Encoder, aps object, custom map[string]any) error {
	for name := range custom {
		if name == "aps" || apsNames[name] {
			return errors.New("payload: custom member collides with a reserved protocol name")
		}
	}
	return envelope(enc, aps, custom)
}

func (a Alert) validate() error {
	for _, pair := range []struct {
		text, key string
		args      []string
	}{
		{a.Title, a.TitleLocKey, a.TitleLocArgs}, {a.Subtitle, a.SubtitleLocKey, a.SubtitleLocArgs}, {a.Body, a.LocKey, a.LocArgs},
	} {
		if pair.text != "" && pair.key != "" {
			return errors.New("payload: literal and localized alert text conflict")
		}
		if len(pair.args) > 0 && pair.key == "" {
			return errors.New("payload: alert localization arguments require a key")
		}
	}
	return nil
}

func (a Alert) MarshalJSONTo(enc *jsontext.Encoder) error {
	if err := a.validate(); err != nil {
		return err
	}
	type wire Alert
	data, err := fixed(wire(a))
	if err != nil {
		return err
	}
	return enc.WriteValue(data)
}

func (s Sound) MarshalJSONTo(enc *jsontext.Encoder) error {
	if s.Name == "" {
		return errors.New("payload: sound name is required")
	}
	if !s.Critical {
		if s.Volume != nil {
			return errors.New("payload: ordinary sound cannot have a volume")
		}
		data, err := fixed(s.Name)
		if err != nil {
			return err
		}
		return enc.WriteValue(data)
	}
	if s.Volume != nil && (math.IsNaN(*s.Volume) || math.IsInf(*s.Volume, 0) || *s.Volume < 0 || *s.Volume > 1) {
		return errors.New("payload: critical sound volume must be between zero and one")
	}
	wire := struct {
		Critical int      `json:"critical"`
		Name     string   `json:"name"`
		Volume   *float64 `json:"volume,omitempty"`
	}{1, s.Name, s.Volume}
	data, err := fixed(wire)
	if err != nil {
		return err
	}
	return enc.WriteValue(data)
}

func (a APS) fields(opts json.Options) (object, error) {
	if a.RelevanceScore != nil && (math.IsNaN(*a.RelevanceScore) || math.IsInf(*a.RelevanceScore, 0) || *a.RelevanceScore < 0 || *a.RelevanceScore > 1) {
		return nil, errors.New("payload: ordinary relevance score must be between zero and one")
	}
	o := object{}
	for _, field := range []struct {
		name    string
		value   any
		present bool
	}{
		{"alert", a.Alert, a.Alert != nil},
		{"badge", a.Badge, a.Badge != nil},
		{"sound", a.Sound, a.Sound != nil},
		{"category", a.Category, a.Category != ""},
		{"thread-id", a.ThreadID, a.ThreadID != ""},
		{"content-available", 1, a.ContentAvailable},
		{"mutable-content", 1, a.MutableContent},
		{"interruption-level", a.InterruptionLevel, a.InterruptionLevel != ""},
		{"relevance-score", a.RelevanceScore, a.RelevanceScore != nil},
		{"target-content-id", a.TargetContentID, a.TargetContentID != ""},
		{"filter-criteria", a.FilterCriteria, a.FilterCriteria != ""},
		{"content-changed", true, a.ContentChanged},
	} {
		if field.present {
			if err := o.set(field.name, field.value); err != nil {
				return nil, err
			}
		}
	}
	if err := o.extensions(a.Extensions, apsNames, opts); err != nil {
		return nil, err
	}
	return o, nil
}

func (a APS) MarshalJSONTo(enc *jsontext.Encoder) error {
	o, err := a.fields(enc.Options())
	if err != nil {
		return err
	}
	return o.write(enc)
}

func (p Notification) MarshalJSONTo(enc *jsontext.Encoder) error {
	aps, err := p.APS.fields(enc.Options())
	if err != nil {
		return err
	}
	return envelope(enc, aps, p.Custom)
}

func (p Background) MarshalJSONTo(enc *jsontext.Encoder) error {
	return envelope(enc, object{"content-available": jsontext.Value("1")}, p.Custom)
}

func (p MDM) MarshalJSONTo(enc *jsontext.Encoder) error {
	if p.PushMagic == "" {
		return errors.New("payload: MDM push magic is required")
	}
	data, err := fixed(p.PushMagic)
	if err != nil {
		return err
	}
	return (object{"mdm": data}).write(enc)
}

func (t ActivityText) MarshalJSONTo(enc *jsontext.Encoder) error {
	var value any
	switch t.kind {
	case 1:
		value = t.value
	case 2:
		if t.value == "" {
			return errors.New("payload: activity localization key is required")
		}
		value = struct {
			Key  string   `json:"loc-key"`
			Args []string `json:"loc-args,omitempty"`
		}{t.value, t.args}
	default:
		return errors.New("payload: activity text must use Text or Localized")
	}
	data, err := fixed(value)
	if err != nil {
		return err
	}
	return enc.WriteValue(data)
}

func (a ActivityAlert) MarshalJSONTo(enc *jsontext.Encoder) error {
	if a.Title.kind == 0 && a.Body.kind == 0 {
		return errors.New("payload: activity alert requires title or body")
	}
	o := object{}
	if a.Title.kind != 0 {
		if err := o.set("title", a.Title); err != nil {
			return err
		}
	}
	if a.Body.kind != 0 {
		if err := o.set("body", a.Body); err != nil {
			return err
		}
	}
	if a.Sound != "" {
		if err := o.set("sound", a.Sound); err != nil {
			return err
		}
	}
	return o.write(enc)
}

func unix(t time.Time) (jsontext.Value, error) {
	if t.IsZero() {
		return nil, errors.New("payload: protocol timestamp must not be zero")
	}
	return fixed(t.Unix())
}

func activityFields[S any](timestamp time.Time, event string, state S, opts json.Options) (object, error) {
	ts, err := unix(timestamp)
	if err != nil {
		return nil, err
	}
	content, err := requiredObject(state, "content-state", opts)
	if err != nil {
		return nil, err
	}
	ev, err := fixed(event)
	if err != nil {
		return nil, err
	}
	return object{"timestamp": ts, "event": ev, "content-state": content}, nil
}

func optionalDate(o object, name string, date *time.Time) error {
	if date == nil {
		return nil
	}
	data, err := unix(*date)
	if err == nil {
		o[name] = data
	}
	return err
}

func activityOptions(o object, relevance *float64, extensions map[string]any, opts json.Options) error {
	if relevance != nil {
		if err := o.set("relevance-score", relevance); err != nil {
			return err
		}
	}
	return o.extensions(extensions, apsNames, opts)
}

func (p ActivityStart[A, S]) MarshalJSONTo(enc *jsontext.Encoder) error {
	o, err := activityFields(p.Timestamp, "start", p.State, enc.Options())
	if err != nil {
		return err
	}
	if p.AttributesType == "" {
		return errors.New("payload: activity attributes type is required")
	}
	attrs, err := requiredObject(p.Attributes, "attributes", enc.Options())
	if err != nil {
		return err
	}
	o["attributes"] = attrs
	if err := o.set("attributes-type", p.AttributesType); err != nil {
		return err
	}
	if err := o.set("alert", p.Alert); err != nil {
		return err
	}
	if err := optionalDate(o, "stale-date", p.StaleDate); err != nil {
		return err
	}
	switch p.Updates.kind {
	case 0:
	case 1:
		o["input-push-token"] = jsontext.Value("1")
	case 2:
		if p.Updates.channel == "" {
			return errors.New("payload: activity update channel is required")
		}
		if err := o.set("input-push-channel", p.Updates.channel); err != nil {
			return err
		}
	default:
		return errors.New("payload: invalid activity update destination")
	}
	if err := activityOptions(o, p.RelevanceScore, p.Extensions, enc.Options()); err != nil {
		return err
	}
	return activityEnvelope(enc, o, p.Custom)
}

func (p ActivityUpdate[S]) MarshalJSONTo(enc *jsontext.Encoder) error {
	o, err := activityFields(p.Timestamp, "update", p.State, enc.Options())
	if err != nil {
		return err
	}
	if err := optionalDate(o, "stale-date", p.StaleDate); err != nil {
		return err
	}
	if p.Alert != nil {
		if err := o.set("alert", p.Alert); err != nil {
			return err
		}
	}
	if err := activityOptions(o, p.RelevanceScore, p.Extensions, enc.Options()); err != nil {
		return err
	}
	return activityEnvelope(enc, o, p.Custom)
}

func (p ActivityEnd[S]) MarshalJSONTo(enc *jsontext.Encoder) error {
	o, err := activityFields(p.Timestamp, "end", p.State, enc.Options())
	if err != nil {
		return err
	}
	if err := optionalDate(o, "dismissal-date", p.DismissalDate); err != nil {
		return err
	}
	if err := activityOptions(o, p.RelevanceScore, p.Extensions, enc.Options()); err != nil {
		return err
	}
	return activityEnvelope(enc, o, p.Custom)
}

func (d ActivityDate) MarshalJSONTo(enc *jsontext.Encoder) error {
	if d.Time.IsZero() {
		return errors.New("payload: activity date must not be zero")
	}
	seconds := float64(d.Time.Unix()-978307200) + float64(d.Time.Nanosecond())/1e9
	data, err := fixed(seconds)
	if err != nil {
		return err
	}
	return enc.WriteValue(data)
}

// MarshalJSON bridges the payload values to encoding/json using their v2 encoders.
func (p Notification) MarshalJSON() ([]byte, error)        { return json.Marshal(p) }
func (p Background) MarshalJSON() ([]byte, error)          { return json.Marshal(p) }
func (p MDM) MarshalJSON() ([]byte, error)                 { return json.Marshal(p) }
func (p APS) MarshalJSON() ([]byte, error)                 { return json.Marshal(p) }
func (p Alert) MarshalJSON() ([]byte, error)               { return json.Marshal(p) }
func (p Sound) MarshalJSON() ([]byte, error)               { return json.Marshal(p) }
func (p ActivityText) MarshalJSON() ([]byte, error)        { return json.Marshal(p) }
func (p ActivityAlert) MarshalJSON() ([]byte, error)       { return json.Marshal(p) }
func (p ActivityStart[A, S]) MarshalJSON() ([]byte, error) { return json.Marshal(p) }
func (p ActivityUpdate[S]) MarshalJSON() ([]byte, error)   { return json.Marshal(p) }
func (p ActivityEnd[S]) MarshalJSON() ([]byte, error)      { return json.Marshal(p) }
func (p ActivityDate) MarshalJSON() ([]byte, error)        { return json.Marshal(p) }
