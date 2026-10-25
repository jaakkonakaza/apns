// Package payload is a helper package which contains a payload
// builder to make constructing notification payloads easier.
package payload

import (
	"encoding/json/v2"
	"errors"
	"maps"
	"reflect"
	"time"
)

// InterruptionLevel defines the value for the payload aps interruption-level
type InterruptionLevel string

const (
	// InterruptionLevelPassive adds the notification to the notification list
	// without lighting up the screen or playing a sound.
	InterruptionLevelPassive InterruptionLevel = "passive"

	// InterruptionLevelActive presents the notification immediately, lights up
	// the screen, and can play a sound. It is the default.
	InterruptionLevelActive InterruptionLevel = "active"

	// InterruptionLevelTimeSensitive presents the notification immediately,
	// even during a Focus that would otherwise hold it.
	InterruptionLevelTimeSensitive InterruptionLevel = "time-sensitive"

	// InterruptionLevelCritical presents the notification immediately and
	// bypasses the mute switch to play a sound. It requires an approved
	// entitlement from Apple.
	// See: https://developer.apple.com/documentation/usernotifications/unnotificationinterruptionlevel/
	InterruptionLevelCritical InterruptionLevel = "critical"
)

// LiveActivityEvent defines the value for the payload aps event
type LiveActivityEvent string

const (
	// LiveActivityEventStart starts a Live Activity from a push-to-start token.
	// Include attributes-type, attributes, content-state, timestamp, and an
	// alert. The attributes and content state must match the app's
	// ActivityAttributes types. Send updates and end events to the Live
	// Activity's own push token, or to its broadcast channel when it was
	// started with InputPushChannel. Now Playing remote media sessions also
	// use the start, update and end events.
	LiveActivityEventStart LiveActivityEvent = "start"

	// LiveActivityEventUpdate updates a Live Activity or Now Playing session.
	LiveActivityEventUpdate LiveActivityEvent = "update"

	// LiveActivityEventEnd ends a Live Activity or Now Playing session. For a
	// Live Activity, include the final content state.
	LiveActivityEventEnd LiveActivityEvent = "end"
)

// Payload represents a notification which holds the content that will be
// marshalled as JSON. The zero value is an empty payload ready to use.
type Payload struct {
	dictionary aps
	content    map[string]any
	mdm        *string
}

type aps struct {
	Alert             any               `json:"alert,omitempty"`
	Badge             *int              `json:"badge,omitempty"`
	Category          string            `json:"category,omitempty"`
	ContentAvailable  int               `json:"content-available,omitzero"`
	InterruptionLevel InterruptionLevel `json:"interruption-level,omitempty"`
	MutableContent    int               `json:"mutable-content,omitzero"`
	RelevanceScore    *float64          `json:"relevance-score,omitempty"`
	Sound             any               `json:"sound,omitempty"`
	ThreadID          string            `json:"thread-id,omitempty"`
	ContentState      map[string]any    `json:"content-state,omitzero"`
	DismissalDate     *int64            `json:"dismissal-date,omitempty"`
	StaleDate         *int64            `json:"stale-date,omitempty"`
	Event             LiveActivityEvent `json:"event,omitempty"`
	Timestamp         *int64            `json:"timestamp,omitempty"`
	AttributesType    string            `json:"attributes-type,omitempty"`
	Attributes        map[string]any    `json:"attributes,omitzero"`
	TargetContentID   string            `json:"target-content-id,omitempty"`
	FilterCriteria    string            `json:"filter-criteria,omitempty"`
	ContentChanged    bool              `json:"content-changed,omitzero"`
	InputPushToken    int               `json:"input-push-token,omitzero"`
	InputPushChannel  string            `json:"input-push-channel,omitempty"`
}

type alert struct {
	Body            any      `json:"body,omitempty"`
	LaunchImage     string   `json:"launch-image,omitempty"`
	LocArgs         []string `json:"loc-args,omitempty"`
	LocKey          string   `json:"loc-key,omitempty"`
	Title           any      `json:"title,omitempty"`
	Subtitle        string   `json:"subtitle,omitempty"`
	TitleLocArgs    []string `json:"title-loc-args,omitempty"`
	TitleLocKey     string   `json:"title-loc-key,omitempty"`
	SubtitleLocArgs []string `json:"subtitle-loc-args,omitempty"`
	SubtitleLocKey  string   `json:"subtitle-loc-key,omitempty"`
	Sound           string   `json:"sound,omitempty"`
}

// localizedString is the dictionary form of a Live Activity alert title or body.
type localizedString struct {
	LocKey  string   `json:"loc-key"`
	LocArgs []string `json:"loc-args,omitempty"`
}

type sound struct {
	Critical int      `json:"critical,omitzero"`
	Name     string   `json:"name,omitempty"`
	Volume   *float32 `json:"volume,omitempty"`
}

// NewPayload returns a new Payload struct
func NewPayload() *Payload {
	return &Payload{}
}

// Alert sets the aps alert on the payload.
// This will display a notification alert message to the user. A string alert
// becomes the alert body if an Alert* method later adds other alert fields.
// Any other value, such as a dictionary, and the Alert* methods replace each
// other.
//
//	{"aps":{"alert":alert}}
func (p *Payload) Alert(alert any) *Payload {
	p.aps().Alert = alert
	return p
}

// ContentState sets the aps content-state on the payload.
// Its fields must match the Live Activity's ContentState type. An empty map
// encodes an empty dictionary; nil removes the field. Include the final
// content state when ending a Live Activity. ActivityKit decodes it with its
// default JSON strategies, so encode dates the way Swift's default Date
// decoding expects, as seconds since 2001-01-01, not as Go time.Time strings.
//
//	{"aps":{"content-state": {} }}
func (p *Payload) ContentState(contentState map[string]any) *Payload {
	p.aps().ContentState = contentState
	return p
}

// DismissalDate sets the aps dismissal-date on an end event. A date in the
// past removes the Live Activity from the Lock Screen immediately; otherwise
// use a date within four hours. Without it, the ended activity stays for up to
// four hours.
//
//	{"aps":{"dismissal-date": DismissalDate }}
//
// A zero time removes the field. Values are encoded as Unix seconds.
func (p *Payload) DismissalDate(dismissalDate time.Time) *Payload {
	p.aps().DismissalDate = unixSeconds(dismissalDate)
	return p
}

// StaleDate sets the aps stale-date on the payload.
// This marks the Live Activity as outdated at the given time.
//
//	{"aps":{"stale-date": StaleDate }}
//
// A zero time removes the field. Values are encoded as Unix seconds.
func (p *Payload) StaleDate(staleDate time.Time) *Payload {
	p.aps().StaleDate = unixSeconds(staleDate)
	return p
}

// Event sets the aps event type on the payload.
// Use LiveActivityEventStart, LiveActivityEventUpdate, or LiveActivityEventEnd.
// The same event values are used for Now Playing remote media sessions.
//
//	{"aps":{"event": Event }}
func (p *Payload) Event(event LiveActivityEvent) *Payload {
	p.aps().Event = event
	return p
}

// Timestamp sets the aps timestamp on the payload.
// It identifies when the Live Activity update was generated.
//
//	{"aps":{"timestamp": Timestamp }}
//
// A zero time removes the field. Values are encoded as Unix seconds.
func (p *Payload) Timestamp(timestamp time.Time) *Payload {
	p.aps().Timestamp = unixSeconds(timestamp)
	return p
}

// AttributesType sets the aps attributes-type field on the payload.
// It names the ActivityAttributes type of a push-to-start Live Activity.
//
//	{"aps":{"attributes-type": attributesType }}
func (p *Payload) AttributesType(attributesType string) *Payload {
	p.aps().AttributesType = attributesType
	return p
}

// Attributes sets the aps attributes field on the payload.
// This is used for push-to-start Live Activities and Now Playing remote media
// sessions. An empty map encodes an empty dictionary; nil removes the field.
//
//	{"aps":{"attributes": attributes }}
func (p *Payload) Attributes(attributes map[string]any) *Payload {
	p.aps().Attributes = attributes
	return p
}

// Badge sets the aps badge on the payload.
// This will display a numeric badge on the app icon.
//
//	{"aps":{"badge":b}}
func (p *Payload) Badge(b int) *Payload {
	p.aps().Badge = &b
	return p
}

// UnsetBadge removes the badge attribute from the payload.
// This will leave the badge on the app icon unchanged.
// If you wish to clear the app icon badge, use Badge(0).
//
//	{"aps":{}}
func (p *Payload) UnsetBadge() *Payload {
	p.aps().Badge = nil
	return p
}

// Sound sets the aps sound for a regular notification: the name of a sound
// file in the app's main bundle or its Library/Sounds folder, or "default" for
// the system sound. Use CriticalSound for critical alerts.
//
//	{"aps":{"sound":name}}
func (p *Payload) Sound(name string) *Payload {
	p.aps().Sound = name
	return p
}

// ContentAvailable sets the aps content-available on the payload to 1.
// This requests background runtime to download new content; delivery is not
// guaranteed. For a silent background notification, omit alert, badge, and
// sound, and use the background push type with priority 5.
//
//	{"aps":{"content-available":1}}
func (p *Payload) ContentAvailable() *Payload {
	p.aps().ContentAvailable = 1
	return p
}

// MutableContent sets the aps mutable-content on the payload to 1.
// This requests a notification service extension to modify the content.
// Also include an alert dictionary with title, subtitle, or body information.
//
//	{"aps":{"mutable-content":1}}
func (p *Payload) MutableContent() *Payload {
	p.aps().MutableContent = 1
	return p
}

// Custom payload

// Custom sets a custom key and value on the payload.
// This will add custom key/value data to the notification payload at root level.
// Setting the key "aps" replaces the aps dictionary the other methods build.
//
//	{"aps":{}, key:value}
func (p *Payload) Custom(key string, val any) *Payload {
	if p.content == nil {
		p.content = map[string]any{}
	}
	p.content[key] = val
	return p
}

// Alert dictionary

// AlertTitle sets the aps alert title on the payload.
// Apple Watch displays it in the short look notification interface.
//
//	{"aps":{"alert":{"title":title}}}
func (p *Payload) AlertTitle(title string) *Payload {
	p.aps().alert().Title = title
	return p
}

// AlertTitleLocKey sets the aps alert title localization key on the payload.
// This is the key to a title string in the Localizable.strings file for the
// current localization. See
// https://developer.apple.com/documentation/usernotifications/generating-a-remote-notification
//
//	{"aps":{"alert":{"title-loc-key":key}}}
func (p *Payload) AlertTitleLocKey(key string) *Payload {
	p.aps().alert().TitleLocKey = key
	return p
}

// AlertTitleLocArgs sets the aps alert title localization args on the payload.
// These are the variable string values to appear in place of the format
// specifiers in title-loc-key. See
// https://developer.apple.com/documentation/usernotifications/generating-a-remote-notification
//
//	{"aps":{"alert":{"title-loc-args":args}}}
func (p *Payload) AlertTitleLocArgs(args []string) *Payload {
	p.aps().alert().TitleLocArgs = args
	return p
}

// AlertSubtitle sets the aps alert subtitle on the payload.
// It adds information that explains the purpose of the notification.
//
//	{"aps":{"alert":{"subtitle":"subtitle"}}}
func (p *Payload) AlertSubtitle(subtitle string) *Payload {
	p.aps().alert().Subtitle = subtitle
	return p
}

// AlertSubtitleLocKey sets the aps alert subtitle localization key on the payload.
// This is the key to a subtitle string in the Localizable.strings file for the
// current localization. See
// https://developer.apple.com/documentation/usernotifications/generating-a-remote-notification
//
//	{"aps":{"alert":{"subtitle-loc-key":key}}}
func (p *Payload) AlertSubtitleLocKey(key string) *Payload {
	p.aps().alert().SubtitleLocKey = key
	return p
}

// AlertSubtitleLocArgs sets the aps alert subtitle localization args on the payload.
// These are the variable string values to appear in place of the format
// specifiers in subtitle-loc-key. See
// https://developer.apple.com/documentation/usernotifications/generating-a-remote-notification
//
//	{"aps":{"alert":{"subtitle-loc-args":args}}}
func (p *Payload) AlertSubtitleLocArgs(args []string) *Payload {
	p.aps().alert().SubtitleLocArgs = args
	return p
}

// AlertTitleLocalized sets the alert title to a localized string dictionary,
// the form Live Activity alerts use.
//
//	{"aps":{"alert":{"title":{"loc-key":key,"loc-args":args}}}}
func (p *Payload) AlertTitleLocalized(key string, args ...string) *Payload {
	p.aps().alert().Title = localizedString{LocKey: key, LocArgs: args}
	return p
}

// AlertBodyLocalized sets the alert body to a localized string dictionary,
// the form Live Activity alerts use.
//
//	{"aps":{"alert":{"body":{"loc-key":key,"loc-args":args}}}}
func (p *Payload) AlertBodyLocalized(key string, args ...string) *Payload {
	p.aps().alert().Body = localizedString{LocKey: key, LocArgs: args}
	return p
}

// AlertSound sets the sound inside the alert dictionary, as Live Activity
// alerts use. Regular notifications use Sound.
//
//	{"aps":{"alert":{"sound":name}}}
func (p *Payload) AlertSound(name string) *Payload {
	p.aps().alert().Sound = name
	return p
}

// AlertBody sets the aps alert body on the payload.
// This is the text of the alert message.
//
//	{"aps":{"alert":{"body":body}}}
func (p *Payload) AlertBody(body string) *Payload {
	p.aps().alert().Body = body
	return p
}

// AlertLaunchImage sets the aps alert launch-image on the payload.
// If the user launches the app from the notification, this image or
// storyboard file is shown instead of the app's normal launch image.
//
//	{"aps":{"alert":{"launch-image":image}}}
func (p *Payload) AlertLaunchImage(image string) *Payload {
	p.aps().alert().LaunchImage = image
	return p
}

// AlertLocArgs sets the aps alert localization args on the payload.
// These are the variable string values to appear in place of the format
// specifiers in loc-key. See
// https://developer.apple.com/documentation/usernotifications/generating-a-remote-notification
//
//	{"aps":{"alert":{"loc-args":args}}}
func (p *Payload) AlertLocArgs(args []string) *Payload {
	p.aps().alert().LocArgs = args
	return p
}

// AlertLocKey sets the aps alert localization key on the payload.
// This is the key to an alert-message string in the Localizable.strings file
// for the current localization. See
// https://developer.apple.com/documentation/usernotifications/generating-a-remote-notification
//
//	{"aps":{"alert":{"loc-key":key}}}
func (p *Payload) AlertLocKey(key string) *Payload {
	p.aps().alert().LocKey = key
	return p
}

// General

// Category sets the aps category on the payload.
// It must match the identifier of a UNNotificationCategory the app registers at
// launch. See https://developer.apple.com/documentation/usernotifications/declaring-your-actionable-notification-types
//
//	{"aps":{"category":category}}
func (p *Payload) Category(category string) *Payload {
	p.aps().Category = category
	return p
}

// Mdm sets the mdm on the payload.
// This is for Apple Mobile Device Management (mdm) payloads. Pass the PushMagic
// string. An MDM payload is exactly {"mdm":...}: marshaling fails if other
// keys or aps fields are set.
//
//	{"mdm":mdm}
func (p *Payload) Mdm(mdm string) *Payload {
	p.mdm = &mdm
	return p
}

// TargetContentID sets the aps target-content-id on the payload.
// It identifies the window brought forward when the notification is opened.
//
//	{"aps":{"target-content-id":id}}
func (p *Payload) TargetContentID(id string) *Payload {
	p.aps().TargetContentID = id
	return p
}

// FilterCriteria sets the aps filter-criteria on the payload.
// The system evaluates it against the current Focus filter to decide whether
// to display the notification.
//
//	{"aps":{"filter-criteria":criteria}}
func (p *Payload) FilterCriteria(criteria string) *Payload {
	p.aps().FilterCriteria = criteria
	return p
}

// ContentChanged sets the aps content-changed on the payload to true.
// Widget and control pushes use it to tell WidgetKit to reload their content.
//
//	{"aps":{"content-changed":true}}
func (p *Payload) ContentChanged() *Payload {
	p.aps().ContentChanged = true
	return p
}

// InputPushToken sets the aps input-push-token on the payload to 1.
// On a LiveActivityEventStart payload, it asks the started Live Activity for a
// new push token. Requires iOS or iPadOS 18 or later.
//
//	{"aps":{"input-push-token":1}}
func (p *Payload) InputPushToken() *Payload {
	p.aps().InputPushToken = 1
	return p
}

// InputPushChannel sets the aps input-push-channel on the payload.
// On a LiveActivityEventStart payload, the started Live Activity subscribes to
// the existing broadcast channel. Requires iOS or iPadOS 18 or later.
//
//	{"aps":{"input-push-channel":channelID}}
func (p *Payload) InputPushChannel(channelID string) *Payload {
	p.aps().InputPushChannel = channelID
	return p
}

// ThreadID sets the aps thread id on the payload.
// This app-specific identifier groups related notifications.
//
//	{"aps":{"thread-id":id}}
func (p *Payload) ThreadID(threadID string) *Payload {
	p.aps().ThreadID = threadID
	return p
}

// CriticalSound sets a critical alert sound with a volume from 0 to 1.
// Critical alerts require Apple's entitlement.
func (p *Payload) CriticalSound(name string, volume float32) *Payload {
	p.aps().Sound = &sound{Critical: 1, Name: name, Volume: &volume}
	return p
}

// InterruptionLevel defines the value for the payload aps interruption-level
// This is to indicate the importance and delivery timing of a notification.
// (Using InterruptionLevelCritical requires an approved entitlement from Apple.)
// See: https://developer.apple.com/documentation/usernotifications/unnotificationinterruptionlevel/
//
// {"aps":{"interruption-level":passive}}
func (p *Payload) InterruptionLevel(interruptionLevel InterruptionLevel) *Payload {
	p.aps().InterruptionLevel = interruptionLevel
	return p
}

// RelevanceScore sets the score the system uses to sort the notifications
// from your app. The highest score gets featured in the notification summary.
// Use a number between 0 and 1. Live Activity updates accept any relative
// value, for example 25, 50, 75 or 100; the highest score also decides which
// Live Activity appears in the Dynamic Island.
//
//	{"aps":{"relevance-score":0.1}}
func (p *Payload) RelevanceScore(b float64) *Payload {
	p.aps().RelevanceScore = &b
	return p
}

// UnsetRelevanceScore removes the relevance score from the payload.
// See https://developer.apple.com/documentation/usernotifications/unnotificationcontent/relevancescore
//
//	{"aps":{}}
func (p *Payload) UnsetRelevanceScore() *Payload {
	p.aps().RelevanceScore = nil
	return p
}

// MarshalJSON returns the JSON encoded version of the Payload. It has a value
// receiver, so a Payload passed by value encodes the same as a pointer.
func (p Payload) MarshalJSON() ([]byte, error) {
	if p.mdm != nil {
		if len(p.content) > 0 || !reflect.ValueOf(p.dictionary).IsZero() {
			return nil, errors.New("payload: an MDM payload can't contain other keys")
		}
		return json.Marshal(map[string]string{"mdm": *p.mdm})
	}
	content := make(map[string]any, len(p.content)+1)
	maps.Copy(content, p.content)
	if _, custom := content["aps"]; !custom {
		content["aps"] = &p.dictionary
	}
	return json.Marshal(content, json.Deterministic(true))
}

func (p *Payload) aps() *aps {
	return &p.dictionary
}

func (a *aps) alert() *alert {
	switch current := a.Alert.(type) {
	case *alert:
		return current
	case string:
		a.Alert = &alert{Body: current}
	default:
		a.Alert = &alert{}
	}
	return a.Alert.(*alert)
}

func unixSeconds(t time.Time) *int64 {
	if t.IsZero() {
		return nil
	}
	seconds := t.Unix()
	return &seconds
}
