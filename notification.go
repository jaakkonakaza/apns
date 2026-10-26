package apns

import (
	"encoding/json/v2"
	"time"
)

// PushType defines the value for the apns-push-type header
type PushType string

const (
	// PushTypeAlert is used for notifications that trigger a user interaction —
	// for example, an alert, badge, or sound. If you set this push type, the
	// topic field must use your app’s bundle ID as the topic. If the
	// notification requires immediate action from the user, set notification
	// priority to 10; otherwise use 5. The alert push type is required on
	// watchOS 6 and later. It is recommended on macOS, iOS, tvOS, and iPadOS.
	PushTypeAlert PushType = "alert"

	// PushTypeBackground is used for notifications that deliver content in the
	// background, and don’t trigger any user interactions. If you set this push
	// type, the topic field must use your app’s bundle ID as the topic. Always
	// use priority 5. Using priority 10 is an error. The background push type
	// is required on watchOS 6 and later. It is recommended on macOS, iOS,
	// tvOS, and iPadOS.
	PushTypeBackground PushType = "background"

	// PushTypeLocation is used for notifications that request a user’s
	// location. If you set this push type, the topic field must use your app’s
	// bundle ID with .location-query appended to the end. The location push
	// type is recommended for iOS and iPadOS. It isn’t available on macOS,
	// tvOS, and watchOS. If the location query requires an immediate response
	// from the Location Push Service Extension, set notification apns-priority
	// to 10; otherwise, use 5. The location push type supports only token-based
	// authentication.
	PushTypeLocation PushType = "location"

	// PushTypeVOIP is used for notifications that provide information about an
	// incoming Voice-over-IP (VoIP) call. If you set this push type, the topic
	// field must use your app’s bundle ID with .voip appended to the end. If
	// you’re using certificate-based authentication, you must also register the
	// certificate for VoIP services. The voip push type is not available on
	// watchOS. It is recommended on macOS, iOS, tvOS, and iPadOS.
	PushTypeVOIP PushType = "voip"

	// PushTypeComplication is used for notifications that contain update
	// information for a watchOS app’s complications. If you set this push type,
	// the topic field must use your app’s bundle ID with .complication appended
	// to the end. If you’re using certificate-based authentication, you must
	// also register the certificate for WatchKit services. The complication
	// push type is recommended for watchOS and iOS. It is not available on
	// macOS, tvOS, and iPadOS.
	PushTypeComplication PushType = "complication"

	// PushTypeFileProvider is used to signal changes to a File Provider
	// extension. If you set this push type, the topic field must use your app’s
	// bundle ID with .pushkit.fileprovider appended to the end. The
	// fileprovider push type is not available on watchOS. It is recommended on
	// macOS, iOS, tvOS, and iPadOS.
	PushTypeFileProvider PushType = "fileprovider"

	// PushTypeMDM is used for notifications that tell managed devices to
	// contact the MDM server. If you set this push type, you must use the topic
	// from the UID attribute in the subject of your MDM push certificate. The
	// mdm push type isn't available on watchOS. It is recommended on macOS,
	// iOS, tvOS, and iPadOS.
	PushTypeMDM PushType = "mdm"

	// PushTypeLiveActivity is used for Live Activities that display various
	// real-time information. If you set this push type, the topic field must
	// use your app’s bundle ID with .push-type.liveactivity appended to the end.
	// The live activity push supports only token-based authentication. This
	// push type is recommended for iOS and iPadOS. It is not available on
	// macOS, tvOS, and watchOS.
	PushTypeLiveActivity PushType = "liveactivity"

	// PushTypePushToTalk is used for notifications that provide information about the
	// push to talk. If you set this push type, the apns-topic header field
	// must use your app’s bundle ID with .voip-ptt appended to the end.
	// The pushtotalk push type isn’t available on watchOS, macOS, and tvOS. It’s recommended on iOS and iPadOS.
	PushTypePushToTalk PushType = "pushtotalk"

	// PushTypeAccessory delivers a paired accessory's response to an iOS device
	// over the internet. The topic must use your app's bundle ID with
	// .push-type.accessory appended. It is available on iOS only.
	PushTypeAccessory PushType = "accessory"

	// PushTypeControls reloads and updates a control. The topic must use your
	// app's bundle ID with .push-type.controls appended. Set the payload's
	// content-changed key to true.
	PushTypeControls PushType = "controls"

	// PushTypeWidgets signals changes to widgets and watch complications made
	// with WidgetKit. The topic must use your app's bundle ID with
	// .push-type.widgets appended. Set the payload's content-changed key.
	PushTypeWidgets PushType = "widgets"

	// PushTypeNowPlaying starts, updates, or ends a remote media session shown
	// on the Lock Screen and in Control Center. The topic must use your app's
	// bundle ID with .push-type.nowplaying appended. Available on iOS, iPadOS,
	// and Mac Catalyst 27 and later. See
	// https://developer.apple.com/documentation/nowplaying/publishing-remote-media-sessions.
	PushTypeNowPlaying PushType = "nowplaying"
)

const (
	// PriorityPowerSaving tells APNs to put the device's power considerations
	// ahead of all other delivery factors and not to wake the device.
	PriorityPowerSaving = 1

	// PriorityLow will tell APNs to send the push message at a time that takes
	// into account power considerations for the device. Notifications with this
	// priority might be grouped and delivered in bursts. They are throttled,
	// and in some cases are not delivered.
	PriorityLow = 5

	// PriorityHigh tells APNs to send the push message immediately. Background
	// notifications must use PriorityLow instead. Other push types may impose
	// their own priority requirements.
	PriorityHigh = 10
)

// Notification represents the data and metadata for an APNs remote notification.
type Notification struct {
	// An optional canonical UUID that identifies the notification. The
	// canonical form is 32 lowercase hexadecimal digits, displayed in five
	// groups separated by hyphens in the form 8-4-4-4-12. An example UUID is as
	// follows:
	//
	//  123e4567-e89b-12d3-a456-4266554400a0
	//
	// If you don't set this, a new UUID is created by APNs and returned in the
	// response. Push rejects a value that isn't in this form; uppercase hex
	// digits are accepted.
	APNSID string

	// A string which allows multiple notifications with the same collapse
	// identifier to be displayed to the user as a single notification. The
	// value must not exceed 64 bytes.
	CollapseID string

	// A string containing hexadecimal bytes of the device token for the target
	// device. The token must match the topic and environment, and its length
	// isn't fixed.
	DeviceToken string

	// The topic of the remote notification: your app's bundle ID, with the
	// suffix its push type requires, such as .push-type.liveactivity. Each
	// PushType constant names its topic. Token clients must set it. Certificate
	// clients may omit it, and APNs then uses the app's bundle ID.
	Topic string

	// An optional time at which the notification is no longer valid. APNs makes
	// a best effort to honor this time; delivery may still occur after it.
	// If this value is left as the default (Expiration.IsZero()), the expiration
	// header is omitted and APNs applies its storage policy.
	// Use time.Unix(0, 0) to request immediate expiration without storage.
	// Times before the Unix epoch are also sent as zero. APNs stores a
	// notification for 30 days at most.
	Expiration time.Time

	// The priority of the notification: PriorityHigh (10), PriorityLow (5), or
	// PriorityPowerSaving (1). Zero selects 5 for background notifications and
	// otherwise omits the header so APNs applies its default.
	Priority int

	// The JSON payload, supplied as a JSON string, []byte, or a value to encode.
	// Device notifications are limited to 4096 bytes, or 5120 bytes for VoIP.
	// See https://developer.apple.com/documentation/usernotifications/generating-a-remote-notification.
	Payload any

	// The push type, sent as apns-push-type. It is required and must match the
	// payload; APNs may reject, delay or drop a notification whose push type
	// doesn't match. Set Priority to suit it too.
	PushType PushType
}

// MarshalJSON converts the notification payload to JSON. String and []byte
// payloads are sent as is, after json.Marshal validates them.
func (n *Notification) MarshalJSON() ([]byte, error) {
	switch payload := n.Payload.(type) {
	case string:
		return []byte(payload), nil
	case []byte:
		return payload, nil
	default:
		return json.Marshal(payload, json.Deterministic(true))
	}
}
