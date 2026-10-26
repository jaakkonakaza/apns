package apns

import (
	"time"
	"uuid"
)

// PushType defines the value for the apns-push-type header
type PushType string

const (
	// PushTypeAlert is used for notifications that trigger a user interaction,
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
	// This
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
	PriorityPowerSaving Priority = 1

	// PriorityLow will tell APNs to send the push message at a time that takes
	// into account power considerations for the device. Notifications with this
	// priority might be grouped and delivered in bursts. They are throttled,
	// and in some cases are not delivered.
	PriorityLow Priority = 5

	// PriorityHigh tells APNs to send the push message immediately. Background
	// notifications must use PriorityLow instead. Other push types may impose
	// their own priority requirements.
	PriorityHigh Priority = 10
)

// Priority is the numeric APNs delivery priority. Zero selects a request default.
type Priority int

// Request is the destination, metadata, and application payload for a device push.
// The copy is shallow. Do not mutate its payload during Push. Request deliberately
// has no JSON methods; only Payload is encoded for APNs.
type Request struct {
	DeviceToken string
	Topic       string
	PushType    PushType
	Payload     any
	ID          *uuid.UUID
	CollapseID  string
	Priority    Priority
	ExpiresAt   *time.Time
}
