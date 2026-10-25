package apns2

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	"github.com/jaakkonakaza/apns2/token"
)

// ErrNotImplemented is returned by APIs that are declared but not implemented yet.
var ErrNotImplemented = errors.New("apns2: not implemented")

// Broadcast push and channel management endpoints. Broadcast pushes use the
// regular APNs hosts, as Apple's connection section lists; the api-broadcast
// names in its request examples resolve to the same servers.
// See https://developer.apple.com/documentation/usernotifications/sending-broadcast-push-notification-requests-to-apns
// and https://developer.apple.com/documentation/usernotifications/sending-channel-management-requests-to-apns
const (
	HostBroadcastDevelopment = HostDevelopment
	HostBroadcastProduction  = HostProduction
	HostChannelDevelopment   = "https://api-manage-broadcast.sandbox.push.apple.com:2195"
	HostChannelProduction    = "https://api-manage-broadcast.push.apple.com:2196"
)

// Additional error reasons for broadcast pushes and channel management.
// See https://developer.apple.com/documentation/usernotifications/handling-error-responses-from-apns.
const (
	// 400 Broadcast capabilities aren't enabled for the topic.
	ReasonFeatureNotEnabled = "FeatureNotEnabled"

	// 400 The apns-channel-id header is missing.
	ReasonMissingChannelID = "MissingChannelId"

	// 400 The channel ID is improperly encoded or exceeds the allowed length.
	ReasonBadChannelID = "BadChannelId"

	// 400 The apns-channel-id header used in the request doesn't exist.
	ReasonChannelNotRegistered = "ChannelNotRegistered"

	// 400 The JSON request contains an unrecognized attribute.
	ReasonBadRequestParams = "BadRequestParams"

	// 400 The JSON request can't be parsed.
	ReasonBadRequestPayload = "BadRequestPayload"

	// 400 The push type is missing: the apns-push-type header of a broadcast
	// push, or the push-type field of a channel request.
	ReasonMissingPushType = "MissingPushType"

	// 400 The app has reached its maximum number of channels. Delete channels
	// that you no longer use.
	ReasonCannotCreateChannelConfig = "CannotCreateChannelConfig"

	// 403 The bundle ID in the path isn't covered by the token or certificate.
	ReasonTopicMismatch = "TopicMismatch"
)

// BroadcastClient sends broadcast push notifications to Live Activity
// channels and manages those channels. Devices on iOS and iPadOS 18 and later
// subscribe to channels. Channels can't be shared across environments.
//
// Not implemented yet: every request method returns ErrNotImplemented.
type BroadcastClient struct {
	// Host is the broadcast push endpoint, HostBroadcastProduction or
	// HostBroadcastDevelopment. There is no default.
	Host string

	// ChannelHost is the channel management endpoint, HostChannelProduction or
	// HostChannelDevelopment. There is no default.
	ChannelHost string

	client *Client
}

// NewBroadcastClient returns a certificate-authenticated broadcast client.
// Host options are ignored; set Host and ChannelHost for the environment.
func NewBroadcastClient(certificate tls.Certificate, options ...ClientOption) *BroadcastClient {
	return newBroadcastClient(NewClient(certificate, options...))
}

// NewBroadcastTokenClient returns a token-authenticated broadcast client.
// Host options are ignored; set Host and ChannelHost for the environment.
func NewBroadcastTokenClient(token *token.Token, options ...ClientOption) *BroadcastClient {
	return newBroadcastClient(NewTokenClient(token, options...))
}

func newBroadcastClient(client *Client) *BroadcastClient {
	return &BroadcastClient{client: client}
}

// CloseIdleConnections closes idle broadcast and channel management connections.
func (c *BroadcastClient) CloseIdleConnections() {
	c.client.CloseIdleConnections()
}

// BroadcastNotification is a Live Activity update sent to every device
// subscribed to a channel. Push always sends apns-push-type liveactivity.
type BroadcastNotification struct {
	// BundleID is the app's bundle ID, without a push type suffix.
	BundleID string

	// ChannelID is the base64 channel ID returned by CreateChannel.
	ChannelID string

	// RequestID is an optional canonical UUID that APNs returns in its response.
	RequestID string

	// Expiration is when APNs stops trying to deliver. Zero sends 0, so APNs
	// attempts delivery once without storing it. A nonzero expiration requires
	// a channel created with MessageStorageMostRecent.
	Expiration time.Time

	// Priority is PriorityHigh (10), PriorityLow (5), or PriorityPowerSaving (1).
	// Apple requires the header, so zero sends 10. ActivityKit's channel guide
	// mentions only 5 and 10.
	Priority int

	// Payload is the uncompressed Live Activity payload, limited to 5120 bytes. Build it
	// with the payload package or supply JSON as a string or []byte.
	Payload any
}

// BroadcastResponse is the result of a broadcast push or channel request.
type BroadcastResponse struct {
	// Response includes the status and reason. Push also sets ApnsUniqueID,
	// a successful push's identifier in both environments. ApnsID and
	// Timestamp are unused: broadcast requests are identified by RequestID.
	Response

	// RequestID is the request's apns-request-id, generated by APNs if the
	// request did not set one.
	RequestID string
}

// Success reports whether APNs accepted the request. Unlike Sent, it accepts
// every 2xx status: channel creation returns 201 and deletion 204.
func (r *BroadcastResponse) Success() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// Push sends n to every device subscribed to its channel.
//
// Not implemented yet: it returns ErrNotImplemented.
func (c *BroadcastClient) Push(ctx context.Context, n *BroadcastNotification) (*BroadcastResponse, error) {
	return nil, ErrNotImplemented
}

// MessageStoragePolicy decides whether a channel stores the most recent
// message for offline devices. It is fixed when the channel is created.
type MessageStoragePolicy int

const (
	// MessageStorageNone is Apple's No Message Stored policy. It allows a
	// higher publishing budget.
	// Use it for frequent updates, such as sports scores.
	MessageStorageNone MessageStoragePolicy = 0

	// MessageStorageMostRecent stores the most recent message for up to 8 hours.
	// Use it for infrequent updates, such as flight status.
	MessageStorageMostRecent MessageStoragePolicy = 1
)

// ChannelRequest identifies the app, and the channel where an operation needs
// one, for a channel management request.
type ChannelRequest struct {
	// BundleID is the app's bundle ID, without a push type suffix.
	BundleID string

	// ChannelID is the base64 channel ID returned by CreateChannel. GetChannel
	// and DeleteChannel require it; CreateChannel and ListChannels don't use it.
	ChannelID string

	// RequestID is an optional lowercase canonical UUID sent as
	// apns-request-id. APNs returns it, or one it generates, in the response.
	RequestID string
}

// ChannelResponse is the result of a channel management request.
type ChannelResponse struct {
	BroadcastResponse

	// ChannelID is set by CreateChannel.
	ChannelID string

	// MessageStoragePolicy is set by GetChannel.
	MessageStoragePolicy MessageStoragePolicy

	// PushType is the channel's push type, set by GetChannel. Channel bodies
	// use LiveActivity, which differs in case from the apns-push-type header
	// value liveactivity.
	PushType string

	// ChannelIDs is set by ListChannels.
	ChannelIDs []string
}

// CreateChannel creates a Live Activity channel for r.BundleID. APNs chooses
// the channel ID. An app can keep up to 10,000 channels in each environment.
//
// Not implemented yet: it returns ErrNotImplemented.
func (c *BroadcastClient) CreateChannel(ctx context.Context, r *ChannelRequest, policy MessageStoragePolicy) (*ChannelResponse, error) {
	return nil, ErrNotImplemented
}

// GetChannel reads the configuration of an existing channel.
//
// Not implemented yet: it returns ErrNotImplemented.
func (c *BroadcastClient) GetChannel(ctx context.Context, r *ChannelRequest) (*ChannelResponse, error) {
	return nil, ErrNotImplemented
}

// DeleteChannel deletes a channel permanently. APNs may still deliver
// messages it already stored.
//
// Not implemented yet: it returns ErrNotImplemented.
func (c *BroadcastClient) DeleteChannel(ctx context.Context, r *ChannelRequest) (*ChannelResponse, error) {
	return nil, ErrNotImplemented
}

// ListChannels lists the active channel IDs for r.BundleID.
//
// Not implemented yet: it returns ErrNotImplemented.
func (c *BroadcastClient) ListChannels(ctx context.Context, r *ChannelRequest) (*ChannelResponse, error) {
	return nil, ErrNotImplemented
}
