package apns2

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jaakkonakaza/apns2/token"
)

// Broadcast push and channel management endpoints.
// See https://developer.apple.com/documentation/usernotifications/sending-broadcast-push-notification-requests-to-apns
// and https://developer.apple.com/documentation/usernotifications/sending-channel-management-requests-to-apns
const (
	HostBroadcastDevelopment = "https://api-broadcast.sandbox.push.apple.com"
	HostBroadcastProduction  = "https://api-broadcast.push.apple.com"
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

// BroadcastEndpoints selects the push and channel-management endpoints together.
// The client copies this value during construction.
type BroadcastEndpoints struct {
	Push     string
	Channels string
}

// DevelopmentBroadcastEndpoints returns Apple's dedicated sandbox endpoints.
func DevelopmentBroadcastEndpoints() BroadcastEndpoints {
	return BroadcastEndpoints{Push: HostBroadcastDevelopment, Channels: HostChannelDevelopment}
}

// ProductionBroadcastEndpoints returns Apple's dedicated production endpoints.
func ProductionBroadcastEndpoints() BroadcastEndpoints {
	return BroadcastEndpoints{Push: HostBroadcastProduction, Channels: HostChannelProduction}
}

// BroadcastClient sends Live Activity updates and manages channels in one environment.
type BroadcastClient struct {
	endpoints BroadcastEndpoints
	client    *Client
}

// Endpoints returns the endpoint pair selected during construction.
func (c *BroadcastClient) Endpoints() BroadcastEndpoints { return c.endpoints }

// NewBroadcastClient constructs a certificate-authenticated broadcast client.
// Supply both endpoints explicitly. WithHost is unsupported for broadcast clients.
func NewBroadcastClient(certificate tls.Certificate, endpoints BroadcastEndpoints, options ...ClientOption) (*BroadcastClient, error) {
	config, endpoints, err := broadcastConfig(endpoints, options)
	if err != nil {
		return nil, err
	}
	client, err := newCertificateClient(certificate, config)
	if err != nil {
		return nil, err
	}
	return &BroadcastClient{endpoints: endpoints, client: client}, nil
}

// NewBroadcastTokenClient constructs a token-authenticated broadcast client.
// Supply both endpoints explicitly. WithHost is unsupported for broadcast clients.
func NewBroadcastTokenClient(provider *token.Token, endpoints BroadcastEndpoints, options ...ClientOption) (*BroadcastClient, error) {
	config, endpoints, err := broadcastConfig(endpoints, options)
	if err != nil {
		return nil, err
	}
	client, err := newTokenClient(provider, config)
	if err != nil {
		return nil, err
	}
	return &BroadcastClient{endpoints: endpoints, client: client}, nil
}

func broadcastConfig(endpoints BroadcastEndpoints, options []ClientOption) (clientConfig, BroadcastEndpoints, error) {
	config, err := clientConfigForOptions(options)
	if err != nil {
		return clientConfig{}, BroadcastEndpoints{}, err
	}
	if config.hostSet {
		return clientConfig{}, BroadcastEndpoints{}, errors.New("apns2: use BroadcastEndpoints instead of WithHost for broadcast clients")
	}
	if err := validateHost(endpoints.Push, config.httpClient != nil); err != nil {
		return clientConfig{}, BroadcastEndpoints{}, fmt.Errorf("apns2: broadcast push endpoint: %w", err)
	}
	if err := validateHost(endpoints.Channels, config.httpClient != nil); err != nil {
		return clientConfig{}, BroadcastEndpoints{}, fmt.Errorf("apns2: channel endpoint: %w", err)
	}
	endpoints.Push = strings.TrimRight(endpoints.Push, "/")
	endpoints.Channels = strings.TrimRight(endpoints.Channels, "/")
	config.host = endpoints.Push
	return config, endpoints, nil
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

// BroadcastResponse contains the metadata from a broadcast or channel request.
type BroadcastResponse struct {
	StatusCode int
	Reason     string
	Header     http.Header
	// APNSUniqueID identifies an accepted broadcast push.
	APNSUniqueID string
	// RequestID identifies the request, generated by APNs if it was omitted.
	RequestID string
}

// Success reports whether APNs accepted the request. Channel creation returns
// 201 and deletion returns 204.
func (r *BroadcastResponse) Success() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// Push sends n to every device subscribed to its channel.
func (c *BroadcastClient) Push(ctx context.Context, n *BroadcastNotification) (*BroadcastResponse, error) {
	if n == nil {
		return nil, errors.New("apns2: broadcast notification is nil")
	}
	if n.ChannelID == "" {
		return nil, errors.New("apns2: channel ID is empty")
	}
	priority := n.Priority
	if priority == 0 {
		priority = PriorityHigh
	}
	if priority != PriorityHigh && priority != PriorityLow && priority != PriorityPowerSaving {
		return nil, errors.New("apns2: invalid broadcast priority")
	}
	payload, err := marshalPayload(n.Payload, 5120)
	if err != nil {
		return nil, err
	}

	r, err := c.request(ctx, c.endpoints.Push, http.MethodPost, "/4/broadcasts/apps/", n.BundleID, "", n.RequestID, n.ChannelID, payload, func(req *http.Request) {
		req.Header.Set("apns-push-type", string(PushTypeLiveActivity))
		req.Header.Set("apns-priority", strconv.Itoa(priority))
		expiration := int64(0)
		if !n.Expiration.IsZero() {
			expiration = max(0, n.Expiration.Unix())
		}
		req.Header.Set("apns-expiration", strconv.FormatInt(expiration, 10))
	})
	if r == nil {
		return nil, err
	}
	return &r.BroadcastResponse, err
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
func (c *BroadcastClient) CreateChannel(ctx context.Context, r *ChannelRequest, policy MessageStoragePolicy) (*ChannelResponse, error) {
	if policy != MessageStorageNone && policy != MessageStorageMostRecent {
		return nil, errors.New("apns2: invalid message storage policy")
	}
	body, err := json.Marshal(struct {
		Policy   MessageStoragePolicy `json:"message-storage-policy"`
		PushType string               `json:"push-type"`
	}{policy, "LiveActivity"})
	if err != nil {
		return nil, err
	}
	return c.channelRequest(ctx, http.MethodPost, r, false, false, body)
}

// GetChannel reads the configuration of an existing channel.
func (c *BroadcastClient) GetChannel(ctx context.Context, r *ChannelRequest) (*ChannelResponse, error) {
	return c.channelRequest(ctx, http.MethodGet, r, true, false, nil)
}

// DeleteChannel deletes a channel permanently. APNs may still deliver
// messages it already stored.
func (c *BroadcastClient) DeleteChannel(ctx context.Context, r *ChannelRequest) (*ChannelResponse, error) {
	return c.channelRequest(ctx, http.MethodDelete, r, true, false, nil)
}

// ListChannels lists the active channel IDs for r.BundleID.
func (c *BroadcastClient) ListChannels(ctx context.Context, r *ChannelRequest) (*ChannelResponse, error) {
	return c.channelRequest(ctx, http.MethodGet, r, false, true, nil)
}

func (c *BroadcastClient) channelRequest(ctx context.Context, method string, r *ChannelRequest, needsChannel, list bool, body []byte) (*ChannelResponse, error) {
	if r == nil {
		return nil, errors.New("apns2: channel request is nil")
	}
	channelID := ""
	if needsChannel {
		channelID = r.ChannelID
		if channelID == "" {
			return nil, errors.New("apns2: channel ID is empty")
		}
	}
	suffix := "/channels"
	if list {
		suffix = "/all-channels"
	}
	return c.request(ctx, c.endpoints.Channels, method, "/1/apps/", r.BundleID, suffix, r.RequestID, channelID, body, nil)
}

// Channel lists can contain up to 10,000 IDs, substantially more than a push response.
const maxChannelResponseBytes = 4 << 20

func (c *BroadcastClient) request(ctx context.Context, host, method, prefix, bundleID, suffix, requestID, channelID string, body []byte, headers func(*http.Request)) (*ChannelResponse, error) {
	if host == "" {
		return nil, errors.New("apns2: broadcast or channel host is not set")
	}
	if bundleID == "" {
		return nil, errors.New("apns2: bundle ID is empty")
	}
	if requestID != "" && !canonicalUUID(requestID) {
		return nil, errors.New("apns2: apns-request-id must be a canonical 8-4-4-4-12 UUID")
	}
	req, err := http.NewRequestWithContext(ctx, method, host+prefix+url.PathEscape(bundleID)+suffix, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if requestID != "" {
		req.Header.Set("apns-request-id", requestID)
	}
	if channelID != "" {
		req.Header.Set("apns-channel-id", channelID)
	}
	if headers != nil {
		headers(req)
	}
	var bearer string
	if c.client.token != nil {
		bearer, err = c.client.token.Bearer()
		if err != nil {
			return nil, err
		}
		req.Header.Set("authorization", "bearer "+bearer)
	}
	resp, err := c.client.httpClient.Do(prepareRequest(req))
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	r := &ChannelResponse{ChannelID: resp.Header.Get("apns-channel-id")}
	r.StatusCode = resp.StatusCode
	r.Header = resp.Header.Clone()
	r.APNSUniqueID = resp.Header.Get("apns-unique-id")
	r.RequestID = resp.Header.Get("apns-request-id")
	limit := int64(maxResponseBytes)
	if suffix == "/all-channels" {
		limit = maxChannelResponseBytes
	}
	data, err := readResponseBodyLimit(resp.Body, limit)
	if err != nil {
		return r, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return r, nil
	}
	var result struct {
		Reason   string               `json:"reason"`
		Policy   MessageStoragePolicy `json:"message-storage-policy"`
		PushType string               `json:"push-type"`
		Channels []string             `json:"channels"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return r, err
	}
	r.Reason = result.Reason
	r.MessageStoragePolicy = result.Policy
	r.PushType = result.PushType
	r.ChannelIDs = result.Channels
	if c.client.token != nil && (r.Reason == ReasonExpiredProviderToken || r.Reason == ReasonInvalidProviderToken) {
		c.client.token.Invalidate(bearer)
	}
	return r, nil
}
