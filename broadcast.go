package apns

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/url"
	"time"
	"uuid"
)

// Broadcast push and channel management endpoints are selected by Environment.
const (
	HostBroadcastDevelopment = "https://api-broadcast.sandbox.push.apple.com"
	HostBroadcastProduction  = "https://api-broadcast.push.apple.com"
	HostChannelDevelopment   = "https://api-manage-broadcast.sandbox.push.apple.com:2195"
	HostChannelProduction    = "https://api-manage-broadcast.push.apple.com:2196"
)

// Additional APNs rejection reasons for broadcast and channel operations.
const (
	ReasonFeatureNotEnabled         Reason = "FeatureNotEnabled"
	ReasonMissingChannelID          Reason = "MissingChannelId"
	ReasonBadChannelID              Reason = "BadChannelId"
	ReasonChannelNotRegistered      Reason = "ChannelNotRegistered"
	ReasonBadRequestParams          Reason = "BadRequestParams"
	ReasonBadRequestPayload         Reason = "BadRequestPayload"
	ReasonMissingPushType           Reason = "MissingPushType"
	ReasonCannotCreateChannelConfig Reason = "CannotCreateChannelConfig"
	ReasonTopicMismatch             Reason = "TopicMismatch"
)

// BroadcastRequest sends a Live Activity payload to one channel. BundleID has
// no push-type suffix. ID, when nonnil, becomes apns-request-id.
type BroadcastRequest struct {
	BundleID  string
	ChannelID string
	ID        *uuid.UUID
	Priority  Priority
	ExpiresAt *time.Time
	Payload   any

	// MessageStoragePolicy is an optional assertion about the channel's policy.
	// When supplied, it permits preflight expiration validation. When nil, APNs
	// validates compatibility with the existing channel. No channel lookup is made.
	MessageStoragePolicy *MessageStoragePolicy
}

// Broadcast sends to the channel's subscribers. A nil error means APNs accepted
// the request, not that any subscriber received or displayed it.
func (c *Client) Broadcast(ctx context.Context, r BroadcastRequest) (Response, error) {
	if c == nil || c.httpClient == nil {
		return Response{}, safeError("validation", errors.New("client is uninitialized"))
	}
	headers, err := broadcastHeaders(r.BundleID, r.ChannelID, r.ID, true)
	if err != nil {
		return Response{}, safeError("validation", err)
	}
	if err := setPriority(headers, r.Priority, PushTypeLiveActivity, true); err != nil {
		return Response{}, safeError("validation", err)
	}
	if err := setExpiration(headers, r.ExpiresAt, true); err != nil {
		return Response{}, safeError("validation", err)
	}
	if policy := r.MessageStoragePolicy; policy != nil {
		if !validStoragePolicy(*policy) {
			return Response{}, safeError("validation", errors.New("invalid message storage policy"))
		}
		if *policy == MessageStorageNone && r.ExpiresAt != nil && r.ExpiresAt.Unix() != 0 {
			return Response{}, safeError("validation", errors.New("a no-storage channel requires zero expiration"))
		}
	}
	body, err := marshalPayload(r.Payload, 5120)
	if err != nil {
		return Response{}, err
	}
	headers.Set("apns-push-type", string(PushTypeLiveActivity))
	return c.execute(ctx, http.MethodPost, c.broadcastHost()+"/4/broadcasts/apps/"+url.PathEscape(r.BundleID), headers, body, http.StatusOK, maxResponseBytes, nil)
}

// MessageStoragePolicy is fixed when a channel is created.
type MessageStoragePolicy int

const (
	// MessageStorageNone does not retain messages for offline subscribers.
	MessageStorageNone MessageStoragePolicy = 0
	// MessageStorageMostRecent retains the latest message for up to eight hours.
	MessageStorageMostRecent MessageStoragePolicy = 1
)

// CreateChannelRequest creates a Live Activity channel with a fixed storage policy.
type CreateChannelRequest struct {
	BundleID             string
	ID                   *uuid.UUID
	MessageStoragePolicy MessageStoragePolicy
}

// CreateChannelResponse contains the channel ID returned in apns-channel-id.
type CreateChannelResponse struct {
	Response
	ChannelID string
}

// GetChannelRequest identifies a channel for inspection.
type GetChannelRequest struct {
	BundleID  string
	ChannelID string
	ID        *uuid.UUID
}

// GetChannelResponse describes one channel's configuration.
type GetChannelResponse struct {
	Response
	MessageStoragePolicy MessageStoragePolicy
	PushType             string
}

// ListChannelsRequest identifies an app's channel collection.
type ListChannelsRequest struct {
	BundleID string
	ID       *uuid.UUID
}

// ListChannelsResponse contains all channel IDs returned by APNs.
type ListChannelsResponse struct {
	Response
	ChannelIDs []string
}

// DeleteChannelRequest identifies the channel to delete permanently.
type DeleteChannelRequest struct {
	BundleID  string
	ChannelID string
	ID        *uuid.UUID
}

// CreateChannel creates a Live Activity channel. APNs chooses its identifier.
func (c *Client) CreateChannel(ctx context.Context, r CreateChannelRequest) (CreateChannelResponse, error) {
	if c == nil || c.httpClient == nil {
		return CreateChannelResponse{}, safeError("validation", errors.New("client is uninitialized"))
	}
	headers, err := broadcastHeaders(r.BundleID, "", r.ID, false)
	if err != nil {
		return CreateChannelResponse{}, safeError("validation", err)
	}
	if !validStoragePolicy(r.MessageStoragePolicy) {
		return CreateChannelResponse{}, safeError("validation", errors.New("invalid message storage policy"))
	}
	body, err := json.Marshal(struct {
		Policy   MessageStoragePolicy `json:"message-storage-policy"`
		PushType string               `json:"push-type"`
	}{r.MessageStoragePolicy, "LiveActivity"})
	if err != nil {
		return CreateChannelResponse{}, safeError("encode channel configuration", err)
	}
	response, err := c.execute(ctx, http.MethodPost, c.channelHost()+"/1/apps/"+url.PathEscape(r.BundleID)+"/channels", headers, body, http.StatusCreated, maxResponseBytes, nil)
	result := CreateChannelResponse{Response: response}
	if err != nil {
		return result, err
	}
	result.ChannelID = response.Header.Get("apns-channel-id")
	if !validChannelID(result.ChannelID) {
		return result, &ResponseError{Response: response, cause: errors.New("apns: channel creation response has no valid channel ID")}
	}
	return result, nil
}

// GetChannel reads the configuration of a channel.
func (c *Client) GetChannel(ctx context.Context, r GetChannelRequest) (GetChannelResponse, error) {
	if c == nil || c.httpClient == nil {
		return GetChannelResponse{}, safeError("validation", errors.New("client is uninitialized"))
	}
	headers, err := broadcastHeaders(r.BundleID, r.ChannelID, r.ID, true)
	if err != nil {
		return GetChannelResponse{}, safeError("validation", err)
	}
	var result GetChannelResponse
	response, err := c.execute(ctx, http.MethodGet, c.channelHost()+"/1/apps/"+url.PathEscape(r.BundleID)+"/channels", headers, nil, http.StatusOK, maxResponseBytes, func(data []byte) error {
		var body struct {
			Policy   *MessageStoragePolicy `json:"message-storage-policy"`
			PushType *string               `json:"push-type"`
		}
		if err := json.Unmarshal(data, &body); err != nil {
			return err
		}
		if body.Policy == nil || !validStoragePolicy(*body.Policy) || body.PushType == nil || *body.PushType == "" {
			return errors.New("apns: incomplete or invalid channel configuration")
		}
		result.MessageStoragePolicy = *body.Policy
		result.PushType = *body.PushType
		return nil
	})
	result.Response = response
	return result, err
}

// ListChannels lists the active channel IDs for an app. APNs does not paginate
// this operation. The returned slice belongs to the result.
func (c *Client) ListChannels(ctx context.Context, r ListChannelsRequest) (ListChannelsResponse, error) {
	if c == nil || c.httpClient == nil {
		return ListChannelsResponse{}, safeError("validation", errors.New("client is uninitialized"))
	}
	headers, err := broadcastHeaders(r.BundleID, "", r.ID, false)
	if err != nil {
		return ListChannelsResponse{}, safeError("validation", err)
	}
	var result ListChannelsResponse
	response, err := c.execute(ctx, http.MethodGet, c.channelHost()+"/1/apps/"+url.PathEscape(r.BundleID)+"/all-channels", headers, nil, http.StatusOK, maxChannelResponseBytes, func(data []byte) error {
		var body struct {
			Channels *[]string `json:"channels"`
		}
		if err := json.Unmarshal(data, &body); err != nil {
			return err
		}
		if body.Channels == nil {
			return errors.New("apns: channel list is missing its channels array")
		}
		for _, id := range *body.Channels {
			if !validChannelID(id) {
				return errors.New("apns: channel list contains an invalid channel ID")
			}
		}
		result.ChannelIDs = *body.Channels
		return nil
	})
	result.Response = response
	return result, err
}

// DeleteChannel permanently deletes a channel. APNs may still deliver already
// stored messages after accepting this operation.
func (c *Client) DeleteChannel(ctx context.Context, r DeleteChannelRequest) (Response, error) {
	if c == nil || c.httpClient == nil {
		return Response{}, safeError("validation", errors.New("client is uninitialized"))
	}
	headers, err := broadcastHeaders(r.BundleID, r.ChannelID, r.ID, true)
	if err != nil {
		return Response{}, safeError("validation", err)
	}
	return c.execute(ctx, http.MethodDelete, c.channelHost()+"/1/apps/"+url.PathEscape(r.BundleID)+"/channels", headers, nil, http.StatusNoContent, maxResponseBytes, nil)
}

// Channel lists may contain 10,000 IDs and exceed a notification response size.
const maxChannelResponseBytes = 4 << 20

func broadcastHeaders(bundleID, channelID string, id *uuid.UUID, needsChannel bool) (http.Header, error) {
	if !validBundleID(bundleID) {
		return nil, errors.New("invalid bundle ID")
	}
	if needsChannel && !validChannelID(channelID) {
		return nil, errors.New("invalid channel ID")
	}
	headers := make(http.Header)
	setRequestID(headers, "apns-request-id", id)
	if needsChannel {
		headers.Set("apns-channel-id", channelID)
	}
	return headers, nil
}

func validBundleID(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c != '.' && c != '-' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func validChannelID(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '!' || c > '~' {
			return false
		}
	}
	return true
}

func validStoragePolicy(policy MessageStoragePolicy) bool {
	return policy == MessageStorageNone || policy == MessageStorageMostRecent
}

func (c *Client) broadcastHost() string {
	if c.environment == Production {
		return HostBroadcastProduction
	}
	return HostBroadcastDevelopment
}

func (c *Client) channelHost() string {
	if c.environment == Production {
		return HostChannelProduction
	}
	return HostChannelDevelopment
}
