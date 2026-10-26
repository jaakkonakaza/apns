package apns

import (
	"fmt"
	"net/http"
	"time"
)

// StatusAccepted is a 200 response.
const StatusAccepted = http.StatusOK

// The possible Reason error codes returned from APNs. See
// https://developer.apple.com/documentation/usernotifications/handling-notification-responses-from-apns
const (
	// 400 The collapse identifier exceeds the maximum allowed size
	ReasonBadCollapseID Reason = "BadCollapseId"

	// 400 The specified device token was bad. Verify that the request contains a
	// valid token and that the token matches the environment.
	ReasonBadDeviceToken Reason = "BadDeviceToken"

	// 400 The apns-expiration value is bad.
	ReasonBadExpirationDate Reason = "BadExpirationDate"

	// 400 The apns-id value is bad.
	ReasonBadMessageID Reason = "BadMessageId"

	// 400 The apns-priority value is bad.
	ReasonBadPriority Reason = "BadPriority"

	// 400 The apns-topic was invalid.
	ReasonBadTopic Reason = "BadTopic"

	// 400 The device token does not match the specified topic.
	ReasonDeviceTokenNotForTopic Reason = "DeviceTokenNotForTopic"

	// 400 One or more headers were repeated.
	ReasonDuplicateHeaders Reason = "DuplicateHeaders"

	// 400 Idle time out.
	ReasonIdleTimeout Reason = "IdleTimeout"

	// 400 The apns-push-type value is invalid.
	ReasonInvalidPushType Reason = "InvalidPushType"

	// 400 The device token is not specified in the request :path. Verify that the
	// :path header contains the device token.
	ReasonMissingDeviceToken Reason = "MissingDeviceToken"

	// 400 The apns-topic header of the request was not specified and was
	// required. The apns-topic header is mandatory when the client is connected
	// using a certificate that supports multiple topics.
	ReasonMissingTopic Reason = "MissingTopic"

	// 400 The message payload was empty.
	ReasonPayloadEmpty Reason = "PayloadEmpty"

	// 400 Pushing to this topic is not allowed.
	ReasonTopicDisallowed Reason = "TopicDisallowed"

	// 403 The certificate was bad.
	ReasonBadCertificate Reason = "BadCertificate"

	// 403 The client certificate was for the wrong environment.
	ReasonBadCertificateEnvironment Reason = "BadCertificateEnvironment"

	// 403 The provider token is stale and a new token should be generated.
	ReasonExpiredProviderToken Reason = "ExpiredProviderToken"

	// 403 The specified action is not allowed.
	ReasonForbidden Reason = "Forbidden"

	// 403 The provider token is not valid or the token signature could not be
	// verified.
	ReasonInvalidProviderToken Reason = "InvalidProviderToken"

	// 403 No provider certificate was used to connect to APNs and Authorization
	// header was missing or no provider token was specified.
	ReasonMissingProviderToken Reason = "MissingProviderToken"

	// 403 The key ID in the provider token isn't related to the key ID of the
	// token used in the first push of this connection. To use this token, open
	// a new connection.
	ReasonUnrelatedKeyIDInToken Reason = "UnrelatedKeyIdInToken"

	// 403 The key ID in the provider token doesn't match the environment.
	ReasonBadEnvironmentKeyIDInToken Reason = "BadEnvironmentKeyIdInToken"

	// 404 The request contained a bad :path value.
	ReasonBadPath Reason = "BadPath"

	// 405 The specified :method was not POST.
	ReasonMethodNotAllowed Reason = "MethodNotAllowed"

	// 410 The device token has expired.
	ReasonExpiredToken Reason = "ExpiredToken"

	// 410 The device token is inactive for the specified topic.
	ReasonUnregistered Reason = "Unregistered"

	// 413 The message payload was too large. The limit is 4 KB (4096 bytes),
	// or 5 KB (5120 bytes) for VoIP and broadcast notifications.
	ReasonPayloadTooLarge Reason = "PayloadTooLarge"

	// 429 The provider token is being updated too often. Update the
	// authentication token no more than once every 20 minutes.
	ReasonTooManyProviderTokenUpdates Reason = "TooManyProviderTokenUpdates"

	// 429 Too many requests were made consecutively to the same device token.
	ReasonTooManyRequests Reason = "TooManyRequests"

	// 500 An internal server error occurred.
	ReasonInternalServerError Reason = "InternalServerError"

	// 503 The service is unavailable.
	ReasonServiceUnavailable Reason = "ServiceUnavailable"

	// 503 The server is shutting down.
	ReasonShutdown Reason = "Shutdown"
)

// Reason is an APNs rejection reason. Unknown values remain available for inspection.
type Reason string

// Response is an owned snapshot of APNs response metadata. Acceptance does not
// establish delivery. Header and identifiers may contain sensitive diagnostic data.
type Response struct {
	StatusCode   int
	APNSID       string
	APNSUniqueID string
	RequestID    string
	Header       http.Header
}

// Rejection reports an actual HTTP 4xx or 5xx response. Reason and unwrapped
// causes are diagnostic data and need redaction before logging.
type Rejection struct {
	Response                 Response
	Reason                   Reason
	DeviceTokenInvalidatedAt time.Time
	cause                    error
}

func (e *Rejection) Error() string {
	return fmt.Sprintf("apns: request rejected (status %d)", e.Response.StatusCode)
}
func (e *Rejection) Unwrap() error { return e.cause }

// ResponseError reports an unexpected status or an incomplete response.
type ResponseError struct {
	Response Response
	cause    error
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("apns: invalid response (status %d)", e.Response.StatusCode)
}
func (e *ResponseError) Unwrap() error { return e.cause }

// operationError deliberately omits arbitrary diagnostic text from Error.
type operationError struct {
	operation string
	cause     error
}

func (e *operationError) Error() string { return "apns: " + e.operation + " failed" }
func (e *operationError) Unwrap() error { return e.cause }
func safeError(operation string, cause error) error {
	if cause == nil {
		return nil
	}
	return &operationError{operation: operation, cause: cause}
}
