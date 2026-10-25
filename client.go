// Package apns2 is a Go client for sending Apple Push Notification service
// (APNs) notifications over HTTP/2.
package apns2

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"time"

	"github.com/jaakkonakaza/apns2/token"
)

// Apple HTTP/2 Development & Production urls. APNs also accepts port 2197,
// for example WithHost(HostProduction + ":2197").
const (
	HostDevelopment = "https://api.sandbox.push.apple.com"
	HostProduction  = "https://api.push.apple.com"
)

// Client represents a connection with the APNs. Certificate records the
// certificate passed to NewClient, which ClientManager uses as its cache key.
// Changing it after construction does not change the TLS identity.
type Client struct {
	Host        string
	Certificate tls.Certificate
	// Token is the provider signing identity. Configure it before use and reuse
	// it across pushes. Create a new client when changing teams, environments,
	// or incompatible key scopes because APNs binds identity to the connection,
	// and after adding topics, transferring apps, or revoking credentials.
	Token      *token.Token
	httpClient *http.Client
}

// NewClient returns a certificate-authenticated client. By default it uses an
// HTTP client configured for APNs HTTP/2. It connects when Push is first called.
//
// Reuse the client so its connections to APNs stay open across notifications,
// for hours or days. APNs may treat repeatedly opening and closing connections
// as a denial-of-service attack and temporarily block your server. See
// https://developer.apple.com/documentation/usernotifications/establishing-a-connection-to-apns
//
// If your use case involves multiple long-lived connections, consider using
// the ClientManager, which manages clients for you.
//
// With WithHTTPClient, the supplied client's TLS identity is used instead of
// certificate.
func NewClient(certificate tls.Certificate, options ...ClientOption) *Client {
	client := newClient(&tls.Config{Certificates: []tls.Certificate{certificate}}, options...)
	client.Certificate = certificate
	return client
}

// NewTokenClient returns a token-authenticated client. By default it uses an
// HTTP client configured for APNs HTTP/2. It connects when Push is first called.
//
// Reuse the client so its connections to APNs stay open across notifications,
// for hours or days. APNs may treat repeatedly opening and closing connections
// as a denial-of-service attack and temporarily block your server. See
// https://developer.apple.com/documentation/usernotifications/establishing-a-connection-to-apns
func NewTokenClient(token *token.Token, options ...ClientOption) *Client {
	client := newClient(&tls.Config{}, options...)
	client.Token = token
	return client
}

func newClient(tlsConfig *tls.Config, options ...ClientOption) *Client {
	config := defaultClientConfig()
	for _, option := range options {
		option(&config)
	}
	if config.tlsConfig != nil {
		supplied := config.tlsConfig.Clone()
		if len(tlsConfig.Certificates) != 0 {
			supplied.Certificates = tlsConfig.Certificates
			supplied.GetClientCertificate = nil
		}
		tlsConfig = supplied
	}
	httpClient := config.httpClient
	if httpClient == nil {
		httpClient = &http.Client{
			Transport:     newTransport(tlsConfig, config),
			Timeout:       config.timeout,
			CheckRedirect: noRedirects,
		}
	}
	return &Client{httpClient: httpClient, Host: config.host}
}

// maxResponseBytes bounds how much of an APNs response body Push reads.
const maxResponseBytes = 64 << 10

func noRedirects(*http.Request, []*http.Request) error {
	return errors.New("apns2: redirects are not supported")
}

// Push sends a Notification to the APNs gateway. Context carries cancellation
// and deadlines and must not be nil. Push reconnects as needed and returns the
// APNs response or an error if the request could not be completed.
//
// Push does not retry. Correct rejected requests before retrying, back off on
// ReasonTooManyRequests, and stop sending to a token that returns 410 until the
// app registers a new one.
func (c *Client) Push(ctx context.Context, n *Notification) (*Response, error) {
	if n == nil {
		return nil, errors.New("apns2: notification is nil")
	}
	if n.DeviceToken == "" {
		return nil, errors.New("apns2: device token is empty")
	}
	if _, err := hex.DecodeString(n.DeviceToken); err != nil {
		return nil, fmt.Errorf("apns2: invalid device token: %w", err)
	}
	if c.Host == "" {
		return nil, errors.New("apns2: host is not set; use WithHost(HostProduction) or WithHost(HostDevelopment)")
	}
	if n.PushType == "" {
		return nil, errors.New("apns2: push type is empty")
	}
	if n.Topic == "" && c.Token != nil {
		return nil, errors.New("apns2: topic is required with token authentication")
	}
	if len(n.CollapseID) > maxCollapseIDBytes {
		return nil, fmt.Errorf("apns2: collapse ID exceeds %d bytes", maxCollapseIDBytes)
	}
	if n.ApnsID != "" && !canonicalUUID(n.ApnsID) {
		return nil, errors.New("apns2: apns-id must be a canonical 8-4-4-4-12 UUID")
	}
	payload, err := json.Marshal(n)
	if err != nil {
		return nil, err
	}

	requestURL := c.Host + "/3/device/" + n.DeviceToken
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	target := newPushTarget(request.URL)
	requestCtx := context.WithValue(request.Context(), pushTargetKey{}, target)
	// Dials keep the request's trace, so this fires after the origin handshake
	// even when net/http performs it through a proxy.
	requestCtx = httptrace.WithClientTrace(requestCtx, &httptrace.ClientTrace{
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err == nil && state.NegotiatedProtocol == "h2" {
				target.proxy.release()
			}
		},
	})
	request = request.WithContext(requestCtx)

	var bearer string
	if c.Token != nil {
		if bearer, err = c.Token.Bearer(); err != nil {
			return nil, err
		}
		request.Header.Set("authorization", "bearer "+bearer)
	}

	setHeaders(request, n)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		// Closing a response body after reading it cannot change the push result.
		_ = response.Body.Close()
	}()

	r := &Response{}
	r.StatusCode = response.StatusCode
	r.ApnsID = response.Header.Get("apns-id")
	r.ApnsUniqueID = response.Header.Get("apns-unique-id")

	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return r, err
	}
	if len(data) > maxResponseBytes {
		return r, fmt.Errorf("apns2: response body exceeds %d bytes", maxResponseBytes)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return r, nil
	}
	var body struct {
		Reason    string `json:"reason"`
		Timestamp *int64 `json:"timestamp"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return r, err
	}
	r.Reason = body.Reason
	if body.Timestamp != nil {
		r.Timestamp = time.UnixMilli(*body.Timestamp)
	}
	if c.Token != nil && (r.Reason == ReasonExpiredProviderToken || r.Reason == ReasonInvalidProviderToken) {
		c.Token.Invalidate(bearer)
	}
	return r, nil
}

// CloseIdleConnections closes any underlying connections which were previously
// connected from previous requests but are now sitting idle. It will not
// interrupt any connections currently in use.
func (c *Client) CloseIdleConnections() {
	c.httpClient.CloseIdleConnections()
}

func setHeaders(r *http.Request, n *Notification) {
	r.Header.Set("apns-push-type", string(n.PushType))
	if n.Topic != "" {
		r.Header.Set("apns-topic", n.Topic)
	}
	if n.ApnsID != "" {
		r.Header.Set("apns-id", n.ApnsID)
	}
	if n.CollapseID != "" {
		r.Header.Set("apns-collapse-id", n.CollapseID)
	}
	if n.Priority > 0 {
		r.Header.Set("apns-priority", strconv.Itoa(n.Priority))
	}
	if !n.Expiration.IsZero() {
		r.Header.Set("apns-expiration", strconv.FormatInt(max(0, n.Expiration.Unix()), 10))
	}
}

// maxCollapseIDBytes is Apple's limit for apns-collapse-id.
const maxCollapseIDBytes = 64

// canonicalUUID reports whether s is 32 hexadecimal digits in the 8-4-4-4-12
// form APNs uses for apns-id and apns-request-id. Apple documents lowercase,
// but APNs returns uppercase IDs, so either case is accepted.
func canonicalUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}
	}
	return true
}
