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

// Apple HTTP/2 Development & Production urls
const (
	HostDevelopment = "https://api.sandbox.push.apple.com"
	HostProduction  = "https://api.push.apple.com"
)

// Client represents a connection with the APNs
type Client struct {
	Host        string
	Certificate tls.Certificate
	Token       *token.Token
	httpClient  *http.Client
}

// NewClient returns a certificate-authenticated client. By default it uses an
// HTTP client configured for APNs HTTP/2. It connects when Push is first called.
//
// As per the Apple APNs Provider API, you should keep a handle on this client
// so that you can keep your connections with APNs open across multiple
// notifications; don’t repeatedly open and close connections. APNs treats rapid
// connection and disconnection as a denial-of-service attack.
//
// If your use case involves multiple long-lived connections, consider using
// the ClientManager, which manages clients for you.
// WithHTTPClient uses the supplied client's TLS identity instead of certificate.
func NewClient(certificate tls.Certificate, options ...ClientOption) *Client {
	client := newClient(&tls.Config{Certificates: []tls.Certificate{certificate}}, options...)
	client.Certificate = certificate
	return client
}

// NewTokenClient returns a token-authenticated client. By default it uses an
// HTTP client configured for APNs HTTP/2. It connects when Push is first called.
//
// As per the Apple APNs Provider API, you should keep a handle on this client
// so that you can keep your connections with APNs open across multiple
// notifications; don’t repeatedly open and close connections. APNs treats rapid
// connection and disconnection as a denial-of-service attack.
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

	if c.Token != nil {
		if err := c.setTokenHeader(request); err != nil {
			return nil, err
		}
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
	return r, nil
}

// CloseIdleConnections closes any underlying connections which were previously
// connected from previous requests but are now sitting idle. It will not
// interrupt any connections currently in use.
func (c *Client) CloseIdleConnections() {
	c.httpClient.CloseIdleConnections()
}

func (c *Client) setTokenHeader(r *http.Request) error {
	bearer, err := c.Token.Bearer()
	if err != nil {
		return err
	}
	r.Header.Set("authorization", "bearer "+bearer)
	return nil
}

func setHeaders(r *http.Request, n *Notification) {
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
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
	if n.PushType != "" {
		r.Header.Set("apns-push-type", string(n.PushType))
	} else {
		r.Header.Set("apns-push-type", string(PushTypeAlert))
	}
}
