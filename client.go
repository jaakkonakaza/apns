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
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jaakkonakaza/apns2/token"
)

// Apple HTTP/2 Development & Production urls. APNs also accepts port 2197,
// for example WithHost(HostProduction + ":2197").
const (
	HostDevelopment = "https://api.sandbox.push.apple.com"
	HostProduction  = "https://api.push.apple.com"
)

// Client sends notifications using a fixed endpoint and authentication identity.
// Reuse it across pushes so its HTTP/2 connections stay open.
type Client struct {
	host           string
	certificate    tls.Certificate
	token          *token.Token
	httpClient     *http.Client
	ownedTransport *http.Transport
}

// Host returns the endpoint selected when the client was constructed.
func (c *Client) Host() string { return c.host }

// NewClient constructs a certificate-authenticated client without connecting.
// WithHTTPClient uses the supplied client's TLS identity instead of certificate.
func NewClient(certificate tls.Certificate, options ...ClientOption) (*Client, error) {
	config, err := clientConfigForOptions(options)
	if err != nil {
		return nil, err
	}
	return newCertificateClient(certificate, config)
}

func newCertificateClient(certificate tls.Certificate, config clientConfig) (*Client, error) {
	if config.httpClient == nil && (len(certificate.Certificate) == 0 || certificate.PrivateKey == nil) {
		return nil, errors.New("apns2: certificate and private key are required")
	}
	client, err := newClient(&tls.Config{Certificates: []tls.Certificate{certificate}}, config)
	if err != nil {
		return nil, err
	}
	client.certificate = certificate
	return client, nil
}

// NewTokenClient constructs a token-authenticated client without connecting.
// Share one provider token per signing identity and reuse the returned client.
func NewTokenClient(provider *token.Token, options ...ClientOption) (*Client, error) {
	config, err := clientConfigForOptions(options)
	if err != nil {
		return nil, err
	}
	return newTokenClient(provider, config)
}

func newTokenClient(provider *token.Token, config clientConfig) (*Client, error) {
	if provider == nil {
		return nil, token.ErrAuthKeyNil
	}
	if _, err := provider.Identity(); err != nil {
		return nil, err
	}
	client, err := newClient(&tls.Config{}, config)
	if err != nil {
		return nil, err
	}
	client.token = provider
	return client, nil
}

func clientConfigForOptions(options []ClientOption) (clientConfig, error) {
	config := defaultClientConfig()
	for _, option := range options {
		if option == nil {
			return clientConfig{}, errors.New("apns2: client option is nil")
		}
		option(&config)
	}
	return config, nil
}

func newClient(tlsConfig *tls.Config, config clientConfig) (*Client, error) {
	if err := validateHost(config.host, config.httpClient != nil); err != nil {
		return nil, err
	}
	if config.httpClient == nil && (config.timeout < 0 || config.dialTimeout < 0 || config.readIdleTimeout < 0 || config.idleConnTimeout < 0) {
		return nil, errors.New("apns2: timeouts must not be negative")
	}
	if config.httpClient != nil && config.transportWrapper != nil {
		return nil, errors.New("apns2: WithTransportWrapper cannot be combined with WithHTTPClient")
	}
	if config.tlsConfig != nil {
		supplied := config.tlsConfig.Clone()
		if len(tlsConfig.Certificates) != 0 {
			supplied.Certificates = tlsConfig.Certificates
			supplied.GetClientCertificate = nil
		}
		tlsConfig = supplied
	}
	if config.httpClient == nil && tlsConfig.MaxVersion != 0 && (tlsConfig.MaxVersion < tls.VersionTLS12 || tlsConfig.MinVersion > tlsConfig.MaxVersion) {
		return nil, errors.New("apns2: incompatible TLS version limits")
	}
	client := &Client{host: strings.TrimRight(config.host, "/"), httpClient: config.httpClient}
	if client.httpClient == nil {
		transport := newTransport(tlsConfig, config)
		var roundTripper http.RoundTripper = transport
		if config.transportWrapper != nil {
			roundTripper = config.transportWrapper(transport)
			if roundTripper == nil {
				return nil, errors.New("apns2: transport wrapper returned nil")
			}
		}
		client.ownedTransport = transport
		client.httpClient = &http.Client{Transport: roundTripper, Timeout: config.timeout, CheckRedirect: noRedirects}
	}
	return client, nil
}

func validateHost(host string, allowHTTP bool) error {
	if host == "" {
		return errors.New("apns2: host is required")
	}
	endpoint, err := url.Parse(host)
	if err != nil {
		return fmt.Errorf("apns2: invalid host: %w", err)
	}
	if endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || strings.Contains(host, "#") || endpoint.Fragment != "" || endpoint.Path != "" && endpoint.Path != "/" || endpoint.Opaque != "" {
		return errors.New("apns2: host must be an absolute endpoint without credentials, path, query or fragment")
	}
	if endpoint.Scheme != "https" {
		if endpoint.Scheme == "http" && allowHTTP {
			return nil
		}
		return ErrHTTP2Required
	}
	return nil
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
// If APNs closes a connection, its reason may appear in the transport error text.
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
	if n.PushType == "" {
		return nil, errors.New("apns2: push type is empty")
	}
	if n.Topic == "" && c.token != nil {
		return nil, errors.New("apns2: topic is required with token authentication")
	}
	if len(n.CollapseID) > maxCollapseIDBytes {
		return nil, fmt.Errorf("apns2: collapse ID exceeds %d bytes", maxCollapseIDBytes)
	}
	if n.APNSID != "" && !canonicalUUID(n.APNSID) {
		return nil, errors.New("apns2: apns-id must be a canonical 8-4-4-4-12 UUID")
	}
	if n.PushType == PushTypeBackground && n.Priority != 0 && n.Priority != PriorityLow {
		return nil, errors.New("apns2: background notifications require priority 5")
	}
	limit := 4096
	if n.PushType == PushTypeVOIP {
		limit = 5120
	}
	payload, err := marshalPayload(n.Payload, limit)
	if err != nil {
		return nil, err
	}

	requestURL := c.host + "/3/device/" + n.DeviceToken
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}

	request = prepareRequest(request)

	var bearer string
	if c.token != nil {
		if bearer, err = c.token.Bearer(); err != nil {
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
	r.Header = response.Header.Clone()
	r.APNSID = response.Header.Get("apns-id")
	r.APNSUniqueID = response.Header.Get("apns-unique-id")

	data, err := readResponseBody(response.Body)
	if err != nil {
		return r, err
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
	if c.token != nil && (r.Reason == ReasonExpiredProviderToken || r.Reason == ReasonInvalidProviderToken) {
		c.token.Invalidate(bearer)
	}
	return r, nil
}

// CloseIdleConnections closes any underlying connections which were previously
// connected from previous requests but are now sitting idle. It will not
// interrupt any connections currently in use.
func (c *Client) CloseIdleConnections() {
	if c.ownedTransport != nil {
		c.ownedTransport.CloseIdleConnections()
		return
	}
	c.httpClient.CloseIdleConnections()
}

func setHeaders(r *http.Request, n *Notification) {
	r.Header.Set("apns-push-type", string(n.PushType))
	if n.Topic != "" {
		r.Header.Set("apns-topic", n.Topic)
	}
	if n.APNSID != "" {
		r.Header.Set("apns-id", n.APNSID)
	}
	if n.CollapseID != "" {
		r.Header.Set("apns-collapse-id", n.CollapseID)
	}
	priority := n.Priority
	if n.PushType == PushTypeBackground && priority == 0 {
		priority = PriorityLow
	}
	if priority > 0 {
		r.Header.Set("apns-priority", strconv.Itoa(priority))
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

func readResponseBody(body io.Reader) ([]byte, error) {
	return readResponseBodyLimit(body, maxResponseBytes)
}

func readResponseBodyLimit(body io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("apns2: response body exceeds %d bytes", limit)
	}
	return data, nil
}

func marshalPayload(value any, limit int) ([]byte, error) {
	data, err := json.Marshal(&Notification{Payload: value})
	if err != nil {
		return nil, err
	}
	object := bytes.TrimSpace(data)
	if len(object) == 0 || object[0] != '{' {
		return nil, errors.New("apns2: payload must be a JSON object")
	}
	if len(data) > limit {
		return nil, fmt.Errorf("apns2: payload exceeds %d bytes", limit)
	}
	return data, nil
}
