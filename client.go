// Package apns is a client for Apple Push Notification service (APNs).
package apns

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
	"uuid"

	"github.com/jaakkonakaza/apns/internal/credential"
	"github.com/jaakkonakaza/apns/internal/nilcheck"
	"github.com/jaakkonakaza/apns/token"
)

// Environment selects the complete built-in APNs endpoint set.
type Environment uint8

const (
	Sandbox Environment = iota + 1
	Production
)

const (
	HostDevelopment    = "https://api.sandbox.push.apple.com"
	HostProduction     = "https://api.push.apple.com"
	maxResponseBytes   = 64 << 10
	maxCollapseIDBytes = 64
)

// Client binds an immutable authentication identity and environment. Reuse it
// across concurrent requests. External certificate signers must remain immutable
// and safe for concurrent use. Callbacks must preserve request contexts.
type Client struct {
	environment    Environment
	host           string
	token          *token.Token
	httpClient     *http.Client
	ownedTransport *http.Transport
	proxied        bool
}

// NewTokenClient validates configuration without contacting APNs.
func NewTokenClient(provider *token.Token, cfg Config) (*Client, error) {
	if provider == nil {
		return nil, safeError("construction", token.ErrAuthKeyNil)
	}
	if _, err := provider.Identity(); err != nil {
		return nil, safeError("construction", err)
	}
	client, err := newClient(&tls.Config{}, cfg)
	if err != nil {
		return nil, err
	}
	client.token = provider
	return client, nil
}

// NewCertificateClient copies mutable certificate data and validates key matching.
// External private signers are retained and must not be mutated by the caller.
func NewCertificateClient(cert tls.Certificate, cfg Config) (*Client, error) {
	copied, err := copyCertificate(cert)
	if err != nil {
		return nil, safeError("construction", err)
	}
	return newClient(&tls.Config{Certificates: []tls.Certificate{copied}}, cfg)
}

func copyCertificate(cert tls.Certificate) (tls.Certificate, error) {
	pub, err := credential.PublicKey(cert)
	if err != nil {
		return tls.Certificate{}, err
	}
	copied := cert
	copied.Certificate = make([][]byte, len(cert.Certificate))
	for i, der := range cert.Certificate {
		copied.Certificate[i] = bytes.Clone(der)
	}
	leaf, err := x509.ParseCertificate(copied.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	if !bytes.Equal(pub, leaf.RawSubjectPublicKeyInfo) {
		return tls.Certificate{}, errors.New("certificate does not match signing key")
	}
	copied.Leaf = leaf
	copied.OCSPStaple = bytes.Clone(cert.OCSPStaple)
	copied.SignedCertificateTimestamps = make([][]byte, len(cert.SignedCertificateTimestamps))
	for i, v := range cert.SignedCertificateTimestamps {
		copied.SignedCertificateTimestamps[i] = bytes.Clone(v)
	}
	copied.SupportedSignatureAlgorithms = append([]tls.SignatureScheme(nil), cert.SupportedSignatureAlgorithms...)
	return copied, nil
}

func newClient(originTLS *tls.Config, cfg Config) (*Client, error) {
	transport, err := makeTransport(originTLS, cfg)
	if err != nil {
		return nil, safeError("construction", err)
	}
	var rt http.RoundTripper = transport
	if cfg.Transport.Decorate != nil {
		rt = cfg.Transport.Decorate(rt)
		if nilcheck.IsNil(rt) {
			transport.CloseIdleConnections()
			return nil, safeError("construction", errors.New("nil transport decoration"))
		}
	}
	host := HostDevelopment
	if cfg.Environment == Production {
		host = HostProduction
	}
	if cfg.DevicePort == 2197 {
		host += ":2197"
	}
	return &Client{environment: cfg.Environment, host: host, ownedTransport: transport, proxied: cfg.Transport.Proxy != nil, httpClient: &http.Client{
		Transport: captureRoundTripper{next: rt}, Timeout: requestTimeout(cfg), CheckRedirect: noRedirects,
	}}, nil
}

func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Push encodes the payload once and returns nil error only for APNs acceptance.
// It adds no application retry loop. HTTP/2 may replay safely unprocessed work.
func (c *Client) Push(ctx context.Context, req Request) (Response, error) {
	if c == nil || c.httpClient == nil {
		return Response{}, safeError("validation", errors.New("client is uninitialized"))
	}
	if err := validateRequest(req); err != nil {
		return Response{}, safeError("validation", err)
	}
	headers := make(http.Header)
	headers.Set("apns-topic", req.Topic)
	headers.Set("apns-push-type", string(req.PushType))
	if req.CollapseID != "" {
		headers.Set("apns-collapse-id", req.CollapseID)
	}
	setRequestID(headers, "apns-id", req.ID)
	if err := setPriority(headers, req.Priority, req.PushType, false); err != nil {
		return Response{}, safeError("validation", err)
	}
	if err := setExpiration(headers, req.ExpiresAt, false); err != nil {
		return Response{}, safeError("validation", err)
	}
	limit := 4096
	if req.PushType == PushTypeVOIP {
		limit = 5120
	}
	body, err := marshalPayload(req.Payload, limit)
	if err != nil {
		return Response{}, err
	}
	return c.execute(ctx, http.MethodPost, c.host+"/3/device/"+req.DeviceToken, headers, body, http.StatusOK, maxResponseBytes, nil)
}

func validateRequest(req Request) error {
	if req.DeviceToken == "" {
		return errors.New("device token required")
	}
	if _, err := hex.DecodeString(req.DeviceToken); err != nil {
		return err
	}
	if req.Topic == "" || req.PushType == "" {
		return errors.New("topic and push type required")
	}
	if len(req.CollapseID) > maxCollapseIDBytes {
		return errors.New("collapse identifier too long")
	}
	for _, v := range []string{req.Topic, string(req.PushType), req.CollapseID} {
		if !validHeader(v) {
			return errors.New("invalid metadata header")
		}
	}
	return nil
}

func validHeader(s string) bool {
	for _, b := range []byte(s) {
		if b == '\r' || b == '\n' || b == 127 || b < 32 && b != '\t' {
			return false
		}
	}
	return true
}

func setRequestID(h http.Header, name string, id *uuid.UUID) {
	if id != nil {
		h.Set(name, id.String())
	}
}

func setPriority(h http.Header, p Priority, typ PushType, broadcast bool) error {
	if p != 0 && p != 1 && p != 5 && p != 10 {
		return errors.New("unsupported priority")
	}
	if typ == PushTypeBackground {
		if p == 0 {
			p = PriorityLow
		}
		if p != PriorityLow {
			return errors.New("background priority must be 5")
		}
	}
	if (typ == PushTypeLiveActivity || broadcast) && p != 0 && p != PriorityLow && p != PriorityHigh {
		return errors.New("activity priority must be 5 or 10")
	}
	if broadcast && p == 0 {
		p = PriorityHigh
	}
	if p != 0 {
		h.Set("apns-priority", strconv.Itoa(int(p)))
	}
	return nil
}

func setExpiration(h http.Header, expires *time.Time, broadcast bool) error {
	if expires == nil {
		if broadcast {
			h.Set("apns-expiration", "0")
		}
		return nil
	}
	if expires.Before(time.Unix(0, 0)) {
		return errors.New("expiration precedes Unix epoch")
	}
	h.Set("apns-expiration", strconv.FormatInt(expires.Unix(), 10))
	return nil
}

// responseCapture is scoped to one operation, including transport recovery.
// It keeps the last response and copies its metadata only if Do fails.
type responseCapture struct {
	mu       sync.Mutex
	response *http.Response
}
type (
	responseCaptureKey  struct{}
	captureRoundTripper struct{ next http.RoundTripper }
)

func (rt captureRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := rt.next.RoundTrip(req)
	if response != nil {
		if capture, ok := req.Context().Value(responseCaptureKey{}).(*responseCapture); ok {
			capture.mu.Lock()
			capture.response = response
			capture.mu.Unlock()
		}
	}
	return response, err
}

func (capture *responseCapture) snapshot() Response {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if capture.response == nil {
		return Response{}
	}
	return responseMetadata(capture.response)
}

func responseMetadata(response *http.Response) Response {
	h := response.Header.Clone()
	return Response{StatusCode: response.StatusCode, Header: h, APNSID: h.Get("apns-id"), APNSUniqueID: h.Get("apns-unique-id"), RequestID: h.Get("apns-request-id")}
}

func (c *Client) execute(ctx context.Context, method, url string, headers http.Header, body []byte, expectedStatus int, bodyLimit int64, decodeSuccess func([]byte) error) (Response, error) {
	if c == nil || c.httpClient == nil {
		return Response{}, safeError("validation", errors.New("client is uninitialized"))
	}
	if ctx == nil {
		return Response{}, safeError("validation", errors.New("context is nil"))
	}
	capture := new(responseCapture)
	ctx = context.WithValue(ctx, responseCaptureKey{}, capture)
	request, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return Response{}, safeError("request", err)
	}
	request.Header = headers.Clone()
	request.Header.Set("content-type", "application/json")
	request = prepareRequest(request, c.proxied)
	var bearer string
	if c.token != nil {
		bearer, err = c.token.Bearer()
		if err != nil {
			return Response{}, safeError("authentication", err)
		}
		request.Header.Set("authorization", "bearer "+bearer)
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		metadata := capture.snapshot()
		if metadata.StatusCode != 0 {
			return metadata, responseFailure(metadata, err)
		}
		return Response{}, safeError("transport", err)
	}
	defer func() { _ = response.Body.Close() }()
	metadata := responseMetadata(response)
	// APNs has accepted the work once the expected status arrives. Bodies it
	// does not need cannot turn acceptance into a failure that invites a retry.
	if response.StatusCode == expectedStatus && decodeSuccess == nil {
		return metadata, nil
	}
	data, readErr := readResponseBodyLimit(response.Body, bodyLimit)
	if readErr != nil {
		return metadata, responseFailure(metadata, readErr)
	}
	if response.StatusCode >= 400 && response.StatusCode <= 599 {
		rejection := &Rejection{Response: metadata}
		rejection.cause = decodeRejection(data, response.StatusCode, rejection)
		if rejection.cause == nil && response.StatusCode == http.StatusForbidden && c.token != nil &&
			(rejection.Reason == ReasonInvalidProviderToken || rejection.Reason == ReasonExpiredProviderToken) {
			c.token.Invalidate(bearer)
		}
		return metadata, rejection
	}
	if response.StatusCode != expectedStatus {
		return metadata, &ResponseError{Response: metadata, cause: errors.New("unexpected HTTP status")}
	}
	if decodeSuccess != nil {
		if err := decodeSuccess(data); err != nil {
			return metadata, &ResponseError{Response: metadata, cause: err}
		}
	}
	return metadata, nil
}

func responseFailure(metadata Response, cause error) error {
	if metadata.StatusCode >= 400 && metadata.StatusCode <= 599 {
		return &Rejection{Response: metadata, cause: cause}
	}
	return &ResponseError{Response: metadata, cause: cause}
}

func decodeRejection(data []byte, status int, rejection *Rejection) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var fields map[string]jsontext.Value
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if fields == nil {
		return errors.New("rejection body must be an object")
	}
	var failures []error
	if reason, ok := fields["reason"]; ok {
		var text string
		if bytes.Equal(bytes.TrimSpace(reason), []byte("null")) {
			failures = append(failures, errors.New("null rejection reason"))
		} else if err := json.Unmarshal(reason, &text); err != nil {
			failures = append(failures, err)
		} else {
			rejection.Reason = Reason(text)
		}
	}
	if status == http.StatusGone {
		if raw, ok := fields["timestamp"]; ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			var milliseconds int64
			if err := json.Unmarshal(raw, &milliseconds); err != nil {
				failures = append(failures, err)
			} else {
				rejection.DeviceTokenInvalidatedAt = time.UnixMilli(milliseconds)
			}
		}
	}
	return errors.Join(failures...)
}

func readResponseBodyLimit(body io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("response body too large")
	}
	return data, nil
}

func marshalPayload(value any, limit int) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, safeError("encoding", err)
	}
	// Marshal already rejects invalid, duplicate-name, and non-UTF-8 output,
	// including from MarshalJSON, and emits it without surrounding whitespace.
	if len(data) == 0 || data[0] != '{' {
		return nil, safeError("validation", errors.New("payload must be a strict JSON object"))
	}
	if len(data) > limit {
		return nil, safeError("validation", fmt.Errorf("payload exceeds %d bytes", limit))
	}
	return data, nil
}

// CloseIdleConnections releases idle sockets while preserving active and future sends.
func (c *Client) CloseIdleConnections() {
	if c != nil && c.ownedTransport != nil {
		c.ownedTransport.CloseIdleConnections()
	}
}
