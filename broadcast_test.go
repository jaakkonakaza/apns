package apns_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/jaakkonakaza/apns"
	"github.com/jaakkonakaza/apns/token"
)

const (
	broadcastRequestID = "2288cf3f-70d8-46a6-97d7-dd5d00867127"
	broadcastChannelID = "dHN0LXNyY2gtY2hubA=="
)

func broadcastProvider(t testing.TB) *token.Token {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := token.New(key, "lab-key", "lab-team")
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

// broadcastServer keeps the owned transport's real TLS and HTTP/2 verification
// while routing Apple's built-in names to a local server.
func broadcastServer(t testing.TB, handler http.Handler) *apns.Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "APNs test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"api.sandbox.push.apple.com", "api.push.apple.com", "api-broadcast.sandbox.push.apple.com", "api-broadcast.push.apple.com", "api-manage-broadcast.sandbox.push.apple.com", "api-manage-broadcast.push.apple.com"},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	client, err := apns.NewTokenClient(broadcastProvider(t), apns.Config{
		Environment: apns.Sandbox,
		Transport: apns.TransportConfig{
			RootCAs: roots,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func TestBroadcastAndChannelRequests(t *testing.T) {
	id := uuid.MustParse(broadcastRequestID)
	for _, tc := range []struct {
		name, method, host, path, requestBody, responseBody string
		status                                              int
		channel                                             bool
		call                                                func(*apns.Client) (apns.Response, error)
	}{
		{
			"broadcast", "POST", "api-broadcast.sandbox.push.apple.com", "/4/broadcasts/apps/com.example.app", `{"aps":{"event":"update"}}`, "", 200, true,
			func(c *apns.Client) (apns.Response, error) {
				return c.Broadcast(context.Background(), apns.BroadcastRequest{BundleID: "com.example.app", ChannelID: broadcastChannelID, ID: &id, Payload: jsontext.Value(`{"aps":{"event":"update"}}`)})
			},
		},
		{
			"create", "POST", "api-manage-broadcast.sandbox.push.apple.com:2195", "/1/apps/com.example.app/channels", `{"message-storage-policy":0,"push-type":"LiveActivity"}`, "", 201, false,
			func(c *apns.Client) (apns.Response, error) {
				r, err := c.CreateChannel(context.Background(), apns.CreateChannelRequest{BundleID: "com.example.app", ID: &id, MessageStoragePolicy: apns.MessageStorageNone})
				if err == nil && r.ChannelID != broadcastChannelID {
					t.Errorf("created channel = %q", r.ChannelID)
				}
				return r.Response, err
			},
		},
		{
			"get", "GET", "api-manage-broadcast.sandbox.push.apple.com:2195", "/1/apps/com.example.app/channels", "", `{"message-storage-policy":1,"push-type":"LiveActivity"}`, 200, true,
			func(c *apns.Client) (apns.Response, error) {
				r, err := c.GetChannel(context.Background(), apns.GetChannelRequest{BundleID: "com.example.app", ChannelID: broadcastChannelID, ID: &id})
				if err == nil && (r.MessageStoragePolicy != apns.MessageStorageMostRecent || r.PushType != "LiveActivity") {
					t.Errorf("channel configuration = %+v", r)
				}
				return r.Response, err
			},
		},
		{
			"delete", "DELETE", "api-manage-broadcast.sandbox.push.apple.com:2195", "/1/apps/com.example.app/channels", "", "", 204, true,
			func(c *apns.Client) (apns.Response, error) {
				return c.DeleteChannel(context.Background(), apns.DeleteChannelRequest{BundleID: "com.example.app", ChannelID: broadcastChannelID, ID: &id})
			},
		},
		{
			"list", "GET", "api-manage-broadcast.sandbox.push.apple.com:2195", "/1/apps/com.example.app/all-channels", "", `{"channels":["dHN0LXNyY2gtY2hubA=="]}`, 200, false,
			func(c *apns.Client) (apns.Response, error) {
				r, err := c.ListChannels(context.Background(), apns.ListChannelsRequest{BundleID: "com.example.app", ID: &id})
				if err == nil && (len(r.ChannelIDs) != 1 || r.ChannelIDs[0] != broadcastChannelID) {
					t.Errorf("channels = %v", r.ChannelIDs)
				}
				return r.Response, err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := broadcastServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 || r.Method != tc.method || r.Host != tc.host || r.URL.Path != tc.path {
					t.Errorf("request = %s %s %s %s", r.Proto, r.Method, r.Host, r.URL.Path)
				}
				if !strings.HasPrefix(r.Header.Get("authorization"), "bearer ") || r.Header.Get("apns-request-id") != broadcastRequestID {
					t.Error("missing authentication or request identifier")
				}
				if got := r.Header.Get("apns-channel-id"); tc.channel && got != broadcastChannelID || !tc.channel && got != "" {
					t.Errorf("channel header = %q", got)
				}
				if tc.name == "broadcast" {
					for key, want := range map[string]string{"apns-push-type": "liveactivity", "apns-priority": "10", "apns-expiration": "0"} {
						if got := r.Header.Get(key); got != want {
							t.Errorf("%s = %q, want %q", key, got, want)
						}
					}
				} else if r.Header.Get("apns-push-type") != "" {
					t.Error("channel management sent a push-type header")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != tc.requestBody {
					t.Errorf("body = %s, error %v", body, err)
				}
				w.Header().Set("apns-id", "device-metadata")
				w.Header().Set("apns-request-id", broadcastRequestID)
				w.Header().Set("apns-channel-id", broadcastChannelID)
				w.Header().Set("apns-unique-id", "unique-id")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.responseBody)
			}))
			response, err := tc.call(client)
			if err != nil || response.StatusCode != tc.status || response.RequestID != broadcastRequestID || response.APNSUniqueID != "unique-id" || response.APNSID != "device-metadata" {
				t.Fatalf("response = %+v, error = %v", response, err)
			}
		})
	}
}

func TestBroadcastEncodedPayloadLimit(t *testing.T) {
	var requests atomic.Int32
	client := broadcastServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil || len(body) != 5120 {
			t.Errorf("encoded length = %d, %v", len(body), err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	for _, raw := range []bool{false, true} {
		for _, size := range []int{5120, 5121} {
			t.Run(fmt.Sprintf("raw-%t-size-%d", raw, size), func(t *testing.T) {
				text := strings.Repeat("界", (size-14)/3) + strings.Repeat("x", (size-14)%3)
				value := struct {
					Padding string `json:"padding"`
				}{text}
				var body any = value
				if raw {
					data, err := json.Marshal(value)
					if err != nil {
						t.Fatal(err)
					}
					body = jsontext.Value(data)
				}
				_, err := client.Broadcast(context.Background(), apns.BroadcastRequest{BundleID: "com.example.app", ChannelID: broadcastChannelID, Payload: body})
				if (err == nil) != (size == 5120) {
					t.Fatalf("size %d error = %v", size, err)
				}
			})
		}
	}
	if requests.Load() != 2 {
		t.Fatalf("requests = %d, want 2", requests.Load())
	}
}

func TestBroadcastPriorityAndExpiration(t *testing.T) {
	expiration := time.Unix(1234567890, 0)
	var wantPriority string
	client := broadcastServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apns-priority") != wantPriority || r.Header.Get("apns-expiration") != "1234567890" {
			t.Errorf("headers = %v", r.Header)
		}
		w.WriteHeader(http.StatusOK)
	}))
	for _, priority := range []apns.Priority{-100, -1, 0, 1, 2, 3, 4, 5, 6, 9, 10, 11, 100} {
		wantPriority = fmt.Sprint(priority)
		if priority == 0 {
			wantPriority = "10"
		}
		_, err := client.Broadcast(context.Background(), apns.BroadcastRequest{BundleID: "com.example.app", ChannelID: broadcastChannelID, Payload: jsontext.Value(`{}`), Priority: priority, ExpiresAt: &expiration})
		valid := priority == 0 || priority == 5 || priority == 10
		if (err == nil) != valid {
			t.Errorf("priority %d error = %v", priority, err)
		}
	}
}

func TestBroadcastAndChannelValidationBeforeHTTP(t *testing.T) {
	var calls atomic.Int32
	client, err := apns.NewTokenClient(broadcastProvider(t), apns.Config{Environment: apns.Sandbox, Transport: apns.TransportConfig{DialContext: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("unexpected network")
	}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	valid := func() apns.BroadcastRequest {
		return apns.BroadcastRequest{BundleID: "com.example.app", ChannelID: broadcastChannelID, Payload: jsontext.Value(`{}`)}
	}
	beforeEpoch := time.Unix(-1, 0)
	future := time.Now().Add(time.Hour)
	noStorage := apns.MessageStorageNone
	invalidPolicy := apns.MessageStoragePolicy(2)
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"missing channel", func() error {
			r := valid()
			r.ChannelID = ""
			_, err := client.Broadcast(context.Background(), r)
			return err
		}},
		{"missing bundle", func() error {
			r := valid()
			r.BundleID = ""
			_, err := client.Broadcast(context.Background(), r)
			return err
		}},
		{"path injection", func() error {
			r := valid()
			r.BundleID = "com.app/secret"
			_, err := client.Broadcast(context.Background(), r)
			return err
		}},
		{"header injection", func() error {
			r := valid()
			r.ChannelID = "secret\r\nheader"
			_, err := client.Broadcast(context.Background(), r)
			return err
		}},
		{"bad JSON", func() error {
			r := valid()
			r.Payload = jsontext.Value(`{`)
			_, err := client.Broadcast(context.Background(), r)
			return err
		}},
		{"string is not raw", func() error {
			r := valid()
			r.Payload = `{}`
			_, err := client.Broadcast(context.Background(), r)
			return err
		}},
		{"pre-epoch", func() error {
			r := valid()
			r.ExpiresAt = &beforeEpoch
			_, err := client.Broadcast(context.Background(), r)
			return err
		}},
		{"incompatible storage", func() error {
			r := valid()
			r.ExpiresAt = &future
			r.MessageStoragePolicy = &noStorage
			_, err := client.Broadcast(context.Background(), r)
			return err
		}},
		{"unknown storage", func() error {
			r := valid()
			r.MessageStoragePolicy = &invalidPolicy
			_, err := client.Broadcast(context.Background(), r)
			return err
		}},
		{"get missing channel", func() error {
			_, err := client.GetChannel(context.Background(), apns.GetChannelRequest{BundleID: "com.example.app"})
			return err
		}},
		{"delete missing channel", func() error {
			_, err := client.DeleteChannel(context.Background(), apns.DeleteChannelRequest{BundleID: "com.example.app"})
			return err
		}},
		{"create missing bundle", func() error {
			_, err := client.CreateChannel(context.Background(), apns.CreateChannelRequest{})
			return err
		}},
		{"list missing bundle", func() error {
			_, err := client.ListChannels(context.Background(), apns.ListChannelsRequest{})
			return err
		}},
		{"create invalid policy", func() error {
			_, err := client.CreateChannel(context.Background(), apns.CreateChannelRequest{BundleID: "com.example.app", MessageStoragePolicy: invalidPolicy})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("invalid request accepted")
			}
			// Payloads that cannot be marshaled fail encoding, as they do for Push.
			want := "apns: validation failed"
			if tc.name == "bad JSON" {
				want = "apns: encoding failed"
			}
			if err.Error() != want || errors.Unwrap(err) == nil {
				t.Fatalf("invalid request error = %q, want wrapped %q", err, want)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid requests dialed %d times", calls.Load())
	}
}

func TestChannelOperationSpecificStatuses(t *testing.T) {
	for _, operation := range []string{"broadcast", "create", "get", "list", "delete"} {
		for _, status := range []int{200, 201, 202, 204, 307, 400, 403, 500} {
			t.Run(fmt.Sprintf("%s-%d", operation, status), func(t *testing.T) {
				client := broadcastServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("apns-request-id", broadcastRequestID)
					w.Header().Set("apns-unique-id", "operation-id")
					w.Header().Set("apns-channel-id", broadcastChannelID)
					w.WriteHeader(status)
					if status >= 400 {
						_, _ = io.WriteString(w, `{"reason":"FutureReason"}`)
					} else if operation == "get" {
						_, _ = io.WriteString(w, `{"message-storage-policy":0,"push-type":"LiveActivity"}`)
					} else if operation == "list" {
						_, _ = io.WriteString(w, `{"channels":[]}`)
					}
				}))
				var response apns.Response
				var err error
				wantStatus := 200
				switch operation {
				case "broadcast":
					response, err = client.Broadcast(context.Background(), apns.BroadcastRequest{BundleID: "com.example.app", ChannelID: broadcastChannelID, Payload: jsontext.Value(`{}`)})
				case "create":
					wantStatus = 201
					var result apns.CreateChannelResponse
					result, err = client.CreateChannel(context.Background(), apns.CreateChannelRequest{BundleID: "com.example.app"})
					response = result.Response
				case "get":
					var result apns.GetChannelResponse
					result, err = client.GetChannel(context.Background(), apns.GetChannelRequest{BundleID: "com.example.app", ChannelID: broadcastChannelID})
					response = result.Response
				case "list":
					var result apns.ListChannelsResponse
					result, err = client.ListChannels(context.Background(), apns.ListChannelsRequest{BundleID: "com.example.app"})
					response = result.Response
				case "delete":
					wantStatus = 204
					response, err = client.DeleteChannel(context.Background(), apns.DeleteChannelRequest{BundleID: "com.example.app", ChannelID: broadcastChannelID})
				}
				if response.StatusCode != status || response.RequestID != broadcastRequestID || response.APNSUniqueID != "operation-id" {
					t.Fatalf("metadata = %+v, error %v", response, err)
				}
				if status == wantStatus {
					if err != nil {
						t.Fatal(err)
					}
				} else if status >= 400 {
					rejection, ok := errors.AsType[*apns.Rejection](err)
					if !ok || rejection.Reason != apns.Reason("FutureReason") {
						t.Fatalf("want typed rejection, got %T %v", err, err)
					}
				} else if _, ok := errors.AsType[*apns.ResponseError](err); !ok {
					t.Fatalf("unexpected success/redirect status error = %T %v", err, err)
				}
			})
		}
	}
}

func TestChannelSuccessResponseValidation(t *testing.T) {
	for _, tc := range []struct {
		name, operation, body string
	}{
		{"create missing header", "create", ""},
		{"get empty", "get", ""},
		{"get malformed", "get", "{"},
		{"get null", "get", "null"},
		{"get no policy", "get", `{"push-type":"LiveActivity"}`},
		{"get no push type", "get", `{"message-storage-policy":0}`},
		{"get null policy", "get", `{"message-storage-policy":null,"push-type":"LiveActivity"}`},
		{"get invalid policy", "get", `{"message-storage-policy":2,"push-type":"LiveActivity"}`},
		{"get duplicate", "get", `{"message-storage-policy":0,"message-storage-policy":1,"push-type":"LiveActivity"}`},
		{"list empty", "list", ""},
		{"list malformed", "list", "{"},
		{"list null", "list", "null"},
		{"list no channels", "list", `{}`},
		{"list null channels", "list", `{"channels":null}`},
		{"list object", "list", `{"channels":{}}`},
		{"list null ID", "list", `{"channels":[null]}`},
		{"list empty ID", "list", `{"channels":[""]}`},
		{"list duplicate", "list", `{"channels":[],"channels":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := broadcastServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("apns-request-id", broadcastRequestID)
				if tc.operation == "create" {
					w.WriteHeader(http.StatusCreated)
				}
				_, _ = io.WriteString(w, tc.body)
			}))
			var err error
			switch tc.operation {
			case "create":
				_, err = client.CreateChannel(context.Background(), apns.CreateChannelRequest{BundleID: "com.example.app"})
			case "get":
				_, err = client.GetChannel(context.Background(), apns.GetChannelRequest{BundleID: "com.example.app", ChannelID: broadcastChannelID})
			case "list":
				_, err = client.ListChannels(context.Background(), apns.ListChannelsRequest{BundleID: "com.example.app"})
			}
			failure, ok := errors.AsType[*apns.ResponseError](err)
			if !ok || failure.Response.RequestID != broadcastRequestID {
				t.Fatalf("invalid success response = %T %v", err, err)
			}
		})
	}
}

func TestListChannelsResponseSize(t *testing.T) {
	channels := make([]string, 10000)
	for i := range channels {
		channels[i] = broadcastChannelID
	}
	data, err := json.Marshal(struct {
		Channels []string `json:"channels"`
	}{channels})
	if err != nil {
		t.Fatal(err)
	}
	var oversized bool
	client := broadcastServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("apns-request-id", broadcastRequestID)
		if oversized {
			_, _ = io.WriteString(w, strings.Repeat(" ", (4<<20)+1))
			return
		}
		_, _ = w.Write(data)
	}))
	result, err := client.ListChannels(context.Background(), apns.ListChannelsRequest{BundleID: "com.example.app"})
	if err != nil || len(result.ChannelIDs) != 10000 {
		t.Fatalf("large list = %d channels, %v", len(result.ChannelIDs), err)
	}
	oversized = true
	result, err = client.ListChannels(context.Background(), apns.ListChannelsRequest{BundleID: "com.example.app"})
	if failure, ok := errors.AsType[*apns.ResponseError](err); !ok || result.StatusCode != 200 || failure.Response.RequestID != broadcastRequestID {
		t.Fatalf("oversized list = %+v, %T %v", result.Response, err, err)
	}
}

func TestBroadcastAndChannelsRejectUninitializedClient(t *testing.T) {
	for _, client := range []*apns.Client{nil, {}} {
		for _, call := range []func() error{
			func() error {
				_, err := client.Broadcast(context.Background(), apns.BroadcastRequest{BundleID: "com.example.app", ChannelID: broadcastChannelID, Payload: jsontext.Value(`{}`)})
				return err
			},
			func() error {
				_, err := client.CreateChannel(context.Background(), apns.CreateChannelRequest{BundleID: "com.example.app"})
				return err
			},
			func() error {
				_, err := client.GetChannel(context.Background(), apns.GetChannelRequest{BundleID: "com.example.app", ChannelID: broadcastChannelID})
				return err
			},
			func() error {
				_, err := client.ListChannels(context.Background(), apns.ListChannelsRequest{BundleID: "com.example.app"})
				return err
			},
			func() error {
				_, err := client.DeleteChannel(context.Background(), apns.DeleteChannelRequest{BundleID: "com.example.app", ChannelID: broadcastChannelID})
				return err
			},
		} {
			if err := call(); err == nil {
				t.Fatal("uninitialized client accepted")
			}
		}
	}
}

func TestBroadcastKnownStoragePolicies(t *testing.T) {
	var calls atomic.Int32
	client := broadcastServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("apns-expiration") != "0" {
			t.Errorf("expiration = %q", r.Header.Get("apns-expiration"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	for _, policy := range []*apns.MessageStoragePolicy{nil, new(apns.MessageStorageNone), new(apns.MessageStorageMostRecent)} {
		for _, expiration := range []*time.Time{nil, new(time.Unix(0, 0))} {
			_, err := client.Broadcast(context.Background(), apns.BroadcastRequest{BundleID: "com.example.app", ChannelID: broadcastChannelID, Payload: jsontext.Value(`{}`), ExpiresAt: expiration, MessageStoragePolicy: policy})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if calls.Load() != 6 {
		t.Fatalf("requests = %d", calls.Load())
	}
}
