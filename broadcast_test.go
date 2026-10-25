package apns2_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	apns "github.com/jaakkonakaza/apns2"
	"github.com/jaakkonakaza/apns2/token"
)

const (
	broadcastRequestID = "2288cf3f-70d8-46a6-97d7-dd5d00867127"
	broadcastChannelID = "dHN0LXNyY2gtY2hubA=="
)

func TestBroadcastAndChannelRequests(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body, response string
		channel                            bool
		status                             int
		call                               func(*apns.BroadcastClient) (*apns.BroadcastResponse, error)
	}{
		{
			"push", http.MethodPost, "/4/broadcasts/apps/com.example.app", `{"aps":{"event":"update"}}`, "", true, 200,
			func(c *apns.BroadcastClient) (*apns.BroadcastResponse, error) {
				return c.Push(context.Background(), &apns.BroadcastNotification{BundleID: "com.example.app", ChannelID: broadcastChannelID, RequestID: broadcastRequestID, Payload: `{"aps":{"event":"update"}}`})
			},
		},
		{
			"create", http.MethodPost, "/1/apps/com.example.app/channels", `{"message-storage-policy":0,"push-type":"LiveActivity"}`, "", false, 201,
			func(c *apns.BroadcastClient) (*apns.BroadcastResponse, error) {
				r, err := c.CreateChannel(context.Background(), &apns.ChannelRequest{BundleID: "com.example.app", RequestID: broadcastRequestID, ChannelID: "ignored"}, apns.MessageStorageNone)
				if err == nil && r.ChannelID != broadcastChannelID {
					t.Errorf("created channel = %q", r.ChannelID)
				}
				if r == nil {
					return nil, err
				}
				return &r.BroadcastResponse, err
			},
		},
		{
			"get", http.MethodGet, "/1/apps/com.example.app/channels", "", `{"message-storage-policy":1,"push-type":"LiveActivity"}`, true, 200,
			func(c *apns.BroadcastClient) (*apns.BroadcastResponse, error) {
				r, err := c.GetChannel(context.Background(), &apns.ChannelRequest{BundleID: "com.example.app", RequestID: broadcastRequestID, ChannelID: broadcastChannelID})
				if err == nil && (r.MessageStoragePolicy != apns.MessageStorageMostRecent || r.PushType != "LiveActivity") {
					t.Errorf("channel configuration = %+v", r)
				}
				if r == nil {
					return nil, err
				}
				return &r.BroadcastResponse, err
			},
		},
		{
			"delete", http.MethodDelete, "/1/apps/com.example.app/channels", "", "", true, 204,
			func(c *apns.BroadcastClient) (*apns.BroadcastResponse, error) {
				r, err := c.DeleteChannel(context.Background(), &apns.ChannelRequest{BundleID: "com.example.app", RequestID: broadcastRequestID, ChannelID: broadcastChannelID})
				if r == nil {
					return nil, err
				}
				return &r.BroadcastResponse, err
			},
		},
		{
			"list", http.MethodGet, "/1/apps/com.example.app/all-channels", "", `{"channels":["dHN0LXNyY2gtY2hubA=="]}`, false, 200,
			func(c *apns.BroadcastClient) (*apns.BroadcastResponse, error) {
				r, err := c.ListChannels(context.Background(), &apns.ChannelRequest{BundleID: "com.example.app", RequestID: broadcastRequestID, ChannelID: "ignored"})
				if err == nil && (len(r.ChannelIDs) != 1 || r.ChannelIDs[0] != broadcastChannelID) {
					t.Errorf("channels = %v", r.ChannelIDs)
				}
				if r == nil {
					return nil, err
				}
				return &r.BroadcastResponse, err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 || r.Method != tc.method || r.URL.Path != tc.path {
					t.Errorf("request = %s %s %s", r.Proto, r.Method, r.URL)
				}
				if !strings.HasPrefix(r.Header.Get("authorization"), "bearer ") || r.Header.Get("apns-request-id") != broadcastRequestID {
					t.Error("missing token authentication or request identifier")
				}
				if got := r.Header.Get("apns-channel-id"); tc.channel && got != broadcastChannelID || !tc.channel && got != "" {
					t.Errorf("channel header = %q", got)
				}
				if tc.name == "push" {
					for key, want := range map[string]string{"apns-push-type": "liveactivity", "apns-priority": "10", "apns-expiration": "0"} {
						if got := r.Header.Get(key); got != want {
							t.Errorf("%s = %q, want %q", key, got, want)
						}
					}
				} else if r.Header.Get("apns-push-type") != "" {
					t.Error("channel management sent a push type header")
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if string(body) != tc.body {
					t.Errorf("body = %s, want %s", body, tc.body)
				}
				w.Header().Set("apns-request-id", broadcastRequestID)
				w.Header().Set("apns-channel-id", broadcastChannelID)
				w.Header().Set("apns-unique-id", "unique-id")
				w.WriteHeader(tc.status)
				if tc.response != "" {
					_, _ = io.WriteString(w, tc.response)
				}
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			client := apns.NewBroadcastTokenClient(mockToken(), apns.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig))
			client.Host, client.ChannelHost = server.URL, server.URL
			defer client.CloseIdleConnections()
			response, err := tc.call(client)
			if err != nil || response == nil || response.StatusCode != tc.status || !response.Success() || response.RequestID != broadcastRequestID || response.ApnsUniqueID != "unique-id" {
				t.Fatalf("response = %+v, error = %v", response, err)
			}
		})
	}
}

func TestBroadcastPushHeadersAndPayloadLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apns-priority") != "1" || r.Header.Get("apns-expiration") != "1234567890" {
			t.Error("non-default broadcast headers missing")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := apns.NewBroadcastTokenClient(mockToken(), apns.WithHTTPClient(server.Client()))
	client.Host = server.URL
	n := &apns.BroadcastNotification{BundleID: "com.example.app", ChannelID: broadcastChannelID, Payload: []byte(`{"aps":{}}`), Priority: apns.PriorityPowerSaving, Expiration: time.Unix(1234567890, 0)}
	if _, err := client.Push(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	n.Payload = `{"aps":{},"padding":"` + strings.Repeat("a", 5120) + `"}`
	if _, err := client.Push(context.Background(), n); err == nil {
		t.Fatal("oversized payload accepted")
	}
}

func TestBroadcastRejectsInvalidRequestsBeforeSending(t *testing.T) {
	var requests atomic.Int32
	client := apns.NewBroadcastTokenClient(mockToken(), apns.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("unexpected request")
	})}))
	client.Host, client.ChannelHost = "https://example.com", "https://example.com"
	valid := func() *apns.BroadcastNotification {
		return &apns.BroadcastNotification{BundleID: "com.example.app", ChannelID: broadcastChannelID, Payload: `{"aps":{}}`}
	}
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"nil push", func() error { _, err := client.Push(context.Background(), nil); return err }},
		{"missing channel", func() error {
			n := valid()
			n.ChannelID = ""
			_, err := client.Push(context.Background(), n)
			return err
		}},
		{"missing bundle", func() error {
			n := valid()
			n.BundleID = ""
			_, err := client.Push(context.Background(), n)
			return err
		}},
		{"bad request ID", func() error {
			n := valid()
			n.RequestID = "invalid"
			_, err := client.Push(context.Background(), n)
			return err
		}},
		{"bad priority", func() error { n := valid(); n.Priority = 3; _, err := client.Push(context.Background(), n); return err }},
		{"bad JSON", func() error {
			n := valid()
			n.Payload = "{"
			_, err := client.Push(context.Background(), n)
			return err
		}},
		{"nil channel request", func() error { _, err := client.ListChannels(context.Background(), nil); return err }},
		{"missing get channel", func() error {
			_, err := client.GetChannel(context.Background(), &apns.ChannelRequest{BundleID: "com.example.app"})
			return err
		}},
		{"missing delete channel", func() error {
			_, err := client.DeleteChannel(context.Background(), &apns.ChannelRequest{BundleID: "com.example.app"})
			return err
		}},
		{"bad storage policy", func() error {
			_, err := client.CreateChannel(context.Background(), &apns.ChannelRequest{BundleID: "com.example.app"}, 2)
			return err
		}},
		{"missing host", func() error {
			c := apns.NewBroadcastTokenClient(mockToken())
			_, err := c.ListChannels(context.Background(), &apns.ChannelRequest{BundleID: "com.example.app"})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	if requests.Load() != 0 {
		t.Fatalf("invalid requests reached network %d times", requests.Load())
	}
}

func TestBroadcastResponseErrorsPreserveMetadata(t *testing.T) {
	for _, body := range []string{`{"reason":"BadChannelId"}`, `{`, `{"reason":"first","reason":"second"}`, strings.Repeat("x", 65537)} {
		t.Run(fmt.Sprintf("body-size-%d", len(body)), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("apns-request-id", broadcastRequestID)
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			client := apns.NewBroadcastTokenClient(mockToken(), apns.WithHTTPClient(server.Client()))
			client.ChannelHost = server.URL
			response, err := client.GetChannel(context.Background(), &apns.ChannelRequest{BundleID: "com.example.app", ChannelID: broadcastChannelID})
			if response == nil || response.StatusCode != 400 || response.RequestID != broadcastRequestID {
				t.Fatalf("response metadata lost: %+v", response)
			}
			if strings.Contains(body, "BadChannelId") {
				if err != nil || response.Reason != apns.ReasonBadChannelID {
					t.Fatalf("rejection = %+v, %v", response, err)
				}
			} else if err == nil {
				t.Fatal("bad response body accepted")
			}
		})
	}
}

func TestListChannelsExceedsPushResponseLimit(t *testing.T) {
	channels := make([]string, 10000)
	for i := range channels {
		channels[i] = broadcastChannelID
	}
	body, err := json.Marshal(map[string]any{"channels": channels})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
	defer server.Close()
	client := apns.NewBroadcastTokenClient(mockToken(), apns.WithHTTPClient(server.Client()))
	client.ChannelHost = server.URL
	response, err := client.ListChannels(context.Background(), &apns.ChannelRequest{BundleID: "com.example.app"})
	if err != nil || response == nil || len(response.ChannelIDs) != len(channels) {
		t.Fatalf("large list = %+v, %v", response, err)
	}
}

func TestBroadcastInvalidatesRejectedRestoredToken(t *testing.T) {
	provider := mockToken()
	provider.Restore("rejected-bearer", time.Now().Add(-25*time.Minute))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "bearer rejected-bearer" {
			t.Error("restored token was not sent")
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"reason":"ExpiredProviderToken"}`)
	}))
	defer server.Close()
	client := apns.NewBroadcastTokenClient(provider, apns.WithHTTPClient(server.Client()))
	client.ChannelHost = server.URL
	if _, err := client.ListChannels(context.Background(), &apns.ChannelRequest{BundleID: "com.example.app"}); err != nil {
		t.Fatal(err)
	}
	if bearer, err := provider.Bearer(); err != nil || bearer == "rejected-bearer" {
		t.Fatal("rejected token was not invalidated")
	}
}

func TestBroadcastSigningAndCancellationErrors(t *testing.T) {
	client := apns.NewBroadcastTokenClient(&token.Token{}, apns.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("request sent after signing failed")
		return nil, errors.New("unexpected request")
	})}))
	client.ChannelHost = "https://example.com"
	if _, err := client.ListChannels(context.Background(), &apns.ChannelRequest{BundleID: "com.example.app"}); !errors.Is(err, token.ErrAuthKeyNil) {
		t.Fatalf("signing error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client = apns.NewBroadcastTokenClient(mockToken())
	client.ChannelHost = "https://example.com"
	if _, err := client.ListChannels(ctx, &apns.ChannelRequest{BundleID: "com.example.app"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestBroadcastResponseSuccess(t *testing.T) {
	for status, want := range map[int]bool{200: true, 201: true, 204: true, 400: false, 410: false} {
		r := &apns.BroadcastResponse{}
		r.StatusCode = status
		if got := r.Success(); got != want {
			t.Errorf("Success() for %d = %v, want %v", status, got, want)
		}
	}
}
