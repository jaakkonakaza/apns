package apns2_test

import (
	"context"
	"errors"
	"testing"

	apns "github.com/jaakkonakaza/apns2"
)

// The stubs fail loudly until they are implemented.
func TestBroadcastStubsNotImplemented(t *testing.T) {
	client := apns.NewBroadcastTokenClient(mockToken())
	defer client.CloseIdleConnections()
	if client.Host != "" || client.ChannelHost != "" {
		t.Errorf("hosts = %q, %q, want no default", client.Host, client.ChannelHost)
	}
	ctx := context.Background()
	for name, call := range map[string]func() error{
		"Push": func() error {
			_, err := client.Push(ctx, &apns.BroadcastNotification{})
			return err
		},
		"CreateChannel": func() error {
			_, err := client.CreateChannel(ctx, &apns.ChannelRequest{BundleID: "com.example.app"}, apns.MessageStorageNone)
			return err
		},
		"GetChannel": func() error {
			_, err := client.GetChannel(ctx, &apns.ChannelRequest{BundleID: "com.example.app", ChannelID: "dHN0LXNyY2gtY2hubA=="})
			return err
		},
		"DeleteChannel": func() error {
			_, err := client.DeleteChannel(ctx, &apns.ChannelRequest{BundleID: "com.example.app", ChannelID: "dHN0LXNyY2gtY2hubA=="})
			return err
		},
		"ListChannels": func() error {
			_, err := client.ListChannels(ctx, &apns.ChannelRequest{BundleID: "com.example.app"})
			return err
		},
	} {
		if err := call(); !errors.Is(err, apns.ErrNotImplemented) {
			t.Errorf("%s error = %v, want ErrNotImplemented", name, err)
		}
	}
}

func TestClientManagerGetByTokenNotImplemented(t *testing.T) {
	defer func() {
		if err, _ := recover().(error); !errors.Is(err, apns.ErrNotImplemented) {
			t.Errorf("panic = %v, want ErrNotImplemented", err)
		}
	}()
	apns.NewClientManager().GetByToken(mockToken())
}

func TestBroadcastResponseSuccess(t *testing.T) {
	for status, want := range map[int]bool{200: true, 201: true, 204: true, 400: false, 410: false} {
		r := &apns.BroadcastResponse{Response: apns.Response{StatusCode: status}}
		if got := r.Success(); got != want {
			t.Errorf("Success() for %d = %v, want %v", status, got, want)
		}
	}
}
