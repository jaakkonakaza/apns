package apns_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jaakkonakaza/apns"
	"github.com/jaakkonakaza/apns/cache"
	"github.com/jaakkonakaza/apns/certificate"
	"github.com/jaakkonakaza/apns/payload"
	"github.com/jaakkonakaza/apns/token"
)

func ExampleRequest() {
	body := payload.Notification{APS: payload.APS{Alert: &payload.Alert{Body: "Hello"}, Badge: new(0)}, Custom: map[string]any{"orderID": "123"}}
	data, err := json.Marshal(body)
	if err != nil {
		log.Print(err)
		return
	}
	var decoded struct {
		APS struct {
			Badge int `json:"badge"`
		}
		OrderID string `json:"orderID"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		log.Print(err)
		return
	}
	fmt.Println(decoded.APS.Badge, decoded.OrderID)
	// Output: 0 123
}

func ExampleNewTokenClient() {
	key, err := token.AuthKeyFromFile("AuthKey.p8")
	if err != nil {
		log.Print(err)
		return
	}
	provider, err := token.New(key, "KEY_ID", "TEAM_ID")
	if err != nil {
		log.Print(err)
		return
	}
	client, err := apns.NewTokenClient(provider, apns.Config{Environment: apns.Sandbox})
	if err != nil {
		log.Print(err)
		return
	}
	defer client.CloseIdleConnections()
	response, err := client.Push(context.Background(), apns.Request{DeviceToken: "aabbcc", Topic: "com.example.app", PushType: apns.PushTypeAlert, Payload: payload.Notification{APS: payload.APS{Alert: &payload.Alert{Body: "Hello"}}}})
	if err != nil {
		if rejection, ok := errors.AsType[*apns.Rejection](err); ok {
			log.Printf("APNs rejected request (status %d)", rejection.Response.StatusCode)
		} else {
			log.Print(err)
		}
		return
	}
	fmt.Println("APNs accepted", response.APNSID)
}

func ExampleNewCertificateClient() {
	cert, err := certificate.FromPEMFile("provider.pem")
	if err != nil {
		log.Print(err)
		return
	}
	client, err := apns.NewCertificateClient(cert, apns.Config{Environment: apns.Production})
	if err != nil {
		log.Print(err)
		return
	}
	defer client.CloseIdleConnections()
	response, err := client.Push(context.Background(), apns.Request{DeviceToken: "aabbcc", Topic: "com.example.app", PushType: apns.PushTypeBackground, Payload: payload.Background{Custom: map[string]any{"revision": 7}}})
	if err != nil {
		log.Print(err)
		return
	}
	fmt.Println("APNs accepted", response.APNSID)
}

func ExampleClient_CreateChannel() {
	key, err := token.AuthKeyFromFile("AuthKey.p8")
	if err != nil {
		log.Print(err)
		return
	}
	provider, err := token.New(key, "KEY_ID", "TEAM_ID")
	if err != nil {
		log.Print(err)
		return
	}
	client, err := apns.NewTokenClient(provider, apns.Config{Environment: apns.Sandbox})
	if err != nil {
		log.Print(err)
		return
	}
	defer client.CloseIdleConnections()
	channel, err := client.CreateChannel(context.Background(), apns.CreateChannelRequest{BundleID: "com.example.app", MessageStoragePolicy: apns.MessageStorageNone})
	if err != nil {
		log.Print(err)
		return
	}
	// Publish only after the app subscribes to this channel.
	type state struct {
		Counter int `json:"counter"`
	}
	_, err = client.Broadcast(context.Background(), apns.BroadcastRequest{BundleID: "com.example.app", ChannelID: channel.ChannelID, MessageStoragePolicy: new(apns.MessageStorageNone), Payload: payload.ActivityUpdate[state]{Timestamp: time.Now(), State: state{Counter: 7}}})
	if err != nil {
		log.Print(err)
	}
	_, err = client.DeleteChannel(context.Background(), apns.DeleteChannelRequest{BundleID: "com.example.app", ChannelID: channel.ChannelID})
	if err != nil {
		log.Print(err)
	}
}

func Example_multipleIdentities() {
	key, err := token.AuthKeyFromFile("AuthKey.p8")
	if err != nil {
		log.Print(err)
		return
	}
	provider, err := token.New(key, "KEY_ID", "TEAM_ID")
	if err != nil {
		log.Print(err)
		return
	}
	clients, err := cache.New(cache.Config{Client: apns.Config{Environment: apns.Production}, MaxEntries: 16})
	if err != nil {
		log.Print(err)
		return
	}
	defer clients.Clear()
	client, err := clients.Token(provider)
	if err != nil {
		log.Print(err)
		return
	}
	removed, err := clients.RemoveToken(provider)
	if err != nil {
		log.Print(err)
		return
	}
	replacement, err := clients.Token(provider)
	if err != nil {
		log.Print(err)
		return
	}
	fmt.Println(removed, client != replacement)
}
