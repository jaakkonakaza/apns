package apns_test

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"log"
	"time"

	"github.com/jaakkonakaza/apns"
	"github.com/jaakkonakaza/apns/certificate"
	"github.com/jaakkonakaza/apns/payload"
	"github.com/jaakkonakaza/apns/token"
)

func ExampleNotification() {
	type progress struct {
		Counter int    `json:"counter"`
		Message string `json:"message"`
	}
	notification := &apns.Notification{
		DeviceToken: "aabbcc",
		Topic:       "com.example.app.push-type.liveactivity",
		PushType:    apns.PushTypeLiveActivity,
		Payload: payload.NewPayload().
			ContentState(progress{Counter: 7, Message: "Arriving soon"}).
			Event(payload.LiveActivityEventUpdate).
			Timestamp(time.Unix(1700000000, 0)),
	}
	data, err := json.Marshal(notification)
	if err != nil {
		log.Print(err)
		return
	}
	fmt.Println(string(data))
	// Output: {"aps":{"content-state":{"counter":7,"message":"Arriving soon"},"event":"update","timestamp":1700000000}}
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
	client, err := apns.NewTokenClient(provider, apns.WithHost(apns.HostDevelopment))
	if err != nil {
		log.Print(err)
		return
	}
	defer client.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, err := client.Push(ctx, &apns.Notification{
		DeviceToken: "aabbcc",
		Topic:       "com.example.app",
		PushType:    apns.PushTypeAlert,
		Payload:     payload.NewPayload().Alert("Hello"),
	})
	if err != nil {
		log.Print(err)
		return
	}
	fmt.Println(response.Success(), response.Reason)
}

func ExampleNewClient() {
	cert, err := certificate.FromPEMFile("provider.pem")
	if err != nil {
		log.Print(err)
		return
	}
	client, err := apns.NewClient(cert, apns.WithHost(apns.HostProduction))
	if err != nil {
		log.Print(err)
		return
	}
	defer client.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, err := client.Push(ctx, &apns.Notification{
		DeviceToken: "aabbcc",
		Topic:       "com.example.app",
		PushType:    apns.PushTypeBackground,
		Payload:     payload.NewPayload().ContentAvailable(),
	})
	if err != nil {
		log.Print(err)
		return
	}
	fmt.Println(response.Success(), response.Reason)
}

func ExampleBroadcastClient_CreateChannel() {
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
	client, err := apns.NewBroadcastTokenClient(provider, apns.DevelopmentBroadcastEndpoints())
	if err != nil {
		log.Print(err)
		return
	}
	defer client.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	channel, err := client.CreateChannel(ctx,
		&apns.ChannelRequest{BundleID: "com.example.app"}, apns.MessageStorageNone)
	if err != nil {
		log.Print(err)
		return
	}
	if !channel.Success() {
		log.Print(channel.Reason)
		return
	}
	fmt.Println(channel.ChannelID)

	deleted, err := client.DeleteChannel(ctx,
		&apns.ChannelRequest{BundleID: "com.example.app", ChannelID: channel.ChannelID})
	if err != nil {
		log.Print(err)
		return
	}
	fmt.Println(deleted.Success(), deleted.Reason)
}

func ExampleClientManager_RemoveByToken() {
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
	manager, err := apns.NewClientManager(apns.ManagerConfig{Host: apns.HostProduction})
	if err != nil {
		log.Print(err)
		return
	}
	defer manager.CloseIdleConnections()
	client, err := manager.GetByToken(provider)
	if err != nil {
		log.Print(err)
		return
	}

	// Remove a cached connection when its credential or topic access changes.
	removed, err := manager.RemoveByToken(provider)
	if err != nil {
		log.Print(err)
		return
	}
	replacement, err := manager.GetByToken(provider)
	if err != nil {
		log.Print(err)
		return
	}
	fmt.Println(removed, client != replacement)
}
