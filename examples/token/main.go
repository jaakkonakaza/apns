package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/jaakkonakaza/apns"
	"github.com/jaakkonakaza/apns/payload"
	"github.com/jaakkonakaza/apns/token"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	authKeyPath := flag.String("authKey", "", "Path to .p8 APNSAuthKey file (Required)")
	deviceToken := flag.String("token", "", "Push token (Required)")
	topic := flag.String("topic", "", "Topic (Required)")
	keyID := flag.String("keyID", "", "APNS KeyID (Required)")
	teamID := flag.String("teamID", "", "APNS TeamID (Required)")
	flag.Parse()

	if *authKeyPath == "" || *deviceToken == "" || *topic == "" || *keyID == "" || *teamID == "" {
		flag.PrintDefaults()
		return fmt.Errorf("required flags are missing")
	}

	authKey, err := token.AuthKeyFromFile(*authKeyPath)
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}

	provider, err := token.New(authKey, *keyID, *teamID)
	if err != nil {
		return err
	}

	notification := apns.Request{DeviceToken: *deviceToken, Topic: *topic, PushType: apns.PushTypeAlert, Payload: payload.Notification{APS: payload.APS{Alert: &payload.Alert{Body: "Hello!"}}}}

	client, err := apns.NewTokenClient(provider, apns.Config{Environment: apns.Production})
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	res, err := client.Push(context.Background(), notification)
	if err != nil {
		return fmt.Errorf("push notification: %w", err)
	}

	if _, err := fmt.Printf("%v %v\n", res.StatusCode, res.APNSID); err != nil {
		return err
	}
	return nil
}
