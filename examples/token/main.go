package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/jaakkonakaza/apns"
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

	notification := &apns.Notification{}
	notification.DeviceToken = *deviceToken
	notification.Topic = *topic
	notification.PushType = apns.PushTypeAlert
	notification.Payload = []byte(`{
			"aps" : {
				"alert" : "Hello!"
			}
		}
	`)

	client, err := apns.NewTokenClient(provider, apns.WithHost(apns.HostProduction))
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	res, err := client.Push(context.Background(), notification)
	if err != nil {
		return fmt.Errorf("push notification: %w", err)
	}

	if _, err := fmt.Printf("%v %v %v\n", res.StatusCode, res.APNSID, res.Reason); err != nil {
		return err
	}
	if !res.Success() {
		return fmt.Errorf("APNs rejected notification: %s", res.Reason)
	}
	return nil
}
