package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/jaakkonakaza/apns2"
	"github.com/jaakkonakaza/apns2/certificate"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	certPath := flag.String("cert", "", "Path to .p12 certificate file (Required)")
	token := flag.String("token", "", "Push token (Required)")
	topic := flag.String("topic", "", "Topic (Required)")
	flag.Parse()

	if *certPath == "" || *token == "" || *topic == "" {
		flag.PrintDefaults()
		return fmt.Errorf("required flags are missing")
	}

	cert, err := certificate.FromP12File(*certPath, "")
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}

	notification := &apns2.Notification{}
	notification.DeviceToken = *token
	notification.Topic = *topic
	notification.PushType = apns2.PushTypeAlert
	notification.Payload = []byte(`{
			"aps" : {
				"alert" : "Hello!"
			}
		}
	`)

	client, err := apns2.NewClient(cert, apns2.WithHost(apns2.HostProduction))
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
