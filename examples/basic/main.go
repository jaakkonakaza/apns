package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/jaakkonakaza/apns"
	"github.com/jaakkonakaza/apns/certificate"
	"github.com/jaakkonakaza/apns/payload"
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

	notification := apns.Request{DeviceToken: *token, Topic: *topic, PushType: apns.PushTypeAlert, Payload: payload.Notification{APS: payload.APS{Alert: &payload.Alert{Body: "Hello!"}}}}

	client, err := apns.NewCertificateClient(cert, apns.Config{Environment: apns.Production})
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
