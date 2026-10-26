package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

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
	proxy := flag.String("proxy", "", "Proxy URL (Required)")
	flag.Parse()

	if *certPath == "" || *token == "" || *topic == "" || *proxy == "" {
		flag.PrintDefaults()
		return fmt.Errorf("cert, token, topic, and proxy are required")
	}

	certificate, certErr := certificate.FromP12File(*certPath, "")
	if certErr != nil {
		return fmt.Errorf("load certificate: %w", certErr)
	}

	proxyURL, err := url.Parse(*proxy)
	if err != nil {
		return fmt.Errorf("invalid proxy URL")
	}
	client, err := apns.NewCertificateClient(certificate, apns.Config{Environment: apns.Production, Transport: apns.TransportConfig{Proxy: http.ProxyURL(proxyURL), IdleConnTimeout: new(60 * time.Second)}})
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()

	notification := apns.Request{DeviceToken: *token, Topic: *topic, PushType: apns.PushTypeAlert, Payload: payload.Notification{APS: payload.APS{Alert: &payload.Alert{Body: "Hello!"}}}}

	res, err := client.Push(context.Background(), notification)
	if err != nil {
		return fmt.Errorf("push notification: %w", err)
	}

	if _, err := fmt.Printf("%v %v\n", res.StatusCode, res.APNSID); err != nil {
		return err
	}
	return nil
}
