package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
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
		return fmt.Errorf("parse proxy URL: %w", err)
	}
	client := apns2.NewClient(certificate)
	defer client.CloseIdleConnections()
	transport := client.HTTPClient.Transport.(*http.Transport)
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.IdleConnTimeout = 60 * time.Second

	notification := &apns2.Notification{}
	notification.DeviceToken = *token
	notification.Topic = *topic
	notification.Payload = []byte(`{
			"aps" : {
				"alert" : "Hello!"
			}
		}
	`)

	res, err := client.Push(notification)
	if err != nil {
		return fmt.Errorf("push notification: %w", err)
	}

	_, err = fmt.Printf("%v %v %v\n", res.StatusCode, res.ApnsID, res.Reason)
	return err
}
