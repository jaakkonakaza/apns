package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/jaakkonakaza/apns2"
	"github.com/jaakkonakaza/apns2/certificate"
)

func main() {
	certPath := flag.String("cert", "", "Path to .p12 certificate file (Required)")
	token := flag.String("token", "", "Push token (Required)")
	topic := flag.String("topic", "", "Topic (Required)")
	flag.Parse()

	if *certPath == "" || *token == "" || *topic == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	cert, err := certificate.FromP12File(*certPath, "")
	if err != nil {
		log.Fatal("Cert Error:", err)
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

	client := apns2.NewClient(cert, apns2.WithHost(apns2.HostProduction))
	res, err := client.Push(context.Background(), notification)
	if err != nil {
		log.Fatal("Error:", err)
	}

	fmt.Printf("%v %v %v\n", res.StatusCode, res.ApnsID, res.Reason)
}
