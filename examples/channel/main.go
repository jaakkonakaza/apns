package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/jaakkonakaza/apns2"
	"github.com/jaakkonakaza/apns2/certificate"
	"github.com/jaakkonakaza/apns2/payload"
)

func main() {
	certPath := flag.String("cert", "", "Path to .p12 certificate file (Required)")
	// APNs answers TooManyRequests when one device token gets many pushes in a row.
	count := flag.Int("count", 10, "Number of pushes to send to the device token")
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

	notifications := make(chan *apns2.Notification, 100)
	responses := make(chan *apns2.Response, *count)

	client := apns2.NewClient(cert, apns2.WithHost(apns2.HostProduction))

	for range 50 {
		go worker(client, notifications, responses)
	}

	for i := 0; i < *count; i++ {
		n := &apns2.Notification{
			DeviceToken: *token,
			Topic:       *topic,
			PushType:    apns2.PushTypeAlert,
			Payload:     payload.NewPayload().Alert(fmt.Sprintf("Hello! %v", i)),
		}
		notifications <- n
	}

	for i := 0; i < *count; i++ {
		res := <-responses
		fmt.Printf("%v %v %v\n", res.StatusCode, res.ApnsID, res.Reason)
	}

	close(notifications)
	close(responses)
}

func worker(client *apns2.Client, notifications <-chan *apns2.Notification, responses chan<- *apns2.Response) {
	for n := range notifications {
		res, err := client.Push(context.Background(), n)
		if err != nil {
			log.Fatal("Push Error:", err)
		}
		responses <- res
	}
}
