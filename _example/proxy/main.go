package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
)

func main() {
	certPath := flag.String("cert", "", "Path to .p12 certificate file (Required)")
	token := flag.String("token", "", "Push token (Required)")
	topic := flag.String("topic", "", "Topic (Required)")
	proxy := flag.String("proxy", "", "Proxy URL (Required)")
	flag.Parse()

	if *certPath == "" || *token == "" || *topic == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	certificate, certErr := certificate.FromP12File(*certPath, "")
	if certErr != nil {
		log.Fatal("Cert Error:", certErr)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
	}

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		Protocols:       protocols,
		Proxy: func(request *http.Request) (*url.URL, error) {
			return url.Parse(*proxy)
		},
		IdleConnTimeout: 60 * time.Second,
	}

	client := &apns2.Client{
		HTTPClient: &http.Client{
			Transport: transport,
			Timeout:   apns2.HTTPClientTimeout,
		},
		Certificate: certificate,
		Host:        apns2.DefaultHost,
	}

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
		log.Fatal("Error:", err)
	}

	fmt.Printf("%v %v %v\n", res.StatusCode, res.ApnsID, res.Reason)
}
