package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"

	"github.com/jaakkonakaza/apns"
	"github.com/jaakkonakaza/apns/certificate"
	"github.com/jaakkonakaza/apns/payload"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, args []string, output, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("channel", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	certPath := flags.String("cert", "", "Path to .p12 certificate file (required)")
	deviceToken := flags.String("token", "", "Device token (required)")
	topic := flags.String("topic", "", "APNs topic (required)")
	count := flags.Int("count", 10, "Number of notifications to send")
	workers := flags.Int("workers", 4, "Maximum concurrent pushes")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *certPath == "" || *deviceToken == "" || *topic == "" || flags.NArg() != 0 {
		return fmt.Errorf("cert, token, and topic are required, with no positional arguments")
	}
	if *count < 1 || *workers < 1 {
		return fmt.Errorf("count and workers must be positive")
	}
	cert, err := certificate.FromP12File(*certPath, "")
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}
	client, err := apns.NewCertificateClient(cert, apns.Config{Environment: apns.Production})
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := sendNotifications(ctx, client, *count, min(*workers, *count), func(i int) apns.Request {
		return apns.Request{
			DeviceToken: *deviceToken,
			Topic:       *topic,
			PushType:    apns.PushTypeAlert,
			Payload:     payload.Notification{APS: payload.APS{Alert: &payload.Alert{Body: fmt.Sprintf("Hello! %d", i)}}},
		}
	})
	defer func() {
		cancel()
		for range results {
		}
	}()
	failed := 0
	for result := range results {
		if result.Err != nil {
			failed++
			if _, err := fmt.Fprintf(output, "%d: %v\n", result.Index, result.Err); err != nil {
				return err
			}
			continue
		}
		response := result.Response
		if _, err := fmt.Fprintf(output, "%d: %d %s\n", result.Index, response.StatusCode, response.APNSID); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if failed != 0 {
		return fmt.Errorf("%d of %d notifications failed", failed, *count)
	}
	return nil
}

type pusher interface {
	Push(context.Context, apns.Request) (apns.Response, error)
}

type sendResult struct {
	Index    int
	Response apns.Response
	Err      error
}

// sendNotifications bounds work and buffered results by the worker count.
// The caller drains results or cancels ctx before returning.
func sendNotifications(ctx context.Context, client pusher, count, workers int, notification func(int) apns.Request) <-chan sendResult {
	jobs := make(chan int)
	results := make(chan sendResult, workers)
	var pending sync.WaitGroup
	pending.Go(func() {
		defer close(jobs)
		for i := range count {
			select {
			case jobs <- i:
			case <-ctx.Done():
				return
			}
		}
	})
	for range workers {
		pending.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case i, ok := <-jobs:
					if !ok {
						return
					}
					response, err := client.Push(ctx, notification(i))
					select {
					case results <- sendResult{Index: i, Response: response, Err: err}:
					case <-ctx.Done():
						return
					}
				}
			}
		})
	}
	go func() {
		pending.Wait()
		close(results)
	}()
	return results
}
