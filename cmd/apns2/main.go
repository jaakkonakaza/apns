package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		log.Fatal(err)
	}
}

func run(args []string, input io.Reader, output, diagnostics io.Writer, options ...apns2.ClientOption) error {
	flags := flag.NewFlagSet("apns2", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var certificatePath, topic, mode string
	var version bool
	flags.StringVar(&certificatePath, "certificate-path", "", "Path to a combined PEM certificate (required).")
	flags.StringVar(&topic, "topic", "", "APNs topic, typically the app bundle ID (required).")
	flags.StringVar(&mode, "mode", "production", "APNs server: production or development.")
	flags.BoolVar(&version, "version", false, "Show application version.")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(diagnostics, "Usage: apns2 --certificate-path=PATH --topic=TOPIC [flags]\nReads STDIN lines formatted as: <DeviceToken> <APNs Payload>")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if version {
		_, err := fmt.Fprintln(output, "0.1")
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("positional arguments are not supported")
	}
	if certificatePath == "" || topic == "" {
		return fmt.Errorf("certificate-path and topic are required")
	}
	if mode != "production" && mode != "development" {
		return fmt.Errorf("mode must be production or development")
	}
	cert, err := certificate.FromPemFile(certificatePath)
	if err != nil {
		return fmt.Errorf("load certificate %q: %w", certificatePath, err)
	}
	host := apns2.HostProduction
	if mode == "development" {
		host = apns2.HostDevelopment
	}
	options = append([]apns2.ClientOption{apns2.WithHost(host)}, options...)
	client := apns2.NewClient(cert, options...)
	defer client.CloseIdleConnections()
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		deviceToken, payload, ok := strings.Cut(strings.TrimSpace(scanner.Text()), " ")
		payload = strings.TrimSpace(payload)
		if !ok || deviceToken == "" || payload == "" {
			return fmt.Errorf("expected <DeviceToken> <APNs Payload>")
		}
		res, err := client.Push(context.Background(), &apns2.Notification{DeviceToken: deviceToken, Topic: topic, Payload: payload})
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(output, "%v: '%v'\n", res.StatusCode, res.Reason); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read notifications: %w", err)
	}
	return nil
}
