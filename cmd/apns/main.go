// Apns sends push notifications to APNs from standard input.
//
// Each input line holds a device token and a JSON payload separated by a space:
//
//	apns --topic=com.example.app --auth-key-path=AuthKey.p8 --key-id=KEY_ID --team-id=TEAM_ID < pushes.txt
//
// It prints the response status for each notification, with the reason for
// rejections. Run apns --help for all flags.
package main

import (
	"bufio"
	"context"
	"encoding/json/jsontext"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/jaakkonakaza/apns"
	"github.com/jaakkonakaza/apns/certificate"
	"github.com/jaakkonakaza/apns/token"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		log.Fatal(err)
	}
}

func run(args []string, input io.Reader, output, diagnostics io.Writer, configs ...apns.Config) error {
	flags := flag.NewFlagSet("apns", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var certificatePath, authKeyPath, keyID, teamID, topic, mode, pushType string
	var priority int
	var version bool
	flags.StringVar(&certificatePath, "certificate-path", "", "Path to a combined PEM certificate.")
	flags.StringVar(&authKeyPath, "auth-key-path", "", "Path to an APNs .p8 signing key.")
	flags.StringVar(&keyID, "key-id", "", "Signing key ID (required with auth-key-path).")
	flags.StringVar(&teamID, "team-id", "", "Developer team ID (required with auth-key-path).")
	flags.StringVar(&topic, "topic", "", "APNs topic, typically the app bundle ID (required).")
	flags.StringVar(&mode, "mode", "production", "APNs server: production or development.")
	flags.StringVar(&pushType, "push-type", string(apns.PushTypeAlert), "apns-push-type header; it must match the payload.")
	flags.IntVar(&priority, "priority", 0, "APNs priority: 1, 5 or 10 (0 uses the push type default).")
	flags.BoolVar(&version, "version", false, "Show application version.")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(diagnostics, "Usage: apns --topic=TOPIC [authentication flags] [flags]\nReads STDIN lines formatted as: <DeviceToken> <APNs Payload>")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if version {
		_, err := fmt.Fprintln(output, applicationVersion())
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("positional arguments are not supported")
	}
	if topic == "" {
		return fmt.Errorf("topic is required")
	}
	if certificatePath != "" && (authKeyPath != "" || keyID != "" || teamID != "") {
		return fmt.Errorf("certificate-path cannot be combined with token authentication flags")
	}
	if certificatePath == "" && (authKeyPath == "" || keyID == "" || teamID == "") {
		return fmt.Errorf("provide certificate-path or all of auth-key-path, key-id and team-id")
	}
	switch apns.Priority(priority) {
	case 0, apns.PriorityPowerSaving, apns.PriorityLow, apns.PriorityHigh:
	default:
		return fmt.Errorf("priority must be 0, 1, 5 or 10")
	}
	if mode != "production" && mode != "development" {
		return fmt.Errorf("mode must be production or development")
	}
	cfg := apns.Config{Environment: apns.Production}
	if len(configs) > 1 {
		return fmt.Errorf("at most one client configuration is supported")
	}
	if len(configs) == 1 {
		cfg = configs[0]
		cfg.Environment = apns.Production
	}
	if mode == "development" {
		cfg.Environment = apns.Sandbox
	}
	var client *apns.Client
	if certificatePath != "" {
		cert, err := certificate.FromPEMFile(certificatePath)
		if err != nil {
			return fmt.Errorf("load certificate: %w", err)
		}
		client, err = apns.NewCertificateClient(cert, cfg)
		if err != nil {
			return err
		}
	} else {
		key, err := token.AuthKeyFromFile(authKeyPath)
		if err != nil {
			return fmt.Errorf("load signing key: %w", err)
		}
		provider, err := token.New(key, keyID, teamID)
		if err != nil {
			return err
		}
		client, err = apns.NewTokenClient(provider, cfg)
		if err != nil {
			return err
		}
	}
	defer client.CloseIdleConnections()
	rejected, sent := 0, 0
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		deviceToken, payload, ok := strings.Cut(strings.TrimSpace(scanner.Text()), " ")
		payload = strings.TrimSpace(payload)
		if !ok || deviceToken == "" || payload == "" {
			return fmt.Errorf("expected <DeviceToken> <APNs Payload>")
		}
		res, err := client.Push(context.Background(), apns.Request{DeviceToken: deviceToken, Topic: topic, PushType: apns.PushType(pushType), Priority: apns.Priority(priority), Payload: jsontext.Value(payload)})
		line := fmt.Sprintf("%d", res.StatusCode)
		if err != nil {
			rejection, ok := errors.AsType[*apns.Rejection](err)
			if !ok {
				return err
			}
			rejected++
			line = rejectionLine(res.StatusCode, rejection)
		}
		sent++
		if _, err := fmt.Fprintln(output, line); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read notifications: %w", err)
	}
	if rejected != 0 {
		return fmt.Errorf("APNs rejected %d of %d notifications", rejected, sent)
	}
	return nil
}

// rejectionLine formats a rejection as "<status>: '<reason>'", matching the
// pre-v1 CLI, and appends the device token invalidation time when APNs
// reports one (410 Unregistered).
func rejectionLine(status int, rejection *apns.Rejection) string {
	line := fmt.Sprintf("%d: '%s'", status, rejection.Reason)
	if !rejection.DeviceTokenInvalidatedAt.IsZero() {
		line += " (invalidated at " + rejection.DeviceTokenInvalidatedAt.UTC().Format(time.RFC3339) + ")"
	}
	return line
}

func applicationVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	return versionString(info)
}

func versionString(info *debug.BuildInfo) string {
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	var revision string
	var modified bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if revision == "" {
		return "dev"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified {
		revision += "-dirty"
	}
	return "dev (" + revision + ")"
}
