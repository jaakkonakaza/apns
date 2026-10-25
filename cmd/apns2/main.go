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
	"runtime/debug"
	"strings"

	"github.com/jaakkonakaza/apns2"
	"github.com/jaakkonakaza/apns2/certificate"
	"github.com/jaakkonakaza/apns2/token"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		log.Fatal(err)
	}
}

func run(args []string, input io.Reader, output, diagnostics io.Writer, options ...apns2.ClientOption) error {
	flags := flag.NewFlagSet("apns2", flag.ContinueOnError)
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
	flags.StringVar(&pushType, "push-type", string(apns2.PushTypeAlert), "apns-push-type header; it must match the payload.")
	flags.IntVar(&priority, "priority", 0, "APNs priority: 1, 5 or 10 (0 omits the header).")
	flags.BoolVar(&version, "version", false, "Show application version.")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(diagnostics, "Usage: apns2 --topic=TOPIC [authentication flags] [flags]\nReads STDIN lines formatted as: <DeviceToken> <APNs Payload>")
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
	switch priority {
	case 0, apns2.PriorityPowerSaving, apns2.PriorityLow, apns2.PriorityHigh:
	default:
		return fmt.Errorf("priority must be 0, 1, 5 or 10")
	}
	if mode != "production" && mode != "development" {
		return fmt.Errorf("mode must be production or development")
	}
	host := apns2.HostProduction
	if mode == "development" {
		host = apns2.HostDevelopment
	}
	options = append([]apns2.ClientOption{apns2.WithHost(host)}, options...)
	var client *apns2.Client
	if certificatePath != "" {
		cert, err := certificate.FromPemFile(certificatePath)
		if err != nil {
			return fmt.Errorf("load certificate %q: %w", certificatePath, err)
		}
		client = apns2.NewClient(cert, options...)
	} else {
		key, err := token.AuthKeyFromFile(authKeyPath)
		if err != nil {
			return fmt.Errorf("load signing key %q: %w", authKeyPath, err)
		}
		client = apns2.NewTokenClient(&token.Token{AuthKey: key, KeyID: keyID, TeamID: teamID}, options...)
	}
	defer client.CloseIdleConnections()
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		deviceToken, payload, ok := strings.Cut(strings.TrimSpace(scanner.Text()), " ")
		payload = strings.TrimSpace(payload)
		if !ok || deviceToken == "" || payload == "" {
			return fmt.Errorf("expected <DeviceToken> <APNs Payload>")
		}
		res, err := client.Push(context.Background(), &apns2.Notification{DeviceToken: deviceToken, Topic: topic, PushType: apns2.PushType(pushType), Priority: priority, Payload: payload})
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
