package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaakkonakaza/apns"
)

func TestHelpAndVersion(t *testing.T) {
	for _, help := range []string{"--help", "-h"} {
		var output bytes.Buffer
		if err := run([]string{help}, strings.NewReader(""), io.Discard, &output); err != nil {
			t.Fatal(err)
		}
		for _, flag := range []string{"certificate-path", "auth-key-path", "key-id", "team-id", "priority", "push-type", "topic", "mode", "version"} {
			if !strings.Contains(output.String(), flag) {
				t.Errorf("help missing %s", flag)
			}
		}
	}
	var output bytes.Buffer
	if err := run([]string{"--version"}, strings.NewReader(""), &output, io.Discard); err != nil || output.String() != applicationVersion()+"\n" {
		t.Fatalf("version = %q, %v", output.String(), err)
	}
}

func TestInvalidArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"--certificate-path=missing"}, {"--topic=topic"}, {"--certificate-path=missing", "--topic=topic", "--mode=invalid"}, {"--unknown"}, {"--certificate-path=missing", "--topic=topic", "extra"}} {
		if err := run(args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Errorf("accepted %q", args)
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("input failed") }

func TestInputValidation(t *testing.T) {
	for _, args := range [][]string{
		{"--certificate-path=../../certificate/testdata/certificate-valid.pem", "--topic=topic", "--mode=development"},
		{"--certificate-path=../../certificate/testdata/certificate-valid.pem", "--topic=topic", "--mode=production"},
	} {
		if err := run(args, strings.NewReader(""), io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
		for _, input := range []io.Reader{strings.NewReader("token"), strings.NewReader("token "), strings.NewReader(strings.Repeat("x", 70<<10)), failingReader{}} {
			if err := run(args, input, io.Discard, io.Discard); err == nil {
				t.Fatal("accepted malformed or unreadable input")
			}
		}
	}
}

func TestCLISend(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.Method != http.MethodPost || r.URL.Path != "/3/device/aabbcc" {
			t.Errorf("unexpected request: %s %s %s", r.Proto, r.Method, r.URL.Path)
		}
		if r.Header.Get("apns-topic") != "com.example" {
			t.Error("incorrect topic")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != `{"aps":{"alert":"hello world"}}` {
			t.Errorf("payload = %s, error = %v", body, err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	startTestTLS(t, server)
	defer server.Close()

	var output bytes.Buffer
	args := []string{"--certificate-path=../../certificate/testdata/certificate-valid.pem", "--topic=com.example"}
	if err := run(args, strings.NewReader("aabbcc "+`{"aps":{"alert":"hello world"}}`+"\n"), &output, io.Discard, testConfig(server)); err != nil {
		t.Fatal(err)
	}
	if output.String() != "200\n" {
		t.Fatalf("output = %q", output.String())
	}
}

func TestTokenAuthenticationAndPriority(t *testing.T) {
	for _, tc := range []struct {
		pushType, priority, wantPriority string
	}{
		{"alert", "0", ""},
		{"background", "0", "5"},
		{"liveactivity", "10", "10"},
		{"location", "1", "1"},
	} {
		t.Run(tc.pushType, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 || r.Method != http.MethodPost || r.URL.Path != "/3/device/aabbcc" {
					t.Errorf("unexpected request: %s %s %s", r.Proto, r.Method, r.URL.Path)
				}
				if got := r.Header.Get("authorization"); !strings.HasPrefix(got, "bearer ") || len(strings.Split(strings.TrimPrefix(got, "bearer "), ".")) != 3 {
					t.Error("missing provider bearer token")
				}
				if got := r.Header.Get("apns-push-type"); got != tc.pushType {
					t.Errorf("push type = %q, want %q", got, tc.pushType)
				}
				if got := r.Header.Get("apns-priority"); got != tc.wantPriority {
					t.Errorf("priority = %q, want %q", got, tc.wantPriority)
				}
				w.WriteHeader(http.StatusOK)
			}))
			server.EnableHTTP2 = true
			startTestTLS(t, server)
			defer server.Close()
			args := []string{"--auth-key-path=../../token/testdata/authkey-valid.p8", "--key-id=KEY123", "--team-id=TEAM123", "--topic=com.example", "--push-type=" + tc.pushType, "--priority=" + tc.priority}
			var output bytes.Buffer
			if err := run(args, strings.NewReader("aabbcc {}\n"), &output, io.Discard, testConfig(server)); err != nil {
				t.Fatal(err)
			}
			if got := output.String(); got != "200\n" {
				t.Fatalf("output = %q", got)
			}
		})
	}
}

func TestInvalidAuthenticationAndPriority(t *testing.T) {
	for _, extra := range [][]string{
		{"--auth-key-path=missing"},
		{"--auth-key-path=missing", "--key-id=KEY123"},
		{"--key-id=KEY123", "--team-id=TEAM123"},
		{"--certificate-path=missing", "--auth-key-path=missing", "--key-id=KEY123", "--team-id=TEAM123"},
		{"--certificate-path=missing", "--key-id=KEY123"},
		{"--certificate-path=missing", "--priority=2"},
		{"--certificate-path=missing", "--priority=-1"},
	} {
		args := append([]string{"--topic=com.example"}, extra...)
		if err := run(args, strings.NewReader(""), io.Discard, io.Discard); err == nil || strings.Contains(err.Error(), "load certificate") || strings.Contains(err.Error(), "load signing key") {
			t.Errorf("authentication or priority was not rejected before loading files: %q: %v", args, err)
		}
	}
}

func TestVersionString(t *testing.T) {
	for _, tc := range []struct {
		name string
		info debug.BuildInfo
		want string
	}{
		{"release", debug.BuildInfo{Main: debug.Module{Version: "v2.1.0"}}, "v2.1.0"},
		{"development", debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, "dev"},
		{"no metadata", debug.BuildInfo{}, "dev"},
		{"revision", debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "1234567890abcdef"}}}, "dev (1234567890ab)"},
		{"dirty revision", debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "1234567890abcdef"}, {Key: "vcs.modified", Value: "true"}}}, "dev (1234567890ab-dirty)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := versionString(&tc.info); got != tc.want {
				t.Errorf("version = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCLIReportsRejectedNotifications(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"reason":"InvalidProviderToken"}`)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	startTestTLS(t, server)
	defer server.Close()
	args := []string{"--auth-key-path=../../token/testdata/authkey-valid.p8", "--key-id=KEY123", "--team-id=TEAM123", "--topic=com.example"}
	var output bytes.Buffer
	err := run(args, strings.NewReader("aabbcc {}\naabbcc {}\n"), &output, io.Discard,
		testConfig(server))
	if err == nil || err.Error() != "APNs rejected 1 of 2 notifications" {
		t.Fatalf("run error = %v", err)
	}
	if requests.Load() != 2 || output.String() != "403: 'InvalidProviderToken'\n200\n" {
		t.Fatalf("requests = %d, output = %q", requests.Load(), output.String())
	}
}

func TestCLIPrintsRejectionReasons(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"bad device token", http.StatusBadRequest, `{"reason":"BadDeviceToken"}`, "400: 'BadDeviceToken'\n"},
		{"device token not for topic", http.StatusBadRequest, `{"reason":"DeviceTokenNotForTopic"}`, "400: 'DeviceTokenNotForTopic'\n"},
		{"topic disallowed", http.StatusBadRequest, `{"reason":"TopicDisallowed"}`, "400: 'TopicDisallowed'\n"},
		{"unregistered", http.StatusGone, `{"reason":"Unregistered","timestamp":1700000000000}`, "410: 'Unregistered' (invalidated at 2023-11-14T22:13:20Z)\n"},
		{"no body", http.StatusInternalServerError, "", "500: ''\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			server.EnableHTTP2 = true
			startTestTLS(t, server)
			defer server.Close()
			args := []string{"--auth-key-path=../../token/testdata/authkey-valid.p8", "--key-id=KEY123", "--team-id=TEAM123", "--topic=com.example"}
			var output, diagnostics bytes.Buffer
			err := run(args, strings.NewReader("aabbcc {}\n"), &output, &diagnostics, testConfig(server))
			if err == nil || err.Error() != "APNs rejected 1 of 1 notifications" {
				t.Fatalf("run error = %v", err)
			}
			if got := output.String(); got != tc.want {
				t.Fatalf("output = %q, want %q", got, tc.want)
			}
			if diagnostics.Len() != 0 {
				t.Fatalf("diagnostics = %q", diagnostics.String())
			}
		})
	}
}

func startTestTLS(t *testing.T, server *httptest.Server) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"api.push.apple.com", "api.sandbox.push.apple.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
}

func testConfig(server *httptest.Server) apns.Config {
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return apns.Config{Environment: apns.Production, Transport: apns.TransportConfig{RootCAs: roots, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}}
}
