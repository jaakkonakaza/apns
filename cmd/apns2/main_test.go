package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sideshow/apns2"
)

func TestHelpAndVersion(t *testing.T) {
	for _, help := range []string{"--help", "-h"} {
		var output bytes.Buffer
		if err := run([]string{help}, strings.NewReader(""), io.Discard, &output); err != nil {
			t.Fatal(err)
		}
		for _, flag := range []string{"certificate-path", "topic", "mode", "version"} {
			if !strings.Contains(output.String(), flag) {
				t.Errorf("help missing %s", flag)
			}
		}
	}
	var output bytes.Buffer
	if err := run([]string{"--version"}, strings.NewReader(""), &output, io.Discard); err != nil || output.String() != "0.1\n" {
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
	server.StartTLS()
	defer server.Close()

	var output bytes.Buffer
	args := []string{"--certificate-path=../../certificate/testdata/certificate-valid.pem", "--topic=com.example"}
	if err := run(args, strings.NewReader("aabbcc "+`{"aps":{"alert":"hello world"}}`+"\n"), &output, io.Discard, apns2.WithHost(server.URL),
		apns2.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig)); err != nil {
		t.Fatal(err)
	}
	if output.String() != "200: ''\n" {
		t.Fatalf("output = %q", output.String())
	}
}
