package apns2_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apns "github.com/sideshow/apns2"
)

func TestTransportIdlePings(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	defer fixture.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: fixture.TLS.Certificates,
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	stop := make(chan struct{})
	defer close(stop)
	pings := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			pings <- err
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			pings <- err
			return
		}
		preface := make([]byte, 24)
		if _, err := io.ReadFull(conn, preface); err != nil {
			pings <- err
			return
		}
		if string(preface) != "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
			pings <- fmt.Errorf("invalid HTTP/2 preface")
			return
		}
		// Empty SETTINGS lets the client start a request without a response from the peer.
		if _, err := conn.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0}); err != nil {
			pings <- err
			return
		}
		count := 0
		for count < 2 {
			var header [9]byte
			if _, err := io.ReadFull(conn, header[:]); err != nil {
				pings <- err
				return
			}
			size := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
			if size > 1<<20 {
				pings <- fmt.Errorf("unexpected frame size %d", size)
				return
			}
			body := make([]byte, size)
			if _, err := io.ReadFull(conn, body); err != nil {
				pings <- err
				return
			}
			if header[3] != 6 || header[4]&1 != 0 {
				continue
			}
			if size != 8 || binary.BigEndian.Uint32(header[5:]) != 0 {
				pings <- fmt.Errorf("invalid PING frame")
				return
			}
			// Echo the opaque payload with ACK set, keeping the connection healthy.
			header[4] = 1
			if _, err := conn.Write(append(header[:], body...)); err != nil {
				pings <- err
				return
			}
			count++
		}
		pings <- nil
		<-stop
	}()
	client := apns.NewTokenClient(mockToken(),
		apns.WithHost("https://"+listener.Addr().String()),
		apns.WithTLSConfig(fixture.Client().Transport.(*http.Transport).TLSClientConfig),
		apns.WithReadIdleTimeout(20*time.Millisecond),
	)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pushed := make(chan error, 1)
	go func() { _, err := client.Push(ctx, mockNotification()); pushed <- err }()
	select {
	case err := <-pings:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("HTTP/2 idle PINGs were not received")
	}
	cancel()
	select {
	case err := <-pushed:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("push error = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("push did not stop after cancellation")
	}
}
