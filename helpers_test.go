package apns2_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"net/http"
	"testing"

	apns "github.com/jaakkonakaza/apns2"
	"github.com/jaakkonakaza/apns2/token"
)

func mockNotification() *apns.Notification {
	n := &apns.Notification{}
	n.DeviceToken = "11aa01229f15f0f0c52029d8cf8cd0aeaf2365fe4cebc4af26cd6d76b7919ef7"
	n.Topic = "com.example.app"
	n.PushType = apns.PushTypeAlert
	n.Payload = []byte(`{"aps":{"alert":"Hello!"}}`)
	return n
}

func mockToken() *token.Token {
	pubkeyCurve := elliptic.P256()
	authKey, _ := ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
	provider, err := token.New(authKey, "key", "team")
	if err != nil {
		panic(err)
	}
	return provider
}

func mockCert() tls.Certificate {
	cert, err := tls.LoadX509KeyPair("certificate/testdata/certificate-valid.pem", "certificate/testdata/certificate-valid.pem")
	if err != nil {
		panic(err)
	}
	return cert
}

func mockClient(url string) *apns.Client {
	client, err := apns.NewClient(mockCert(), apns.WithHost(url), apns.WithHTTPClient(&http.Client{}))
	if err != nil {
		panic(err)
	}
	return client
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func mustClient(t testing.TB, cert tls.Certificate, options ...apns.ClientOption) *apns.Client {
	t.Helper()
	client, err := apns.NewClient(cert, options...)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func mustTokenClient(t testing.TB, provider *token.Token, options ...apns.ClientOption) *apns.Client {
	t.Helper()
	client, err := apns.NewTokenClient(provider, options...)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func mustBroadcastTokenClient(t testing.TB, provider *token.Token, endpoints apns.BroadcastEndpoints, options ...apns.ClientOption) *apns.BroadcastClient {
	t.Helper()
	client, err := apns.NewBroadcastTokenClient(provider, endpoints, options...)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func broadcastEndpoints(host string) apns.BroadcastEndpoints {
	return apns.BroadcastEndpoints{Push: host, Channels: host}
}
