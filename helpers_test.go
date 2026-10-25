package apns2_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"net/http"

	apns "github.com/jaakkonakaza/apns2"
	"github.com/jaakkonakaza/apns2/token"
)

func mockNotification() *apns.Notification {
	n := &apns.Notification{}
	n.DeviceToken = "11aa01229f15f0f0c52029d8cf8cd0aeaf2365fe4cebc4af26cd6d76b7919ef7"
	n.Payload = []byte(`{"aps":{"alert":"Hello!"}}`)
	return n
}

func mockToken() *token.Token {
	pubkeyCurve := elliptic.P256()
	authKey, _ := ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
	return &token.Token{AuthKey: authKey}
}

func mockCert() tls.Certificate {
	return tls.Certificate{}
}

func mockClient(url string) *apns.Client {
	return apns.NewClient(mockCert(), apns.WithHost(url), apns.WithHTTPClient(&http.Client{}))
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
