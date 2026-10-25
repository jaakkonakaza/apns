package apns2_test

import (
	"bytes"
	"crypto/tls"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
)

func TestNewClientManager(t *testing.T) {
	manager := apns2.NewClientManager()
	if got, want := 64, manager.MaxSize; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := 10*time.Minute, manager.MaxAge; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientManagerGetWithoutNew(t *testing.T) {
	manager := apns2.ClientManager{
		MaxSize: 32,
		MaxAge:  5 * time.Minute,
		Factory: apns2.NewClient,
	}

	c1 := manager.Get(mockCert())
	c2 := manager.Get(mockCert())
	v1 := reflect.ValueOf(c1)
	v2 := reflect.ValueOf(c2)
	if got := c1; got == nil {
		t.Error("unexpected nil")
	}
	if got, want := v2.Pointer(), v1.Pointer(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := manager.Len(), 1; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientManagerAddWithoutNew(t *testing.T) {
	wg := sync.WaitGroup{}

	manager := apns2.ClientManager{
		MaxSize: 1,
		MaxAge:  5 * time.Minute,
		Factory: apns2.NewClient,
	}

	for range 2 {
		wg.Go(func() {
			manager.Add(apns2.NewClient(mockCert()))
			if got, want := manager.Len(), 1; !reflect.DeepEqual(got, want) {
				t.Errorf("got %#v, want %#v", got, want)
			}
		})
	}
	wg.Wait()
}

func TestClientManagerLenWithoutNew(t *testing.T) {
	manager := apns2.ClientManager{
		MaxSize: 32,
		MaxAge:  5 * time.Minute,
		Factory: apns2.NewClient,
	}

	if got, want := manager.Len(), 0; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientManagerGetDefaultOptions(t *testing.T) {
	manager := apns2.NewClientManager()
	c1 := manager.Get(mockCert())
	c2 := manager.Get(mockCert())
	v1 := reflect.ValueOf(c1)
	v2 := reflect.ValueOf(c2)
	if got := c1; got == nil {
		t.Error("unexpected nil")
	}
	if got, want := v2.Pointer(), v1.Pointer(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := manager.Len(), 1; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientManagerGetNilClientFactory(t *testing.T) {
	manager := apns2.NewClientManager()
	manager.Factory = func(certificate tls.Certificate) *apns2.Client {
		return nil
	}
	c1 := manager.Get(mockCert())
	c2 := manager.Get(mockCert())
	if got := c1; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got := c2; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got, want := manager.Len(), 0; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientManagerGetMaxAgeExpiration(t *testing.T) {
	manager := apns2.NewClientManager()
	manager.MaxAge = time.Nanosecond
	c1 := manager.Get(mockCert())
	time.Sleep(time.Microsecond)
	c2 := manager.Get(mockCert())
	v1 := reflect.ValueOf(c1)
	v2 := reflect.ValueOf(c2)
	if got := c1; got == nil {
		t.Error("unexpected nil")
	}
	if got, want := v2.Pointer(), v1.Pointer(); reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want different from %#v", got, want)
	}
	if got, want := manager.Len(), 1; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientManagerGetMaxAgeExpirationWithNilFactory(t *testing.T) {
	manager := apns2.NewClientManager()
	manager.Factory = func(certificate tls.Certificate) *apns2.Client {
		return nil
	}
	manager.MaxAge = time.Nanosecond
	manager.Add(apns2.NewClient(mockCert()))
	c1 := manager.Get(mockCert())
	time.Sleep(time.Microsecond)
	c2 := manager.Get(mockCert())
	if got := c1; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got := c2; got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if got, want := manager.Len(), 0; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientManagerGetMaxSizeExceeded(t *testing.T) {
	manager := apns2.NewClientManager()
	manager.MaxSize = 1
	cert1 := mockCert()
	_ = manager.Get(cert1)
	cert2, _ := certificate.FromP12File("certificate/testdata/certificate-valid.p12", "")
	_ = manager.Get(cert2)
	cert3, _ := certificate.FromP12File("certificate/testdata/certificate-valid-encrypted.p12", "password")
	c := manager.Get(cert3)
	if !bytes.Equal(cert3.Certificate[0], c.Certificate.Certificate[0]) {
		t.Error("bytes.Equal(cert3.Certificate[0], c.Certificate.Certificate[0]) = false, want true")
	}
	if got, want := manager.Len(), 1; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestClientManagerAdd(t *testing.T) {
	fn := func(certificate tls.Certificate) *apns2.Client {
		t.Fatal("factory should not have been called")
		return nil
	}

	manager := apns2.NewClientManager()
	manager.Factory = fn
	manager.Add(apns2.NewClient(mockCert()))
	manager.Get(mockCert())
}

func TestClientManagerAddTwice(t *testing.T) {
	manager := apns2.NewClientManager()
	manager.Add(apns2.NewClient(mockCert()))
	manager.Add(apns2.NewClient(mockCert()))
	if got, want := manager.Len(), 1; !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}
