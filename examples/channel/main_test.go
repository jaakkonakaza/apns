package main

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jaakkonakaza/apns"
)

type pushFunc func(context.Context, apns.Request) (apns.Response, error)

func (f pushFunc) Push(ctx context.Context, n apns.Request) (apns.Response, error) {
	return f(ctx, n)
}

func TestConcurrentSendingBoundsWorkAndPreservesOutcomes(t *testing.T) {
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	defer release()
	started := make(chan struct{}, 2)
	var active, maximum atomic.Int32
	transportError := errors.New("connection failed")
	client := pushFunc(func(_ context.Context, n apns.Request) (apns.Response, error) {
		current := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); current > old; old = maximum.Load() {
			if maximum.CompareAndSwap(old, current) {
				break
			}
		}
		select {
		case started <- struct{}{}:
		default:
		}
		<-gate
		switch n.CollapseID {
		case "2":
			return apns.Response{StatusCode: 403}, &apns.Rejection{Response: apns.Response{StatusCode: 403}, Reason: apns.ReasonInvalidProviderToken}
		case "3":
			return apns.Response{}, transportError
		default:
			return apns.Response{StatusCode: 200}, nil
		}
	})
	results := sendNotifications(context.Background(), client, 8, 2, func(i int) apns.Request {
		return apns.Request{CollapseID: strconv.Itoa(i)}
	})
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("workers did not start")
		}
	}
	release()
	seen := make(map[int]bool)
	for result := range results {
		if seen[result.Index] {
			t.Errorf("duplicate result for %d", result.Index)
		}
		seen[result.Index] = true
		switch result.Index {
		case 2:
			if result.Err == nil || result.Response.StatusCode != 403 {
				t.Errorf("APNs rejection lost: %+v", result)
			}
		case 3:
			if !errors.Is(result.Err, transportError) || result.Response.StatusCode != 0 {
				t.Errorf("transport failure lost: %+v", result)
			}
		default:
			if result.Err != nil || result.Response.StatusCode != 200 {
				t.Errorf("unexpected result: %+v", result)
			}
		}
	}
	if len(seen) != 8 || maximum.Load() > 2 || maximum.Load() < 1 {
		t.Fatalf("results = %d, maximum concurrency = %d", len(seen), maximum.Load())
	}
}

func TestCancelledSendingStopsWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{}, 1)
	client := pushFunc(func(ctx context.Context, _ apns.Request) (apns.Response, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return apns.Response{}, ctx.Err()
	})
	results := sendNotifications(ctx, client, 100, 1, func(int) apns.Request {
		return apns.Request{}
	})
	<-started
	cancel()
	finished := make(chan struct{})
	go func() {
		for range results {
		}
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("workers did not stop after cancellation")
	}
}
