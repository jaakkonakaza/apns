package apns

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"testing"
)

func TestPriorityMatrixBeforeHTTP(t *testing.T) {
	for _, pushType := range []PushType{PushTypeAlert, PushTypeBackground, PushTypeLiveActivity, PushTypeVOIP, PushTypeLocation, PushTypeNowPlaying, PushType("future-type")} {
		for _, priority := range []Priority{-100, -1, 0, 1, 2, 3, 4, 5, 6, 9, 10, 11, 100} {
			t.Run(fmt.Sprintf("%s/%d", pushType, priority), func(t *testing.T) {
				valid := priority == 0 || priority == 1 || priority == 5 || priority == 10
				if pushType == PushTypeBackground {
					valid = priority == 0 || priority == 5
				}
				if pushType == PushTypeLiveActivity {
					valid = priority == 0 || priority == 5 || priority == 10
				}
				calls := 0
				c := testClient(t, apiProvider(t), func(r *http.Request) (*http.Response, error) {
					calls++
					want := ""
					if priority != 0 {
						want = strconv.Itoa(int(priority))
					} else if pushType == PushTypeBackground {
						want = "5"
					}
					if got := r.Header.Get("apns-priority"); got != want {
						t.Errorf("priority=%q want=%q", got, want)
					}
					return testResponse(200, ""), nil
				})
				r := testRequest()
				r.PushType = pushType
				r.Priority = priority
				response, err := c.Push(context.Background(), r)
				if valid && (err != nil || response.StatusCode != 200 || calls != 1) {
					t.Fatalf("valid priority response=%+v err=%v calls=%d", response, err, calls)
				}
				if !valid && (err == nil || response.StatusCode != 0 || calls != 0) {
					t.Fatalf("invalid priority response=%+v err=%v calls=%d", response, err, calls)
				}
				if r.Priority != priority {
					t.Fatal("Push mutated caller priority")
				}
			})
		}
	}
}
