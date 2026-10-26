package apns

import (
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
	"uuid"
)

type countMarshaler struct {
	calls *int
	value string
}

func (m countMarshaler) MarshalJSON() ([]byte, error) { *m.calls++; return []byte(m.value), nil }

func TestRequestIsNotPayloadMarshaler(t *testing.T) {
	request := testRequest()
	if _, ok := any(request).(json.Marshaler); ok {
		t.Fatal("Request implements payload JSON marshaler")
	}
	if _, ok := any(&request).(json.Marshaler); ok {
		t.Fatal("Request pointer implements payload JSON marshaler")
	}
	if _, ok := any(request).(jsonv2.MarshalerTo); ok {
		t.Fatal("Request implements payload streaming marshaler")
	}
}

func sizedJSON(size int, unit string) jsontext.Value {
	const prefix = `{"data":"`
	const suffix = `"}`
	n := size - len(prefix) - len(suffix)
	text := strings.Repeat(unit, n/len(unit)) + strings.Repeat("x", n%len(unit))
	return jsontext.Value(prefix + text + suffix)
}

func TestPayloadByteLimitsAndMarshalOnce(t *testing.T) {
	for _, pushType := range []PushType{PushTypeAlert, PushTypeLiveActivity, PushTypeVOIP} {
		limit := 4096
		if pushType == PushTypeVOIP {
			limit = 5120
		}
		for _, size := range []int{limit, limit + 1, 4800} {
			for _, unit := range []string{"x", "界"} {
				for _, raw := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%d/%s/raw=%v", pushType, size, unit, raw), func(t *testing.T) {
						calls, encodes := 0, 0
						c := testClient(t, apiProvider(t), func(r *http.Request) (*http.Response, error) {
							calls++
							body, err := io.ReadAll(r.Body)
							if err != nil {
								t.Fatal(err)
							}
							if len(body) != size {
								t.Errorf("wire bytes=%d want=%d", len(body), size)
							}
							return testResponse(200, ""), nil
						})
						request := testRequest()
						request.PushType = pushType
						data := sizedJSON(size, unit)
						if raw {
							request.Payload = data
						} else {
							request.Payload = countMarshaler{&encodes, string(data)}
						}
						response, err := c.Push(context.Background(), request)
						valid := size <= limit
						if valid && (err != nil || calls != 1 || response.StatusCode != 200) {
							t.Fatalf("valid size response=%+v error=%v calls=%d", response, err, calls)
						}
						if !valid && (err == nil || calls != 0 || response.StatusCode != 0) {
							t.Fatalf("oversize response=%+v error=%v calls=%d", response, err, calls)
						}
						if !raw && encodes != 1 {
							t.Fatalf("application marshaler invoked %d times", encodes)
						}
					})
				}
			}
		}
	}
}

func TestStrictRawPayloadValidation(t *testing.T) {
	calls := 0
	c := testClient(t, apiProvider(t), func(*http.Request) (*http.Response, error) { calls++; return testResponse(200, ""), nil })
	for _, value := range []any{nil, "{}", []byte(`{}`), jsontext.Value(`null`), jsontext.Value(`[]`), jsontext.Value(`1`), jsontext.Value(`{`), jsontext.Value(`{"a":1,"a":2}`), jsontext.Value(`{} {}`), jsontext.Value([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'})} {
		if response, err := c.Push(context.Background(), Request{DeviceToken: "aabb", Topic: "com.example", PushType: PushTypeAlert, Payload: value}); err == nil || response.StatusCode != 0 {
			t.Errorf("accepted invalid payload %T: response=%+v error=%v", value, response, err)
		}
	}
	if calls != 0 {
		t.Fatalf("invalid body reached HTTP %d times", calls)
	}
	for _, value := range []any{jsontext.Value(`{}`), map[string]any{}, jsontext.Value(`{"aps":{},"future-apple-field":true}`)} {
		request := testRequest()
		request.Payload = value
		if _, err := c.Push(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRequestHeadersAndExpiration(t *testing.T) {
	epoch := time.Unix(0, 0)
	future := time.Unix(1900000000, 0)
	id := uuid.MustParse("123e4567-e89b-12d3-a456-4266554400a0")
	for _, expiry := range []*time.Time{nil, &epoch, &future} {
		c := testClient(t, apiProvider(t), func(r *http.Request) (*http.Response, error) {
			if r.Method != "POST" || r.URL.Host != "api.sandbox.push.apple.com" || r.URL.Path != "/3/device/aabb" {
				t.Fatalf("wrong request destination %s %s", r.Method, r.URL)
			}
			if r.Header.Get("apns-id") != id.String() || r.Header.Get("apns-topic") != "com.example" || r.Header.Get("apns-collapse-id") != "group" || r.Header.Get("apns-push-type") != "alert" {
				t.Errorf("wrong headers %v", r.Header)
			}
			want := ""
			if expiry != nil {
				want = fmt.Sprint(expiry.Unix())
			}
			if got := r.Header.Get("apns-expiration"); got != want {
				t.Errorf("expiry=%q want=%q", got, want)
			}
			return testResponse(200, ""), nil
		})
		request := testRequest()
		request.ID = &id
		request.CollapseID = "group"
		request.ExpiresAt = expiry
		if _, err := c.Push(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	c := testClient(t, apiProvider(t), func(*http.Request) (*http.Response, error) {
		t.Error("pre-epoch expiration reached HTTP")
		return testResponse(200, ""), nil
	})
	before := time.Unix(-1, 0)
	r := testRequest()
	r.ExpiresAt = &before
	if _, err := c.Push(context.Background(), r); err == nil {
		t.Fatal("accepted pre-epoch expiration")
	}
}

func TestLimitsUseEncodedEscapingAndActualRawWireBytes(t *testing.T) {
	for _, count := range []int{2042, 2043} {
		calls := 0
		c := testClient(t, apiProvider(t), func(r *http.Request) (*http.Response, error) {
			calls++
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if len(body) != 11+2*count {
				t.Fatalf("escaped wire size=%d", len(body))
			}
			return testResponse(200, ""), nil
		})
		r := testRequest()
		r.Payload = map[string]string{"data": strings.Repeat("\n", count)}
		_, err := c.Push(context.Background(), r)
		if count == 2042 && (err != nil || calls != 1) {
			t.Fatalf("valid escaped payload error=%v calls=%d", err, calls)
		}
		if count == 2043 && (err == nil || calls != 0) {
			t.Fatalf("escaped payload exceeded4096 but error=%v calls=%d", err, calls)
		}
	}
	c := testClient(t, apiProvider(t), func(r *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) > 4096 {
			t.Fatalf("actual raw wire exceeded budget: %d", len(body))
		}
		return testResponse(200, ""), nil
	})
	r := testRequest()
	r.Payload = jsontext.Value("{\n" + strings.Repeat(" ", 5000) + "}")
	if _, err := c.Push(context.Background(), r); err != nil {
		t.Fatalf("compacted raw whitespace should use final wire budget: %v", err)
	}
}
