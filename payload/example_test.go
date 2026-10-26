package payload_test

import (
	"encoding/json/v2"
	"fmt"
	"time"

	"github.com/jaakkonakaza/apns/payload"
)

func ExampleNotification() {
	p := payload.Notification{APS: payload.APS{Alert: &payload.Alert{Body: "Your order is ready"}, Badge: new(0)}, Custom: map[string]any{"orderID": "123"}}
	data, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(data))
	// Output: {"aps":{"alert":{"body":"Your order is ready"},"badge":0},"orderID":"123"}
}

func ExampleActivityUpdate() {
	type State struct {
		Counter int `json:"counter"`
	}
	p := payload.ActivityUpdate[State]{Timestamp: time.Unix(1685952000, 0), State: State{Counter: 7}}
	data, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(data))
	// Output: {"aps":{"content-state":{"counter":7},"event":"update","timestamp":1685952000}}
}
