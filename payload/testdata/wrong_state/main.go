package main

import "github.com/jaakkonakaza/apns/payload"

type OrderState struct {
	OrderID string `json:"orderID"`
}

type OtherState struct {
	Message string `json:"message"`
}

// This fixture must fail compilation because its state does not match the
// public payload's generic parameter.
var _ = payload.ActivityUpdate[OrderState]{State: OtherState{}}

func main() {}
