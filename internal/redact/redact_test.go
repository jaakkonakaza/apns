package redact

import (
	"errors"
	"testing"
)

func TestErrorOmitsCause(t *testing.T) {
	cause := errors.New("sensitive-diagnostic")
	err := Error("summary", cause)
	if err.Error() != "summary" {
		t.Fatalf("message = %q", err.Error())
	}
	if !errors.Is(err, cause) {
		t.Fatal("cause not unwrappable")
	}
}
