package nilcheck

import (
	"io"
	"testing"
)

type nilReader []byte

func (nilReader) Read([]byte) (int, error) { return 0, io.EOF }

func TestIsNil(t *testing.T) {
	var ptr *int
	var reader io.Reader = nilReader(nil)
	for _, value := range []any{nil, ptr, map[string]int(nil), (func())(nil), []byte(nil), (chan int)(nil), reader} {
		if !IsNil(value) {
			t.Fatalf("IsNil(%T) = false", value)
		}
	}
	for _, value := range []any{0, "", struct{}{}, new(int), []byte{}, nilReader{}} {
		if IsNil(value) {
			t.Fatalf("IsNil(%T) = true", value)
		}
	}
}
