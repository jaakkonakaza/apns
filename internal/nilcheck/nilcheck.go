// Package nilcheck detects nil values hidden behind non-nil interfaces.
package nilcheck

import "reflect"

// IsNil reports whether value is nil or holds a nil pointer, map, function,
// interface, slice, or channel.
func IsNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Func, reflect.Interface, reflect.Slice, reflect.Chan:
		return v.IsNil()
	}
	return false
}
