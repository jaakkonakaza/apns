// Package redact builds errors whose messages omit sensitive diagnostic input.
package redact

// diagnosticError keeps sensitive input out of routine error strings. Its cause
// is available for deliberate diagnostic inspection and must not be logged raw.
type diagnosticError struct {
	message string
	cause   error
}

func (e *diagnosticError) Error() string { return e.message }
func (e *diagnosticError) Unwrap() error { return e.cause }

// Error returns an error that reports message and unwraps to cause.
func Error(message string, cause error) error {
	return &diagnosticError{message: message, cause: cause}
}
