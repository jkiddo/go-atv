package companion

import "fmt"

// InvalidAuth indicates the Apple TV rejected our credentials; re-pairing is
// required. Detect it with errors.As.
type InvalidAuth struct {
	Message string
}

func (e *InvalidAuth) Error() string {
	return fmt.Sprintf("companion: invalid authentication: %s", e.Message)
}

// ProtocolError indicates the device replied with an error message ("_em").
type ProtocolError struct {
	Command string
	Message string
	Code    int64
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("companion: command %s failed: %s", e.Command, e.Message)
}
