package airplay

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

	"github.com/jkiddo/go-atv/hap"
)

// DiagnosticEvent contains only allowlisted metadata, never PINs, private keys,
// authentication headers, challenge values, response bodies or raw errors.
type DiagnosticEvent struct {
	Stage      string
	Result     string
	StatusCode int
	Identity   string
	SavedCode  bool
	Challenge  bool
}

// WithDiagnosticHandler observes handshake stages synchronously. The handler
// must be safe for concurrent use if it is shared between multiple clients.
func WithDiagnosticHandler(handler func(DiagnosticEvent)) Option {
	return func(c *Client) { c.diagnosticHandler = handler }
}

func (c *Client) emitDiagnostic(event DiagnosticEvent) {
	if c.diagnosticHandler != nil {
		c.diagnosticHandler(event)
	}
}

func (c *Client) traceCredentials(credentials hap.Credentials, err error) {
	if c.diagnosticHandler == nil {
		return
	}
	event := DiagnosticEvent{Stage: "credentials", Result: "loaded"}
	if errors.Is(err, os.ErrNotExist) {
		event.Result = "missing"
	} else if err != nil {
		event.Result = "load-error"
	} else {
		// Fingerprint the public identity, never the private key or four-digit code.
		if len(credentials.LTSK) == ed25519.SeedSize {
			public := ed25519.NewKeyFromSeed(credentials.LTSK).Public().(ed25519.PublicKey)
			sum := sha256.Sum256(append(public, credentials.ClientID...))
			event.Identity = fmt.Sprintf("%x", sum[:8])
		}
	}
	c.emitDiagnostic(event)
}

func (c *Client) verifyLegacyWithDiagnostics(ctx context.Context, conn *connection, credentials hap.Credentials) error {
	err := verifyLegacy(ctx, conn, credentials)
	event := DiagnosticEvent{Stage: "pair-verify", Result: "accepted"}
	if err != nil {
		event.Result = "failed"
		var status *StatusError
		if errors.As(err, &status) {
			event.StatusCode = status.Code
		}
	}
	c.emitDiagnostic(event)
	return err
}
