package hap

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// newSessionPair returns client and server sessions with mirrored keys.
func newSessionPair(t *testing.T) (*Session, *Session) {
	t.Helper()
	keyA := make([]byte, 32)
	keyB := make([]byte, 32)
	rand.Read(keyA)
	rand.Read(keyB)
	client, err := NewSession(keyA, keyB)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSession(keyB, keyA)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestSessionRoundTrip(t *testing.T) {
	client, server := newSessionPair(t)

	// Multi-frame payload (> 1024 bytes) plus a second message to exercise
	// the nonce counters.
	payload := make([]byte, 3000)
	rand.Read(payload)

	for i := 0; i < 2; i++ {
		encrypted := client.Encrypt(payload)
		decrypted, err := server.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if !bytes.Equal(decrypted, payload) {
			t.Fatalf("message %d: decrypted payload mismatch", i)
		}
	}
}

func TestSessionChunkedDelivery(t *testing.T) {
	client, server := newSessionPair(t)

	payload := []byte("hello over a slow network")
	encrypted := client.Encrypt(payload)

	// Deliver byte by byte; only the final chunk completes the frame.
	var got []byte
	for _, b := range encrypted {
		out, err := server.Decrypt([]byte{b})
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, out...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q, want %q", got, payload)
	}
}

func TestSessionTamperDetected(t *testing.T) {
	client, server := newSessionPair(t)
	encrypted := client.Encrypt([]byte("payload"))
	encrypted[len(encrypted)-1] ^= 0xFF
	if _, err := server.Decrypt(encrypted); err == nil {
		t.Fatal("expected decrypt error for tampered frame")
	}
}
