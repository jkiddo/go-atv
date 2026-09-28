package hap

import (
	"bytes"
	"testing"
)

func TestCipherRoundTripCounterNonce(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	sender, err := NewCipher(key, key, 12)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewCipher(key, key, 12)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		aad := []byte{8, 0, 0, byte(20 + i)}
		encrypted := sender.Encrypt([]byte("hello world"), nil, aad)
		decrypted, err := receiver.Decrypt(encrypted, nil, aad)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if string(decrypted) != "hello world" {
			t.Fatalf("message %d: got %q", i, decrypted)
		}
	}
}

func TestCipherCounterAdvances(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	c, err := NewCipher(key, key, 12)
	if err != nil {
		t.Fatal(err)
	}
	first := c.Encrypt([]byte("data"), nil, nil)
	second := c.Encrypt([]byte("data"), nil, nil)
	if bytes.Equal(first, second) {
		t.Error("consecutive encryptions with counter nonce must differ")
	}
}

func TestCipherExplicitNoncePadding(t *testing.T) {
	key := bytes.Repeat([]byte{0x02}, 32)
	a, _ := NewCipher(key, key, 8)
	b, _ := NewCipher(key, key, 8)

	encrypted := a.Encrypt([]byte("secret"), []byte("PS-Msg05"), nil)
	decrypted, err := b.Decrypt(encrypted, []byte("PS-Msg05"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "secret" {
		t.Fatalf("got %q", decrypted)
	}

	// Same nonce must be reproducible regardless of counter state.
	if _, err := b.Decrypt(encrypted, []byte("PS-Msg05"), nil); err != nil {
		t.Fatal("explicit nonce should not consume counter state:", err)
	}
}

// The 8-byte counter nonce layout is 4 zero bytes + 8-byte little-endian
// counter (pyatv Chacha20Cipher8byteNonce); the 12-byte layout is the
// counter little-endian in the first 8 bytes.
func TestCounterNonceLayout(t *testing.T) {
	key := bytes.Repeat([]byte{0x03}, 32)

	c8, _ := NewCipher(key, key, 8)
	nonce8 := c8.counterNonce(0x0102030405060708)
	want8 := []byte{0, 0, 0, 0, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	if !bytes.Equal(nonce8, want8) {
		t.Errorf("8-byte nonce = %x, want %x", nonce8, want8)
	}

	c12, _ := NewCipher(key, key, 12)
	nonce12 := c12.counterNonce(0x0102030405060708)
	want12 := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0, 0, 0, 0}
	if !bytes.Equal(nonce12, want12) {
		t.Errorf("12-byte nonce = %x, want %x", nonce12, want12)
	}
}
