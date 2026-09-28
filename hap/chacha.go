package hap

import (
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher is a ChaCha20-Poly1305 layer with independent send/receive keys and
// per-direction counter nonces, mirroring pyatv's Chacha20Cipher.
//
// nonceLength controls how the counter is encoded: the counter is written
// little-endian into nonceLength bytes and the result is left-padded with
// zeros to the full 12-byte nonce. Companion frame encryption uses 12; the
// pairing sub-messages use 8 with explicit string nonces ("PS-Msg05" etc.).
type Cipher struct {
	out         cipher.AEAD
	in          cipher.AEAD
	outCounter  uint64
	inCounter   uint64
	nonceLength int
}

// NewCipher creates a Cipher with distinct output (send) and input (receive)
// keys.
func NewCipher(outKey, inKey []byte, nonceLength int) (*Cipher, error) {
	out, err := chacha20poly1305.New(outKey)
	if err != nil {
		return nil, err
	}
	in, err := chacha20poly1305.New(inKey)
	if err != nil {
		return nil, err
	}
	return &Cipher{out: out, in: in, nonceLength: nonceLength}, nil
}

func (c *Cipher) counterNonce(counter uint64) []byte {
	nonce := make([]byte, 12)
	// Counter little-endian in the low bytes of an nonceLength-byte buffer,
	// left-padded with zeros to 12 bytes. For nonceLength 12 the counter
	// occupies the first 8 bytes; for 8 it occupies the last 8 bytes.
	le := make([]byte, 8)
	binary.LittleEndian.PutUint64(le, counter)
	copy(nonce[12-c.nonceLength:], le)
	return nonce
}

func padNonce(nonce []byte) []byte {
	if len(nonce) >= 12 {
		return nonce[:12]
	}
	padded := make([]byte, 12)
	copy(padded[12-len(nonce):], nonce)
	return padded
}

// Encrypt seals data. With a nil nonce the outgoing counter is used and
// incremented; an explicit shorter nonce is left-padded with zeros.
func (c *Cipher) Encrypt(data, nonce, aad []byte) []byte {
	if nonce == nil {
		nonce = c.counterNonce(c.outCounter)
		c.outCounter++
	} else {
		nonce = padNonce(nonce)
	}
	return c.out.Seal(nil, nonce, data, aad)
}

// Decrypt opens data. With a nil nonce the incoming counter is used and
// incremented; an explicit shorter nonce is left-padded with zeros.
func (c *Cipher) Decrypt(data, nonce, aad []byte) ([]byte, error) {
	if nonce == nil {
		nonce = c.counterNonce(c.inCounter)
		c.inCounter++
	} else {
		nonce = padNonce(nonce)
	}
	return c.in.Open(nil, nonce, data, aad)
}
