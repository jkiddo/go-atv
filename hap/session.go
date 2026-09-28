package hap

import (
	"encoding/binary"
	"fmt"
)

// Session implements HAP session encryption for stream-oriented channels
// (HAP specification section 5.2.2, as pyatv's HAPSession): data is split
// into frames of at most 1024 bytes, each sealed with ChaCha20-Poly1305
// using an 8-byte little-endian counter nonce and the 2-byte little-endian
// plaintext length as both frame prefix and AAD.
type Session struct {
	cipher *Cipher
	// leftover holds received ciphertext that does not yet form a full frame.
	leftover []byte
}

const (
	sessionFrameLength = 1024
	sessionAuthTagSize = 16
)

// NewSession creates a Session encrypting outgoing data with outputKey and
// decrypting incoming data with inputKey.
func NewSession(outputKey, inputKey []byte) (*Session, error) {
	cipher, err := NewCipher(outputKey, inputKey, 8)
	if err != nil {
		return nil, err
	}
	return &Session{cipher: cipher}, nil
}

// Encrypt seals data into length-prefixed frames ready to be written to the
// underlying connection.
func (s *Session) Encrypt(data []byte) []byte {
	var out []byte
	for len(data) > 0 {
		size := len(data)
		if size > sessionFrameLength {
			size = sessionFrameLength
		}
		length := make([]byte, 2)
		binary.LittleEndian.PutUint16(length, uint16(size))
		out = append(out, length...)
		out = append(out, s.cipher.Encrypt(data[:size], nil, length)...)
		data = data[size:]
	}
	return out
}

// Decrypt consumes raw bytes from the connection and returns all plaintext
// contained in complete frames. Partial frames are buffered until more data
// arrives.
func (s *Session) Decrypt(data []byte) ([]byte, error) {
	s.leftover = append(s.leftover, data...)

	var out []byte
	for len(s.leftover) >= 2 {
		length := s.leftover[0:2]
		blockLength := int(binary.LittleEndian.Uint16(length)) + sessionAuthTagSize
		if len(s.leftover) < 2+blockLength {
			break
		}
		block, err := s.cipher.Decrypt(s.leftover[2:2+blockLength], nil, length)
		if err != nil {
			return nil, fmt.Errorf("hap: session frame decrypt: %w", err)
		}
		out = append(out, block...)
		s.leftover = s.leftover[2+blockLength:]
	}
	return out, nil
}
