package hap

import (
	"crypto/sha512"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HKDFExpand derives a 32-byte key from sharedSecret using HKDF-SHA512 with
// the given salt and info strings, matching pyatv's hkdf_expand.
func HKDFExpand(salt, info string, sharedSecret []byte) []byte {
	reader := hkdf.New(sha512.New, sharedSecret, []byte(salt), []byte(info))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		panic(err) // cannot fail for 32-byte reads
	}
	return key
}
