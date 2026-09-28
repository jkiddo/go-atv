// Package tlv8 implements the TLV8 encoding used by the HomeKit (HAP)
// pairing process, as used by Apple's Companion protocol.
package tlv8

import "errors"

// Tags defined by the HAP specification (plus Apple extensions).
const (
	TagMethod        = 0x00
	TagIdentifier    = 0x01
	TagSalt          = 0x02
	TagPublicKey     = 0x03
	TagProof         = 0x04
	TagEncryptedData = 0x05
	TagSeqNo         = 0x06
	TagError         = 0x07
	TagBackOff       = 0x08
	TagCertificate   = 0x09
	TagSignature     = 0x0A
	TagPermissions   = 0x0B
	TagFragmentData  = 0x0C
	TagFragmentLast  = 0x0D
	TagName          = 0x11
	TagFlags         = 0x13
)

// HAP error codes carried in TagError.
const (
	ErrorUnknown        = 0x01
	ErrorAuthentication = 0x02
	ErrorBackOff        = 0x03
	ErrorMaxPeers       = 0x04
	ErrorMaxTries       = 0x05
	ErrorUnavailable    = 0x06
	ErrorBusy           = 0x07
)

// Read parses TLV8 bytes into a tag → value map. Values longer than 255
// bytes are transmitted as repeated tags and concatenated here.
func Read(data []byte) (map[byte][]byte, error) {
	result := make(map[byte][]byte)
	for pos := 0; pos < len(data); {
		if pos+2 > len(data) {
			return nil, errors.New("tlv8: truncated header")
		}
		tag := data[pos]
		length := int(data[pos+1])
		if pos+2+length > len(data) {
			return nil, errors.New("tlv8: truncated value")
		}
		result[tag] = append(result[tag], data[pos+2:pos+2+length]...)
		pos += 2 + length
	}
	return result, nil
}

// Item is a single tag/value pair for writing.
type Item struct {
	Tag   byte
	Value []byte
}

// Write encodes items as TLV8 bytes, splitting values longer than 255 bytes
// into repeated tags.
func Write(items ...Item) []byte {
	var out []byte
	for _, item := range items {
		value := item.Value
		if len(value) == 0 {
			out = append(out, item.Tag, 0)
			continue
		}
		for pos := 0; pos < len(value); {
			size := len(value) - pos
			if size > 255 {
				size = 255
			}
			out = append(out, item.Tag, byte(size))
			out = append(out, value[pos:pos+size]...)
			pos += size
		}
	}
	return out
}
