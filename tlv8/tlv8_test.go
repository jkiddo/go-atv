package tlv8

import (
	"bytes"
	"testing"
)

func TestRoundTripSimple(t *testing.T) {
	data := Write(
		Item{Tag: TagSeqNo, Value: []byte{0x01}},
		Item{Tag: TagPublicKey, Value: []byte{0xAA, 0xBB}},
	)
	parsed, err := Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed[TagSeqNo], []byte{0x01}) {
		t.Errorf("SeqNo = %x", parsed[TagSeqNo])
	}
	if !bytes.Equal(parsed[TagPublicKey], []byte{0xAA, 0xBB}) {
		t.Errorf("PublicKey = %x", parsed[TagPublicKey])
	}
}

func TestLargeValueChunking(t *testing.T) {
	large := make([]byte, 600)
	for i := range large {
		large[i] = byte(i)
	}
	data := Write(Item{Tag: TagEncryptedData, Value: large})

	// 600 bytes → chunks of 255 + 255 + 90, each with a 2-byte header.
	if len(data) != 600+3*2 {
		t.Errorf("encoded length = %d, want %d", len(data), 600+6)
	}
	parsed, err := Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed[TagEncryptedData], large) {
		t.Error("chunked value did not round trip")
	}
}

func TestReadTruncated(t *testing.T) {
	if _, err := Read([]byte{0x01}); err == nil {
		t.Error("expected error for truncated header")
	}
	if _, err := Read([]byte{0x01, 0x05, 0xAA}); err == nil {
		t.Error("expected error for truncated value")
	}
}

func TestEmptyValue(t *testing.T) {
	data := Write(Item{Tag: TagMethod, Value: nil})
	parsed, err := Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := parsed[TagMethod]; !ok || len(value) != 0 {
		t.Errorf("Method = %x, ok=%v", value, ok)
	}
}
