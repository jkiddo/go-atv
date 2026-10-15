package mrpwire

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

func TestPyatvDataFrames(t *testing.T) {
	raw, err := os.ReadFile("testdata/pyatv.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct{ Name, Protobuf, Frame string }
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			frame, _ := hex.DecodeString(f.Frame)
			want, _ := hex.DecodeString(f.Protobuf)
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(time.Second))
			b.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() { // Split every header/body boundary; no TCP packet assumptions.
				for _, chunk := range [][]byte{frame[:1], frame[1:4], frame[4:31], frame[31:]} {
					if _, err := b.Write(chunk); err != nil {
						done <- err
						return
					}
				}
				var ack [HeaderSize]byte
				_, err := io.ReadFull(b, ack[:])
				if err == nil && (string(ack[4:8]) != "rply" || binary.BigEndian.Uint64(ack[20:28]) != 0x100000123) {
					err = io.ErrUnexpectedEOF
				}
				done <- err
			}()
			messages, err := NewChannel(a).Receive()
			if err != nil {
				t.Fatal(err)
			}
			if len(messages) != 1 {
				t.Fatalf("messages: %d", len(messages))
			}
			expected := &ProtocolMessage{}
			if err := proto.Unmarshal(want, expected); err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(expected, messages[0]) {
				t.Fatal("wire mismatch")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestRejectMalformedFrames(t *testing.T) {
	for _, size := range []uint32{0, 31, MaxFrameSize + 1} {
		t.Run(strconv.FormatUint(uint64(size), 10), func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			go func() { var h [HeaderSize]byte; binary.BigEndian.PutUint32(h[:], size); b.Write(h[:]); b.Close() }()
			if _, err := NewChannel(a).Receive(); err == nil {
				t.Fatal("invalid size accepted")
			}
		})
	}
	for _, raw := range [][]byte{{0x80}, {0xff, 0xff, 0xff, 0xff, 0x7f}, {10, 8, 4}, {1, 8}} {
		if _, err := DecodeMessages(raw); err == nil {
			t.Fatalf("accepted %x", raw)
		}
	}
}
func TestUnprefixedAndBatchedProtobufs(t *testing.T) {
	raw, _ := proto.Marshal(NewMessage(120))
	messages, err := DecodeMessages(raw)
	if err != nil || len(messages) != 1 {
		t.Fatalf("unprefixed: %v", err)
	}
	batch := binary.AppendUvarint(nil, uint64(len(raw)))
	batch = append(batch, raw...)
	batch = append(batch, batch...)
	messages, err = DecodeMessages(batch)
	if err != nil || len(messages) != 2 {
		t.Fatalf("batch: %v", err)
	}
}
func FuzzDecodeMessages(f *testing.F) {
	f.Add([]byte{8, 4})
	f.Add([]byte{0x80})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = DecodeMessages(data) })
}
