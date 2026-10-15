// Package mrpwire implements the playback subset of Media Remote Protocol.
package mrpwire

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"howett.net/plist"
)

const (
	SetState                = 4
	DeviceInfo              = 15
	ClientUpdates           = 16
	KeyboardSession         = 24
	ConnectionState         = 38
	Generic                 = 42
	NowPlayingClientMessage = 46
	NowPlayingPlayerMessage = 47
	RemoveClient            = 53
	RemovePlayer            = 54
	UpdateClient            = 55
	UpdateContentItem       = 56
	MaxFrameSize            = 4 << 20
	HeaderSize              = 32
)

func NewMessage(kind uint32) *ProtocolMessage {
	return &ProtocolMessage{Type: proto.Uint32(kind), ErrorCode: proto.Uint32(0), UniqueIdentifier: proto.String(UUID())}
}
func UUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// Channel carries MRP over an already decrypted AirPlay data stream.
// One reader and multiple writers may use it concurrently.
type Channel struct {
	conn net.Conn
	mu   sync.Mutex
	seq  uint64
}

func NewChannel(conn net.Conn) *Channel { return &Channel{conn: conn, seq: 0x100000000} }

func (c *Channel) write(kind, command string, seq uint64, payload []byte) error {
	if len(payload) > MaxFrameSize-HeaderSize {
		return fmt.Errorf("mrp: oversized data payload")
	}
	frame := make([]byte, HeaderSize+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(frame)))
	copy(frame[4:16], kind)
	copy(frame[16:20], command)
	binary.BigEndian.PutUint64(frame[20:28], seq)
	copy(frame[32:], payload)
	if err := c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	for len(frame) > 0 {
		n, err := c.conn.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}
func (c *Channel) Send(messages ...*ProtocolMessage) error {
	var data []byte
	for _, msg := range messages {
		raw, err := proto.Marshal(msg)
		if err != nil {
			return err
		}
		data = binary.AppendUvarint(data, uint64(len(raw)))
		data = append(data, raw...)
	}
	payload, err := plist.Marshal(map[string]any{"params": map[string]any{"data": data}}, plist.BinaryFormat)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	return c.write("sync", "comm", c.seq, payload)
}

// Receive acknowledges sync frames and returns all protobuf messages in one
// frame. Replies and unrelated payloads are consumed without emitting updates.
func (c *Channel) Receive() ([]*ProtocolMessage, error) {
	for {
		var h [HeaderSize]byte
		if _, err := io.ReadFull(c.conn, h[:]); err != nil {
			return nil, err
		}
		size := binary.BigEndian.Uint32(h[:4])
		if size < HeaderSize || size > MaxFrameSize {
			return nil, fmt.Errorf("mrp: invalid data frame size %d", size)
		}
		body := make([]byte, int(size)-HeaderSize)
		if _, err := io.ReadFull(c.conn, body); err != nil {
			return nil, err
		}
		if string(h[4:8]) == "sync" {
			c.mu.Lock()
			err := c.write("rply", "", binary.BigEndian.Uint64(h[20:28]), nil)
			c.mu.Unlock()
			if err != nil {
				return nil, err
			}
		}
		if len(body) == 0 {
			continue
		}
		var payload struct {
			Params struct {
				Data []byte `plist:"data"`
			} `plist:"params"`
		}
		if _, err := plist.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("mrp: invalid data plist: %w", err)
		}
		if len(payload.Params.Data) == 0 {
			continue
		}
		return DecodeMessages(payload.Params.Data)
	}
}

func DecodeMessages(data []byte) ([]*ProtocolMessage, error) {
	var messages []*ProtocolMessage
	for len(data) > 0 {
		var raw []byte
		// Apple sometimes sends ConfigureConnection without a length prefix.
		if data[0] == 8 {
			raw = data
			data = nil
		} else {
			length, n := binary.Uvarint(data)
			if n <= 0 || length > MaxFrameSize || length > uint64(len(data)-n) {
				return nil, fmt.Errorf("mrp: invalid protobuf length")
			}
			raw = data[n : n+int(length)]
			data = data[n+int(length):]
		}
		msg := &ProtocolMessage{}
		if err := proto.Unmarshal(raw, msg); err != nil {
			return nil, fmt.Errorf("mrp: decode protobuf: %w", err)
		}
		if msg.Type == nil {
			return nil, fmt.Errorf("mrp: missing message type")
		}
		messages = append(messages, msg)
	}
	return messages, nil
}
