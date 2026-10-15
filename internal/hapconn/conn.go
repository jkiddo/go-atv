// Package hapconn adapts a TCP stream to HAP's authenticated record framing.
package hapconn

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/jkiddo/go-atv/hap"
)

// Conn supports one concurrent reader and writer, like net.Conn.
type Conn struct {
	net.Conn
	session         *hap.Session
	readMu, writeMu sync.Mutex
	pending         []byte
}

func New(conn net.Conn, outputKey, inputKey []byte) (*Conn, error) {
	session, err := hap.NewSession(outputKey, inputKey)
	if err != nil {
		return nil, err
	}
	return &Conn{Conn: conn, session: session}, nil
}

func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for len(c.pending) == 0 {
		var header [2]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		size := int(binary.LittleEndian.Uint16(header[:]))
		if size > 1024 {
			return 0, fmt.Errorf("hap: oversized record: %d", size)
		}
		frame := make([]byte, 2+size+16)
		copy(frame, header[:])
		if _, err := io.ReadFull(c.Conn, frame[2:]); err != nil {
			return 0, err
		}
		plain, err := c.session.Decrypt(frame)
		if err != nil {
			return 0, err
		}
		c.pending = plain
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	out := c.session.Encrypt(p)
	for len(out) > 0 {
		n, err := c.Conn.Write(out)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.ErrShortWrite
		}
		out = out[n:]
	}
	return len(p), nil
}
