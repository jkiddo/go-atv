package companion

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/jkiddo/go-atv/hap"
	"github.com/jkiddo/go-atv/opack"
)

// Message type values used in E_OPACK payloads ("_t").
const (
	messageTypeEvent    = 1
	messageTypeRequest  = 2
	messageTypeResponse = 3
)

// session is a low-level Companion connection: framing, optional encryption
// and request/response correlation. It corresponds to pyatv's
// CompanionConnection + CompanionProtocol pair.
type session struct {
	conn net.Conn

	writeMu sync.Mutex

	mu       sync.Mutex
	cipher   *hap.Cipher
	pending  map[any]chan map[string]any // int64 xid or FrameType
	xid      int64
	closed   bool
	closeErr error

	onEvent func(name string, content map[string]any)
	onClose func(err error)
}

func newSession(conn net.Conn) *session {
	s := &session{
		conn:    conn,
		pending: make(map[any]chan map[string]any),
		xid:     rand.Int63n(1 << 16),
	}
	go s.readLoop()
	return s
}

func dialSession(ctx context.Context, host string, port int) (*session, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, err
	}
	return newSession(conn), nil
}

// enableEncryption switches the connection to encrypted frames using the
// verify-derived keys.
func (s *session) enableEncryption(outputKey, inputKey []byte) error {
	cipher, err := hap.NewCipher(outputKey, inputKey, 12)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cipher = cipher
	s.mu.Unlock()
	return nil
}

func (s *session) close(err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.closeErr = err
	pending := s.pending
	s.pending = make(map[any]chan map[string]any)
	onClose := s.onClose
	s.mu.Unlock()

	s.conn.Close()
	for _, ch := range pending {
		close(ch)
	}
	if onClose != nil {
		onClose(err)
	}
}

func (s *session) readLoop() {
	for {
		frameType, payload, header, err := readFrame(s.conn)
		if err != nil {
			s.close(err)
			return
		}

		s.mu.Lock()
		cipher := s.cipher
		s.mu.Unlock()
		if cipher != nil && len(payload) > 0 {
			payload, err = cipher.Decrypt(payload, nil, header)
			if err != nil {
				s.close(fmt.Errorf("companion: decrypt frame: %w", err))
				return
			}
		}

		switch frameType {
		case FramePSNext, FramePSStart, FramePVNext, FramePVStart:
			s.dispatchAuth(frameType, payload)
		case FrameEOpack, FrameUOpack, FramePOpack:
			s.dispatchOpack(payload)
		default:
			// Ignore unsupported frames (NoOp etc.)
		}
	}
}

func (s *session) dispatchAuth(frameType FrameType, payload []byte) {
	value, _, err := opack.Unpack(payload)
	if err != nil {
		return
	}
	data, ok := value.(map[string]any)
	if !ok {
		return
	}
	s.mu.Lock()
	ch, ok := s.pending[frameType]
	if ok {
		delete(s.pending, frameType)
	}
	s.mu.Unlock()
	if ok {
		ch <- data
	}
}

func (s *session) dispatchOpack(payload []byte) {
	value, _, err := opack.Unpack(payload)
	if err != nil {
		return
	}
	data, ok := value.(map[string]any)
	if !ok {
		return
	}

	messageType, _ := data["_t"].(int64)
	switch messageType {
	case messageTypeEvent:
		name, _ := data["_i"].(string)
		content, _ := data["_c"].(map[string]any)
		s.mu.Lock()
		onEvent := s.onEvent
		s.mu.Unlock()
		if onEvent != nil && name != "" {
			onEvent(name, content)
		}
	case messageTypeResponse:
		xid, ok := data["_x"].(int64)
		if !ok {
			return
		}
		s.mu.Lock()
		ch, found := s.pending[xid]
		if found {
			delete(s.pending, xid)
		}
		s.mu.Unlock()
		if found {
			ch <- data
		}
	}
}

func (s *session) sendFrame(frameType FrameType, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.mu.Lock()
	cipher := s.cipher
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return errors.New("companion: connection closed")
	}

	payloadLength := len(data)
	if cipher != nil && payloadLength > 0 {
		payloadLength += 16 // poly1305 tag
	}
	header := frameHeader(frameType, payloadLength)
	if cipher != nil && len(data) > 0 {
		data = cipher.Encrypt(data, nil, header)
	}
	if _, err := s.conn.Write(append(header, data...)); err != nil {
		return err
	}
	return nil
}

func (s *session) nextXID() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	xid := s.xid
	s.xid++
	return xid
}

// sendOpack sends an OPACK payload without waiting for a response. An "_x"
// transaction id is added if missing (as pyatv does).
func (s *session) sendOpack(frameType FrameType, data map[string]any) error {
	if _, ok := data["_x"]; !ok {
		data["_x"] = s.nextXID()
	}
	packed, err := opack.Pack(data)
	if err != nil {
		return err
	}
	return s.sendFrame(frameType, packed)
}

func (s *session) register(key any) chan map[string]any {
	ch := make(chan map[string]any, 1)
	s.mu.Lock()
	s.pending[key] = ch
	s.mu.Unlock()
	return ch
}

func (s *session) await(ctx context.Context, key any, ch chan map[string]any) (map[string]any, error) {
	select {
	case resp, ok := <-ch:
		if !ok {
			s.mu.Lock()
			err := s.closeErr
			s.mu.Unlock()
			if err == nil {
				err = errors.New("companion: connection closed")
			}
			return nil, err
		}
		return resp, nil
	case <-ctx.Done():
		s.mu.Lock()
		delete(s.pending, key)
		s.mu.Unlock()
		return nil, ctx.Err()
	}
}

// exchangeAuth sends a pairing/verify frame and waits for the reply.
// Responses to *_Start frames arrive as the corresponding *_Next type.
func (s *session) exchangeAuth(ctx context.Context, frameType FrameType, data map[string]any) (map[string]any, error) {
	key := frameType
	switch frameType {
	case FramePSStart:
		key = FramePSNext
	case FramePVStart:
		key = FramePVNext
	}
	ch := s.register(key)
	if err := s.sendOpack(frameType, data); err != nil {
		s.mu.Lock()
		delete(s.pending, key)
		s.mu.Unlock()
		return nil, err
	}
	return s.await(ctx, key, ch)
}

// exchangeOpack sends an E_OPACK request and waits for the response with the
// matching transaction id, translating "_em" into ProtocolError.
func (s *session) exchangeOpack(ctx context.Context, identifier string, content map[string]any) (map[string]any, error) {
	xid := s.nextXID()
	data := map[string]any{
		"_i": identifier,
		"_t": int64(messageTypeRequest),
		"_c": content,
		"_x": xid,
	}
	ch := s.register(xid)
	if err := s.sendOpack(FrameEOpack, data); err != nil {
		s.mu.Lock()
		delete(s.pending, xid)
		s.mu.Unlock()
		return nil, err
	}
	resp, err := s.await(ctx, xid, ch)
	if err != nil {
		return nil, err
	}
	if em, ok := resp["_em"].(string); ok {
		code, _ := resp["_ec"].(int64)
		return nil, &ProtocolError{Command: identifier, Message: em, Code: code}
	}
	return resp, nil
}

// sendEvent sends an E_OPACK event (fire and forget).
func (s *session) sendEvent(identifier string, content map[string]any) error {
	return s.sendOpack(FrameEOpack, map[string]any{
		"_i": identifier,
		"_t": int64(messageTypeEvent),
		"_c": content,
	})
}

// defaultTimeout matches pyatv's per-exchange timeout.
const defaultTimeout = 5 * time.Second

func withDefaultTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, defaultTimeout)
}
