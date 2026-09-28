package airplay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"howett.net/plist"

	"github.com/jkiddo/go-atv/hap"
)

const bplistContentType = "application/x-apple-binary-plist"

// packPlist encodes a value as a binary plist.
func packPlist(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := plist.NewBinaryEncoder(&buf).Encode(v); err != nil {
		return nil, fmt.Errorf("airplay: encode plist: %w", err)
	}
	return buf.Bytes(), nil
}

// unpackPlist decodes a (binary or XML) plist body into a generic map.
// An empty body yields an empty map.
func unpackPlist(data []byte) (map[string]any, error) {
	if len(data) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if _, err := plist.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("airplay: decode plist: %w", err)
	}
	return out, nil
}

// rtspSession issues RTSP requests (and AirPlay's HTTP-methods-over-RTSP
// hybrids) on a connection, mirroring pyatv's RtspSession.
type rtspSession struct {
	conn            *connection
	cseq            int
	sessionID       uint32
	dacpID          string
	activeRemote    uint32
	playbackHandler func(map[string]any)
}

func newRTSPSession(conn *connection, credentials ...*hap.Credentials) *rtspSession {
	var randBytes [16]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	session := &rtspSession{
		conn:         conn,
		sessionID:    binary.BigEndian.Uint32(randBytes[0:4]),
		dacpID:       fmt.Sprintf("%X", binary.BigEndian.Uint64(randBytes[4:12])),
		activeRemote: binary.BigEndian.Uint32(randBytes[12:16]),
	}
	// Legacy sender-identity experiment: keep DACP-ID and Client-Instance
	// tied to the persisted public pairing ID across connections/restarts.
	// The RTSP session ID and Active-Remote remain scoped to this session.
	if len(credentials) > 0 && credentials[0] != nil && credentials[0].IsLegacy() {
		session.dacpID = fmt.Sprintf("%X", credentials[0].ClientID)
	}
	return session
}

// uri is the session URI used when a request has no explicit URI.
func (s *rtspSession) uri() string {
	return fmt.Sprintf("rtsp://%s/%d", s.conn.localIP, s.sessionID)
}

// exchange sends an RTSP message and returns the response. A map body is
// encoded as a binary plist; uri may be empty to use the session URI.
func (s *rtspSession) exchange(ctx context.Context, method, uri string, extraHeaders []header, body any) (*response, error) {
	cseq := s.cseq
	s.cseq++

	headers := []header{
		{"CSeq", fmt.Sprintf("%d", cseq)},
		{"DACP-ID", s.dacpID},
		{"Active-Remote", fmt.Sprintf("%d", s.activeRemote)},
		{"Client-Instance", s.dacpID},
	}
	headers = append(headers, extraHeaders...)

	var (
		rawBody     []byte
		contentType string
		err         error
	)
	switch b := body.(type) {
	case nil:
	case []byte:
		rawBody = b
	case map[string]any:
		if rawBody, err = packPlist(b); err != nil {
			return nil, err
		}
		contentType = bplistContentType
	default:
		return nil, fmt.Errorf("airplay: unsupported RTSP body type %T", body)
	}

	if uri == "" {
		uri = s.uri()
	}
	return s.conn.exchange(ctx, request{
		Method:      method,
		URI:         uri,
		Protocol:    "RTSP/1.0",
		ContentType: contentType,
		Headers:     headers,
		Body:        rawBody,
	})
}

// setup sends a SETUP message with a binary plist body.
func (s *rtspSession) setup(ctx context.Context, body map[string]any) (*response, error) {
	resp, err := s.exchange(ctx, "SETUP", "", nil, body)
	if err != nil {
		return nil, err
	}
	return resp, errStatus(resp, "SETUP")
}

// record sends a RECORD message.
func (s *rtspSession) record(ctx context.Context) error {
	resp, err := s.exchange(ctx, "RECORD", "", nil, nil)
	if err != nil {
		return err
	}
	return errStatus(resp, "RECORD")
}

// feedback sends the keep-alive POST /feedback message.
func (s *rtspSession) feedback(ctx context.Context) error {
	resp, err := s.exchange(ctx, "POST", "/feedback", nil, nil)
	if err != nil {
		return err
	}
	return errStatus(resp, "POST /feedback")
}
