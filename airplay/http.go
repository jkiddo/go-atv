// Package airplay implements the parts of Apple's AirPlay protocol needed
// to stream video from a URL to an Apple TV ("play_url"). The protocol
// implementation is a port of the relevant parts of pyatv.
package airplay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jkiddo/go-atv/hap"
)

const userAgent = "AirPlay/550.10"

// header is a single HTTP/RTSP header. Requests carry ordered header slices
// so messages are formatted deterministically, mirroring pyatv.
type header struct {
	Key   string
	Value string
}

// request is an outgoing HTTP/1.1 or RTSP/1.0 message.
type request struct {
	Method      string
	URI         string
	Protocol    string // "HTTP/1.1" or "RTSP/1.0"; empty means HTTP/1.1
	UserAgent   string // empty means the default AirPlay user agent
	ContentType string
	Headers     []header
	Body        []byte
}

// response is a parsed HTTP/RTSP response. Header keys are lower-cased.
type response struct {
	Protocol string
	Code     int
	Message  string
	Headers  map[string]string
	Body     []byte
}

// incomingRequest is a parsed request received from the device (used on the
// event channel, where the Apple TV acts as HTTP client).
type incomingRequest struct {
	Method   string
	Path     string
	Protocol string
	Headers  map[string]string
	Body     []byte
}

// formatRequest encodes a request following pyatv's _format_message: status
// line, User-Agent, optional Content-Type, Content-Length when a body is
// present, then the caller's headers.
func formatRequest(r request) []byte {
	protocol := r.Protocol
	if protocol == "" {
		protocol = "HTTP/1.1"
	}
	ua := r.UserAgent
	if ua == "" {
		ua = userAgent
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s %s", r.Method, r.URI, protocol)
	fmt.Fprintf(&b, "\r\nUser-Agent: %s", ua)
	if r.ContentType != "" {
		fmt.Fprintf(&b, "\r\nContent-Type: %s", r.ContentType)
	}
	if len(r.Body) > 0 {
		fmt.Fprintf(&b, "\r\nContent-Length: %d", len(r.Body))
	}
	for _, h := range r.Headers {
		fmt.Fprintf(&b, "\r\n%s: %s", h.Key, h.Value)
	}
	b.WriteString("\r\n\r\n")
	b.Write(r.Body)
	return b.Bytes()
}

// splitMessage extracts one complete message (start line, headers, body per
// Content-Length) from data. It returns the start line, headers, body and
// the remaining bytes, or ok=false if data does not yet hold a full message.
func splitMessage(data []byte) (startLine string, headers map[string]string, body, rest []byte, ok bool) {
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	if idx < 0 {
		return "", nil, nil, data, false
	}
	headerBlock := string(data[:idx])
	remainder := data[idx+4:]

	lines := strings.Split(headerBlock, "\r\n")
	headers = make(map[string]string, len(lines)-1)
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		headers[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}

	contentLength := 0
	if cl, exists := headers["content-length"]; exists {
		if n, err := strconv.Atoi(cl); err == nil {
			contentLength = n
		}
	}
	if len(remainder) < contentLength {
		return "", nil, nil, data, false
	}
	return lines[0], headers, remainder[:contentLength], remainder[contentLength:], true
}

// parseResponse parses one response from data, returning the remaining
// unconsumed bytes. A nil response with nil error means more data is needed.
func parseResponse(data []byte) (*response, []byte, error) {
	startLine, headers, body, rest, ok := splitMessage(data)
	if !ok {
		return nil, data, nil
	}
	parts := strings.SplitN(startLine, " ", 3)
	if len(parts) < 2 || !strings.Contains(parts[0], "/") {
		return nil, rest, fmt.Errorf("airplay: malformed response line %q", startLine)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, rest, fmt.Errorf("airplay: malformed status code in %q", startLine)
	}
	message := ""
	if len(parts) == 3 {
		message = parts[2]
	}
	return &response{
		Protocol: parts[0],
		Code:     code,
		Message:  message,
		Headers:  headers,
		Body:     body,
	}, rest, nil
}

// parseRequest parses one request from data, returning the remaining
// unconsumed bytes. A nil request with nil error means more data is needed.
func parseRequest(data []byte) (*incomingRequest, []byte, error) {
	startLine, headers, body, rest, ok := splitMessage(data)
	if !ok {
		return nil, data, nil
	}
	parts := strings.SplitN(startLine, " ", 3)
	if len(parts) != 3 {
		return nil, rest, fmt.Errorf("airplay: malformed request line %q", startLine)
	}
	return &incomingRequest{
		Method:   parts[0],
		Path:     parts[1],
		Protocol: parts[2],
		Headers:  headers,
		Body:     body,
	}, rest, nil
}

// connection is a TCP connection to an AirPlay receiver speaking HTTP/1.1
// and RTSP/1.0 request/response, with optional HAP session encryption.
type connection struct {
	mu      sync.Mutex
	tcp     net.Conn
	session *hap.Session // nil until encryption is enabled
	digest  *digestAuth  // nil until a legacy HTTP Digest challenge is received
	pending []byte       // received plaintext not yet parsed

	legacyPassword    string
	diagnosticHandler func(DiagnosticEvent)

	localIP  string
	remoteIP string
}

const defaultExchangeTimeout = 10 * time.Second

// dial opens a connection to an AirPlay receiver.
func dial(ctx context.Context, address string, port int) (*connection, error) {
	var dialer net.Dialer
	tcp, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	local, _, _ := net.SplitHostPort(tcp.LocalAddr().String())
	remote, _, _ := net.SplitHostPort(tcp.RemoteAddr().String())
	return &connection{tcp: tcp, localIP: local, remoteIP: remote}, nil
}

// enableEncryption switches the connection to HAP session encryption. Data
// already buffered stays plaintext (it was received before enabling).
func (c *connection) enableEncryption(outputKey, inputKey []byte) error {
	session, err := hap.NewSession(outputKey, inputKey)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.session = session
	c.mu.Unlock()
	return nil
}

func (c *connection) close() {
	c.tcp.Close()
}

// interrupt unblocks an in-flight exchange without destroying the TCP
// connection. A caller can reset the deadlines with a subsequent exchange,
// which lets AirPlay v1 send a final session-scoped /stop after cancellation.
func (c *connection) interrupt() {
	_ = c.tcp.SetDeadline(time.Now())
}

// exchange sends a request and waits for the next response on the
// connection. Exchanges are serialized; AirPlay control connections are
// strictly request/response.
func (c *connection) exchange(ctx context.Context, r request) (*response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	deadline := time.Now().Add(defaultExchangeTimeout)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}

	if c.digest != nil && !requestHasHeader(r, "Authorization") {
		r.Headers = append(append([]header(nil), r.Headers...), header{
			Key:   "Authorization",
			Value: c.digest.authorization(r.Method, r.URI),
		})
	}
	out := formatRequest(r)
	if c.session != nil {
		out = c.session.Encrypt(out)
	}
	if err := c.tcp.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := c.tcp.Write(out); err != nil {
		return nil, fmt.Errorf("airplay: send %s %s: %w", r.Method, r.URI, err)
	}

	buf := make([]byte, 16384)
	for {
		resp, rest, err := parseResponse(c.pending)
		if err != nil {
			return nil, err
		}
		if resp != nil {
			c.pending = rest
			return resp, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := c.tcp.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
		n, err := c.tcp.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("airplay: receive %s %s: %w", r.Method, r.URI, err)
		}
		data := buf[:n]
		if c.session != nil {
			if data, err = c.session.Decrypt(data); err != nil {
				return nil, err
			}
		}
		c.pending = append(c.pending, data...)
	}
}

func requestHasHeader(r request, key string) bool {
	for _, item := range r.Headers {
		if strings.EqualFold(item.Key, key) {
			return true
		}
	}
	return false
}

// post sends an HTTP POST and returns the response.
func (c *connection) post(ctx context.Context, uri, contentType string, headers []header, body []byte) (*response, error) {
	return c.exchange(ctx, request{
		Method:      "POST",
		URI:         uri,
		ContentType: contentType,
		Headers:     headers,
		Body:        body,
	})
}

// get sends an HTTP GET and returns the response.
func (c *connection) get(ctx context.Context, uri string, headers []header) (*response, error) {
	return c.exchange(ctx, request{Method: "GET", URI: uri, Headers: headers})
}

// errStatus converts a non-2xx response into an error.
func errStatus(resp *response, what string) error {
	if resp.Code >= 200 && resp.Code < 300 {
		return nil
	}
	return &StatusError{What: what, Code: resp.Code, Message: resp.Message}
}

// StatusError is returned when the receiver answers with an error status.
type StatusError struct {
	What    string
	Code    int
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("airplay: %s failed with status %d %s", e.What, e.Code, e.Message)
}

// IsAuthFailure reports whether the error looks like the receiver rejected
// our credentials (HTTP 470/401/403 on AirPlay endpoints).
func IsAuthFailure(err error) bool {
	var statusErr *StatusError
	if errors.As(err, &statusErr) {
		return statusErr.Code == 470 || statusErr.Code == 401 || statusErr.Code == 403
	}
	return false
}
