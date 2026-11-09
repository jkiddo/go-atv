package airplay

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseRejectsMalformedFraming(t *testing.T) {
	cases := map[string]string{
		"negative length":      "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nabc",
		"signed length":        "HTTP/1.1 200 OK\r\nContent-Length: +3\r\n\r\nabc",
		"non-numeric length":   "HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\nabc",
		"length list":          "HTTP/1.1 200 OK\r\nContent-Length: 3, 3\r\n\r\nabc",
		"empty length":         "HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\n",
		"huge length":          "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n",
		"over body cap":        "HTTP/1.1 200 OK\r\nContent-Length: 16777217\r\n\r\n",
		"conflicting lengths":  "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd",
		"oversized headers":    "HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("a", maxHeaderBytes+1) + "\r\n\r\n",
		"unterminated headers": "HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("a", maxHeaderBytes+1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			// A panic here is itself a failure.
			if resp, _, err := parseResponse([]byte(raw)); err == nil || resp != nil {
				t.Fatalf("parseResponse accepted %q: resp=%v err=%v", name, resp, err)
			}
			request := strings.Replace(raw, "HTTP/1.1 200 OK", "POST /x HTTP/1.1", 1)
			if req, _, err := parseRequest([]byte(request)); err == nil || req != nil {
				t.Fatalf("parseRequest accepted %q: req=%v err=%v", name, req, err)
			}
		})
	}
}

func TestParseAcceptsWellFormedFraming(t *testing.T) {
	// Repeated identical Content-Length headers are harmless.
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 3\r\ncontent-length: 3\r\n\r\nabcNEXT"
	resp, rest, err := parseResponse([]byte(raw))
	if err != nil || resp == nil || string(resp.Body) != "abc" || string(rest) != "NEXT" {
		t.Fatalf("resp=%+v rest=%q err=%v", resp, rest, err)
	}
	// An incomplete body, and no Content-Length at all, are not errors.
	if resp, _, err := parseResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")); resp != nil || err != nil {
		t.Fatalf("incomplete body: resp=%v err=%v", resp, err)
	}
	if resp, _, err := parseResponse([]byte("HTTP/1.1 200 OK\r\n\r\n")); resp == nil || err != nil || len(resp.Body) != 0 {
		t.Fatalf("no length: resp=%v err=%v", resp, err)
	}
	// A body exactly at the cap is within limits (the rest has not arrived).
	if _, _, err := parseResponse([]byte("HTTP/1.1 200 OK\r\nContent-Length: 16777216\r\n\r\n")); err != nil {
		t.Fatalf("length at cap rejected: %v", err)
	}
}

func TestExchangeClosesConnectionOnFramingError(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer serverSide.Close()
	conn := &connection{tcp: clientSide}
	serverDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		if _, err := serverSide.Read(buf); err != nil {
			serverDone <- err
			return
		}
		if _, err := serverSide.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nabc")); err != nil {
			serverDone <- err
			return
		}
		// The client must hang up rather than keep a desynchronised stream.
		serverSide.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := serverSide.Read(buf)
		if err == io.EOF {
			err = nil
		}
		serverDone <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := conn.get(ctx, "/info", nil); err == nil || !strings.Contains(err.Error(), "Content-Length") {
		t.Fatalf("exchange error = %v, want a Content-Length framing error", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("connection was not closed after the framing error: %v", err)
	}
	if len(conn.pending) != 0 {
		t.Fatalf("pending bytes kept after framing error: %q", conn.pending)
	}
}
