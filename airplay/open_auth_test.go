package airplay

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

type openExchange struct {
	method string
	path   string
	auth   bool
}

// startFauxV1Receiver accepts one control connection and answers each request
// with the given status and body. Exchanges arrive on a channel so tests can
// assert the receiver was addressed without prior authentication attempts.
func startFauxV1Receiver(t *testing.T, answer func(method, path string) (int, string)) (int, chan openExchange) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	exchanges := make(chan openExchange, 8)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			req, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			if req.ContentLength > 0 {
				if _, err := io.CopyN(io.Discard, reader, req.ContentLength); err != nil {
					return
				}
			}
			select {
			case exchanges <- openExchange{method: req.Method, path: req.URL.Path, auth: req.Header.Get("Authorization") != ""}:
			default:
			}
			code, body := answer(req.Method, req.URL.Path)
			if _, err := fmt.Fprintf(conn, "HTTP/1.1 %d OK\r\nContent-Length: %d\r\n\r\n%s", code, len(body), body); err != nil {
				return
			}
			if req.Method == "POST" && req.URL.Path == "/play" {
				// Send FIN but drain the client's following status request.
				// Closing with unread data can send RST instead, making this
				// authentication-only test depend on TCP scheduling.
				_ = conn.(*net.TCPConn).CloseWrite()
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(io.Discard, reader)
				return
			}
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, exchanges
}

func drainedExchanges(t *testing.T, exchanges chan openExchange) []openExchange {
	t.Helper()
	var seen []openExchange
	for {
		select {
		case exchange := <-exchanges:
			seen = append(seen, exchange)
		case <-time.After(200 * time.Millisecond):
			return seen
		}
	}
}

func assertNoAuthenticationAttempt(t *testing.T, seen []openExchange) {
	t.Helper()
	for _, exchange := range seen {
		if exchange.auth {
			t.Fatalf("receiver saw an authenticated request: %s %s", exchange.method, exchange.path)
		}
	}
}

func TestPlayURLWithOpenAuthSkipsAuthentication(t *testing.T) {
	port, exchanges := startFauxV1Receiver(t, func(method, path string) (int, string) {
		return http.StatusOK, ""
	})
	client := New("goatv-test", filepath.Join(t.TempDir(), "credentials"), "127.0.0.1",
		WithPort(port), WithAuthMode("open"), WithProperties(map[string]string{"features": "5,0"}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.PlayURL(ctx, "http://example.test/video.mp4", 0); err != nil {
		t.Fatalf("open playback failed: %v", err)
	}

	seen := drainedExchanges(t, exchanges)
	if len(seen) == 0 || seen[0].method != "POST" || seen[0].path != "/play" {
		t.Fatalf("open playback did not start with an unauthenticated /play: %v", seen)
	}
	assertNoAuthenticationAttempt(t, seen)
}

func TestPlayURLWithOpenAuthSurfacesProtectedReceiver(t *testing.T) {
	port, exchanges := startFauxV1Receiver(t, func(method, path string) (int, string) {
		return http.StatusUnauthorized, ""
	})
	client := New("goatv-test", filepath.Join(t.TempDir(), "credentials"), "127.0.0.1",
		WithPort(port), WithAuthMode("open"), WithProperties(map[string]string{"features": "5,0"}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := client.PlayURL(ctx, "http://example.test/video.mp4", 0)
	var invalidAuth *InvalidAuth
	if !errors.As(err, &invalidAuth) {
		t.Fatalf("protected receiver must surface as invalid authentication, got %v", err)
	}

	seen := drainedExchanges(t, exchanges)
	assertNoAuthenticationAttempt(t, seen)
}

func TestPlaybackInfoWithOpenAuthProbesUnauthenticated(t *testing.T) {
	port, exchanges := startFauxV1Receiver(t, func(method, path string) (int, string) {
		return http.StatusOK, ""
	})
	client := New("goatv-test", filepath.Join(t.TempDir(), "credentials"), "127.0.0.1",
		WithPort(port), WithAuthMode("open"), WithProperties(map[string]string{"features": "5,0"}))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	info, err := client.PlaybackInfo(ctx)
	if err != nil {
		t.Fatalf("open status probe failed: %v", err)
	}
	if _, playing := info["duration"]; playing {
		t.Fatalf("empty status body reported active playback: %v", info)
	}

	seen := drainedExchanges(t, exchanges)
	if len(seen) != 1 || seen[0].method != "GET" || seen[0].path != "/playback-info" {
		t.Fatalf("open status probe must be a single unauthenticated request: %v", seen)
	}
	assertNoAuthenticationAttempt(t, seen)
}
