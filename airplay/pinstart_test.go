package airplay

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// answerOnce serves a single request on a pipe with the given raw response and
// reports the request path it saw.
func answerOnce(t *testing.T, raw string) (*connection, <-chan string) {
	t.Helper()
	clientSide, serverSide := net.Pipe()
	t.Cleanup(func() { clientSide.Close(); serverSide.Close() })
	paths := make(chan string, 1)
	go func() {
		var pending []byte
		buf := make([]byte, 4096)
		for {
			req, _, err := parseRequest(pending)
			if err != nil {
				return
			}
			if req != nil {
				paths <- req.Path
				serverSide.Write([]byte(raw))
				return
			}
			n, err := serverSide.Read(buf)
			if err != nil {
				return
			}
			pending = append(pending, buf[:n]...)
		}
	}()
	return &connection{tcp: clientSide}, paths
}

func TestPairPinStartRefusalIsSpecific(t *testing.T) {
	const refused = "HTTP/1.1 453 Not Enough Bandwidth\r\nContent-Length: 0\r\n\r\n"
	starts := map[string]func(context.Context, *connection) error{
		"legacy": func(ctx context.Context, c *connection) error {
			return (&legacyPairSetup{conn: c}).startRequest(ctx)
		},
		"hap": func(ctx context.Context, c *connection) error { return pairPinStart(ctx, c, "3") },
	}
	for name, start := range starts {
		t.Run(name, func(t *testing.T) {
			conn, paths := answerOnce(t, refused)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := start(ctx, conn)
			if got := <-paths; got != "/pair-pin-start" {
				t.Fatalf("request path = %q", got)
			}
			if err == nil {
				t.Fatal("expected an error")
			}
			if !IsPINPairingUnavailable(err) || IsBusy(err) || IsAuthFailure(err) {
				t.Fatalf("classification wrong for %v", err)
			}
			msg := err.Error()
			if !strings.Contains(msg, "PIN pairing") || !strings.Contains(msg, "status 453") || strings.Contains(msg, "saved AirPlay code") {
				t.Fatalf("message = %q", msg)
			}
		})
	}
}

func TestPairPinStartOtherStatusesKeepGenericError(t *testing.T) {
	conn, _ := answerOnce(t, "HTTP/1.1 500 Oops\r\nContent-Length: 0\r\n\r\n")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := (&legacyPairSetup{conn: conn}).startRequest(ctx)
	if err == nil || IsPINPairingUnavailable(err) || IsBusy(err) || strings.Contains(err.Error(), "PIN pairing") {
		t.Fatalf("500 misclassified: %v", err)
	}
	// A 453 on another request keeps its busy meaning.
	busy := &StatusError{What: "POST /play", Code: 453, Message: "Not Enough Bandwidth"}
	if !IsBusy(busy) || IsPINPairingUnavailable(busy) {
		t.Fatalf("play 453 misclassified: %v", busy)
	}
}
