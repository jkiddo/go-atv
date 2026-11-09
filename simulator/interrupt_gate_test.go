package simulator_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jkiddo/go-atv/airplay"
	"github.com/jkiddo/go-atv/hap"
	"github.com/jkiddo/go-atv/simulator"
)

func newGateClient(t *testing.T, receiver *simulator.Receiver) (*airplay.Client, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials")
	if err := hap.SaveCredentials(path, receiver.Credentials()); err != nil {
		t.Fatal(err)
	}
	client := airplay.New("gate-test", path, "127.0.0.1", airplay.WithPort(receiver.Port()), airplay.WithProperties(map[string]string{"features": "0x1"}))
	return client, path
}

func enterCode(t *testing.T, ctx context.Context, client *airplay.Client, code string) {
	t.Helper()
	required, err := client.StartPasswordPairing(ctx)
	if err != nil || !required {
		t.Fatalf("code challenge: required=%v err=%v", required, err)
	}
	if err := client.FinishPasswordPairing(ctx, code); err != nil {
		t.Fatalf("enter code %q: %v", code, err)
	}
}

func rawRequest(t *testing.T, addr string, request string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := fmt.Fprint(conn, request); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(line)
}

// An AppleTV3,2 (12H1006) refuses everything except /info and pair-verify from
// a new connection while another connection holds a session, even /stop with
// the owner's session ID, and recovers as soon as the holder disconnects.
func TestInterruptGateHeldConnection(t *testing.T) {
	receiver, err := simulator.New(simulator.Config{InterruptGate: true, Password: "1234", Duration: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	holder, holderPath := newGateClient(t, receiver)
	enterCode(t, ctx, holder, "1234")
	holderDone := make(chan error, 1)
	go func() { holderDone <- holder.PlayURL(ctx, "https://example.invalid/a.mp4", 0) }()
	waitFor(t, func() bool { return receiver.Snapshot().PlayerState == "PLAYING" })

	// A second sender is refused with 453 and the error is busy, not auth.
	second, secondPath := newGateClient(t, receiver)
	if err := os.WriteFile(secondPath+".password", []byte("1234\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = second.PlayURL(ctx, "https://example.invalid/b.mp4", 0)
	if !airplay.IsBusy(err) || airplay.IsAuthFailure(err) {
		t.Fatalf("second sender error = %v, want busy", err)
	}
	if strings.Contains(err.Error(), "code may have changed") {
		t.Fatalf("busy receiver blamed the saved code: %v", err)
	}
	if got := receiver.Snapshot().URL; got != "https://example.invalid/a.mp4" {
		t.Fatalf("holder's media was replaced: %q", got)
	}

	// Even /stop addressed to the holder's own session ID is refused from a new
	// connection, while /info is still answered.
	sessionID, err := os.ReadFile(holderPath + ".session")
	if err != nil {
		t.Fatal(err)
	}
	addr := receiver.Addr().String()
	stop := fmt.Sprintf("POST /stop HTTP/1.1\r\nX-Apple-Session-ID: %s\r\nContent-Length: 0\r\n\r\n", strings.TrimSpace(string(sessionID)))
	if got := rawRequest(t, addr, stop); !strings.HasPrefix(got, "HTTP/1.1 453") {
		t.Fatalf("/stop from a new connection = %q, want 453", got)
	}
	if got := rawRequest(t, addr, "GET /playback-info HTTP/1.1\r\nContent-Length: 0\r\n\r\n"); !strings.HasPrefix(got, "HTTP/1.1 453") {
		t.Fatalf("/playback-info from a new connection = %q, want 453 before any Digest challenge", got)
	}
	if got := rawRequest(t, addr, "GET /info HTTP/1.1\r\nContent-Length: 0\r\n\r\n"); !strings.HasPrefix(got, "HTTP/1.1 200") {
		t.Fatalf("/info = %q, want 200", got)
	}

	// Closing the holder's connection frees the receiver at once.
	receiver.Disconnect()
	// The holder either errors or treats the now-idle receiver as playback
	// having ended; both are fine, it just must stop.
	select {
	case <-holderDone:
	case <-ctx.Done():
		t.Fatal("holder did not return after disconnect")
	}
	waitFor(t, func() bool { return receiver.Snapshot().PlayerState == "IDLE" })
	secondDone := make(chan error, 1)
	go func() { secondDone <- second.PlayURL(ctx, "https://example.invalid/b.mp4", 0) }()
	waitFor(t, func() bool { return receiver.Snapshot().URL == "https://example.invalid/b.mp4" })
	receiver.Finish()
	if err := <-secondDone; err != nil {
		t.Fatalf("second sender after release: %v", err)
	}
}

// A stale on-screen code yields 453 on /play after the probe was challenged,
// not 401, and the TV shows a new code. The client says the code may be stale.
func TestInterruptGateStaleCode(t *testing.T) {
	receiver, err := simulator.New(simulator.Config{InterruptGate: true, Password: "1234", Duration: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	client, _ := newGateClient(t, receiver)
	enterCode(t, ctx, client, "1234")

	rotated := receiver.RotateAirPlayCode()
	if rotated == "" || rotated == "1234" {
		t.Fatalf("rotated code = %q", rotated)
	}
	err = client.PlayURL(ctx, "https://example.invalid/video.mp4", 0)
	var status *airplay.StatusError
	if !errors.As(err, &status) || status.Code != 453 || !airplay.IsBusy(err) || airplay.IsAuthFailure(err) {
		t.Fatalf("stale-code error = %v, want 453", err)
	}
	if !strings.Contains(err.Error(), "on-screen code may have changed") {
		t.Fatalf("error lacks stale-code hint: %v", err)
	}
	if receiver.Snapshot().PlayCount != 0 {
		t.Fatal("receiver played with a stale code")
	}
	shown := receiver.AirPlayCode()
	if shown == rotated {
		t.Fatalf("code did not rotate after the rejected attempt: %q", shown)
	}

	// Entering the code now on screen restores playback.
	enterCode(t, ctx, client, shown)
	done := make(chan error, 1)
	go func() { done <- client.PlayURL(ctx, "https://example.invalid/video.mp4", 0) }()
	waitFor(t, func() bool { return receiver.Snapshot().PlayerState == "PLAYING" })
	receiver.Finish()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestInterruptGateRequiresLegacyMode(t *testing.T) {
	for _, config := range []simulator.Config{{InterruptGate: true, MRP: true}, {InterruptGate: true, FairPlay: true}} {
		if r, err := simulator.New(config); err == nil {
			r.Close()
			t.Fatalf("accepted %+v", config)
		}
	}
}
