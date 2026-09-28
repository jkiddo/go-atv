package simulator_test

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jkiddo/go-atv/airplay"
	"github.com/jkiddo/go-atv/hap"
	"github.com/jkiddo/go-atv/simulator"
)

func TestClientPlaybackLifecycle(t *testing.T) {
	for _, password := range []string{"", "test-password"} {
		t.Run("password="+password, func(t *testing.T) {
			receiver, err := simulator.New(simulator.Config{Password: password, Duration: 10 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			path := filepath.Join(t.TempDir(), "credentials")
			observed := make(chan struct{})
			var once sync.Once
			client := airplay.New("simulator-test", path, "127.0.0.1", airplay.WithPort(receiver.Port()), airplay.WithProperties(map[string]string{"features": "0x1"}), airplay.WithPlaybackInfoHandler(func(info map[string]any) {
				if _, playing := info["duration"]; playing {
					once.Do(func() { close(observed) })
				}
			}))
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			if password != "" {
				if err := hap.SaveCredentials(path, receiver.Credentials()); err != nil {
					t.Fatal(err)
				}
				required, err := client.StartPasswordPairing(ctx)
				if err != nil || !required {
					t.Fatalf("password challenge: %v %v", required, err)
				}
				if err := client.FinishPasswordPairing(ctx, "wrong"); err == nil {
					t.Fatal("wrong password accepted")
				}
				if err := client.FinishPasswordPairing(ctx, password); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() { done <- client.PlayURL(ctx, "https://example.invalid/video.mp4", 0) }()
			waitFor(t, func() bool { return receiver.Snapshot().PlayerState == "PLAYING" })
			// A separate client must observe the same receiver state.
			observer := airplay.New("observer", path, "127.0.0.1", airplay.WithPort(receiver.Port()), airplay.WithProperties(map[string]string{"features": "0x1"}))
			info, err := observer.PlaybackInfo(ctx)
			if err != nil || info["duration"] != 10.0 {
				t.Fatalf("status=%v err=%v", info, err)
			}
			receiver.Advance(3 * time.Second)
			if state := receiver.Snapshot(); state.Position != 3 || state.URL != "https://example.invalid/video.mp4" || state.PlayCount != 1 {
				t.Fatalf("state=%+v", state)
			}
			// Give the owning client a chance to observe active playback before completion.
			select {
			case <-observed:
			case <-ctx.Done():
				t.Fatal("owning client never observed playback")
			}
			receiver.Finish()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("playback did not finish")
			}
			info, err = observer.PlaybackInfo(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, playing := info["duration"]; playing {
				t.Fatalf("idle status=%v", info)
			}
		})
	}
}

func TestClientRetryAndCancellation(t *testing.T) {
	r, err := simulator.New(simulator.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.FailNextPlay()
	observed := make(chan struct{})
	var once sync.Once
	client := airplay.New("test", filepath.Join(t.TempDir(), "creds"), "127.0.0.1", airplay.WithPort(r.Port()), airplay.WithAuthMode("open"), airplay.WithProperties(map[string]string{"features": "0x1"}), airplay.WithPlaybackInfoHandler(func(info map[string]any) {
		if _, playing := info["duration"]; playing {
			once.Do(func() { close(observed) })
		}
	}))
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.PlayURL(ctx, "http://example.invalid/video.mp4", 0) }()
	// Wait for the client to establish playback, not just for the receiver to
	// process /play while its response may still be in flight.
	select {
	case <-observed:
	case <-ctx.Done():
		t.Fatal("owning client never observed playback")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancellation succeeded unexpectedly")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("cancellation hung")
	}
	if state := r.Snapshot(); state.PlayerState != "IDLE" || state.PlayCount != 1 {
		t.Fatalf("cancellation failed to stop session: %+v", state)
	}
}

func TestDisconnectAndClose(t *testing.T) {
	r, err := simulator.New(simulator.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c, err := net.Dial("tcp", r.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// A response ensures the connection has been registered by the accept loop.
	c.Write([]byte("GET /playback-info HTTP/1.1\r\nContent-Length: 0\r\n\r\n"))
	c.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 1024)
	if _, err := c.Read(b); err != nil {
		t.Fatal(err)
	}
	r.Disconnect()
	observer := airplay.New("observer", "", "127.0.0.1", airplay.WithPort(r.Port()), airplay.WithAuthMode("open"))
	if _, err := observer.PlaybackInfo(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := net.DialTimeout("tcp", r.Addr().String(), time.Second); err == nil {
		t.Fatal("closed receiver accepted connection")
	}
}

func TestDiscoveryReflectsPassword(t *testing.T) {
	r, err := simulator.New(simulator.Config{Password: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if records := strings.Join(r.TXTRecords(), " "); !strings.Contains(records, "pw=true") || !strings.Contains(records, "features=0x1") {
		t.Fatal(records)
	}
	if _, err := simulator.New(simulator.Config{AdvertiseIP: "192.0.2.1"}); err == nil {
		t.Fatal("advertised unreachable loopback listener")
	}
}

func waitFor(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("receiver state did not change")
}
