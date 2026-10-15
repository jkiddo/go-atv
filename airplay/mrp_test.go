package airplay_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jkiddo/go-atv/airplay"
	"github.com/jkiddo/go-atv/hap"
	"github.com/jkiddo/go-atv/mrp"
	"github.com/jkiddo/go-atv/simulator"
)

func number(v float64) *float64 { return &v }
func newMRPClient(t *testing.T) (*simulator.Receiver, *airplay.Client) {
	t.Helper()
	r, err := simulator.New(simulator.Config{MRP: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	path := filepath.Join(t.TempDir(), "credentials")
	if err := hap.SaveCredentials(path, r.Credentials()); err != nil {
		t.Fatal(err)
	}
	return r, airplay.New("MRP test", path, "127.0.0.1", airplay.WithPort(r.Port()))
}
func TestMRPPlaybackLifecycle(t *testing.T) {
	r, c := newMRPClient(t)
	r.SetNowPlaying(mrp.State{PlaybackState: "playing", App: "com.example.video", AppName: "Video", ItemID: "episode1", Title: "First episode", ContentURL: "https://example.test/episode1.mp4", MediaType: "video", Position: number(12), Duration: number(120), PlaybackRate: number(1)})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	updates := make(chan mrp.State, 20)
	done := make(chan error, 1)
	go func() { done <- c.WatchNowPlaying(ctx, func(s mrp.State) { updates <- s }) }()
	next := func() mrp.State {
		t.Helper()
		select {
		case s := <-updates:
			return s
		case err := <-done:
			t.Fatalf("monitor ended: %v", err)
		case <-ctx.Done():
			t.Fatal("timed out waiting for state")
		}
		return mrp.State{}
	}
	first := next()
	if first.ContentURL != "https://example.test/episode1.mp4" || first.Title != "First episode" || first.AppName != "Video" || first.Position == nil || *first.Position != 12 || first.PlaybackState != "playing" {
		t.Fatalf("initial: %+v", first)
	}
	paused := first
	paused.PlaybackState = "paused"
	paused.PlaybackRate = number(0)
	r.SetNowPlaying(paused)
	if s := next(); s.PlaybackState != "paused" || s.Title != first.Title {
		t.Fatalf("pause: %+v", s)
	}
	r.Advance(time.Second) // paused time must not advance
	r.SetNowPlaying(mrp.State{PlaybackState: "playing", App: "com.example.music", AppName: "Music", ItemID: "song1", Title: "A song", Artist: "Artist", Album: "Album", MediaType: "audio", Position: number(0), Duration: number(200), PlaybackRate: number(1)})
	if s := next(); s.ContentURL != "" || s.Title != "A song" || s.App != "com.example.music" || s.Artist != "Artist" || s.SeriesName != "" {
		t.Fatalf("app switch: %+v", s)
	}
	r.Advance(5 * time.Second)
	if s := next(); s.Position == nil || *s.Position != 5 {
		t.Fatalf("position: %+v", s)
	}
	r.Finish()
	if s := next(); s.PlaybackState != "stopped" {
		t.Fatalf("finish: %+v", s)
	}
	r.SetNowPlaying(mrp.State{PlaybackState: "idle"})
	if s := next(); s.PlaybackState != "idle" || s.App != "" || s.Title != "" {
		t.Fatalf("clear: %+v", s)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation blocked")
	}
	// The event socket and encrypted control requests were exercised, not bypassed.
	counters := r.Snapshot()
	if counters.EncryptedRequests < 3 || counters.EventConnections != 1 || counters.EventResponses != 1 || counters.EventErrors != 0 {
		t.Fatalf("transport counters: %+v", counters)
	}
}
func TestMRPDisconnectAndReconnect(t *testing.T) {
	r, c := newMRPClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	initial := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() { done <- c.WatchNowPlaying(ctx, func(mrp.State) { initial <- struct{}{} }) }()
	select {
	case <-initial:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	r.Disconnect()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("disconnect must return error")
		}
	case <-ctx.Done():
		t.Fatal("disconnect not propagated")
	}
	r.SetNowPlaying(mrp.State{PlaybackState: "playing", App: "new.app", Title: "After reconnect"})
	child, stop := context.WithCancel(ctx)
	defer stop()
	err := c.WatchNowPlaying(child, func(s mrp.State) {
		if s.Title != "After reconnect" {
			t.Errorf("stale state: %+v", s)
		}
		stop()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
func TestMRPRejectsInvalidCredentials(t *testing.T) {
	r, _ := newMRPClient(t)
	cred := r.Credentials()
	cred.LTSK[0] ^= 0xff
	path := filepath.Join(t.TempDir(), "wrong")
	hap.SaveCredentials(path, cred)
	c := airplay.New("test", path, "127.0.0.1", airplay.WithPort(r.Port()))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.WatchNowPlaying(ctx, func(mrp.State) { t.Error("unexpected update") }); err == nil {
		t.Fatal("wrong controller signature accepted")
	}
	legacy, _ := simulator.New(simulator.Config{})
	defer legacy.Close()
	hap.SaveCredentials(path, legacy.Credentials())
	if err := c.WatchNowPlaying(ctx, func(mrp.State) {}); err == nil || !strings.Contains(err.Error(), "HAP credentials") {
		t.Fatalf("legacy credentials: %v", err)
	}
}
