package simulator_test

import (
	"context"
	"errors"
	"github.com/jkiddo/go-atv/airplay"
	"github.com/jkiddo/go-atv/hap"
	"github.com/jkiddo/go-atv/simulator"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFairPlayCancellationAndFailureRecovery(t *testing.T) {
	r, err := simulator.New(simulator.Config{FairPlay: true, Duration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	props := map[string]string{}
	for _, entry := range r.TXTRecords() {
		k, v, _ := strings.Cut(entry, "=")
		props[k] = v
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finish := false
	c := airplay.New("cancel test", t.TempDir()+"/credentials", "127.0.0.1", airplay.WithPort(r.Port()), airplay.WithProperties(props), airplay.WithFairPlayControl(true), airplay.WithPlaybackInfoHandler(func(info map[string]any) {
		if _, ok := info["duration"]; ok {
			if finish {
				r.Finish()
			} else {
				cancel()
			}
		}
	}))
	start := time.Now()
	if err := c.PlayURL(ctx, "http://example.invalid/cancel.mp4", 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("cancellation took too long")
	}
	if r.Snapshot().PlayerState != "IDLE" {
		t.Fatal("cancel left playback active")
	}
	finish = true
	ctx, cancel = context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	r.FailNextPlay()
	if err := c.PlayURL(ctx, "http://example.invalid/rejected.mp4", 0); err == nil {
		t.Fatal("play rejection ignored")
	}
	if r.Snapshot().PlayCount != 1 {
		t.Fatal("failed play started media")
	}
	if err := c.PlayURL(ctx, "http://example.invalid/retry.mp4", 0); err != nil {
		t.Fatal(err)
	}
	if r.Snapshot().PlayCount != 2 || r.Snapshot().PlayerState != "IDLE" {
		t.Fatalf("bad recovery: %+v", r.Snapshot())
	}
}

func TestFairPlayRejectsWrongReceiverKey(t *testing.T) {
	r, err := simulator.New(simulator.Config{FairPlay: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	props := map[string]string{}
	for _, entry := range r.TXTRecords() {
		k, v, _ := strings.Cut(entry, "=")
		props[k] = v
	}
	props["pk"] = strings.Repeat("00", 32)
	c := airplay.New("bad key", t.TempDir()+"/credentials", "127.0.0.1", airplay.WithPort(r.Port()), airplay.WithProperties(props), airplay.WithFairPlayControl(true))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.PlayURL(ctx, "http://example.invalid/rejected.mp4", 0); err == nil {
		t.Fatal("wrong receiver key accepted")
	}
	if s := r.Snapshot(); s.PlayCount != 0 || s.FairPlaySetups != 0 {
		t.Fatalf("authentication failure fell back: %+v", s)
	}
}

func TestFairPlayParentDisconnectReleasesPlayback(t *testing.T) {
	r, err := simulator.New(simulator.Config{FairPlay: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	props := map[string]string{}
	for _, entry := range r.TXTRecords() {
		k, v, _ := strings.Cut(entry, "=")
		props[k] = v
	}
	drop := true
	c := airplay.New("disconnect test", t.TempDir()+"/credentials", "127.0.0.1", airplay.WithPort(r.Port()), airplay.WithProperties(props), airplay.WithFairPlayControl(true), airplay.WithPlaybackInfoHandler(func(info map[string]any) {
		if _, ok := info["duration"]; ok {
			if drop {
				r.Disconnect()
			} else {
				r.Finish()
			}
		}
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := c.PlayURL(ctx, "https://example.invalid/disconnect.mp4", 0); err == nil {
		t.Fatal("disconnected transport accepted")
	}
	if r.Snapshot().PlayerState != "IDLE" {
		t.Fatal("parent disconnect retained playback")
	}
	drop = false
	if err := c.PlayURL(ctx, "https://example.invalid/reconnect.mp4", 0); err != nil {
		t.Fatal(err)
	}
}

func TestFairPlayNativeVideoAndReconnect(t *testing.T) {
	var mu sync.Mutex
	var events []simulator.ProtocolEvent
	receiver, e := simulator.New(simulator.Config{FairPlay: true, Duration: 10 * time.Second, Trace: func(e simulator.ProtocolEvent) { mu.Lock(); events = append(events, e); mu.Unlock() }})
	if e != nil {
		t.Fatal(e)
	}
	defer receiver.Close()
	properties := map[string]string{}
	for _, txt := range receiver.TXTRecords() {
		k, v, _ := strings.Cut(txt, "=")
		properties[k] = v
	}
	client := airplay.New("integration", t.TempDir()+"/credentials", "127.0.0.1", airplay.WithPort(receiver.Port()), airplay.WithProperties(properties), airplay.WithFairPlayControl(true), airplay.WithPlaybackInfoHandler(func(info map[string]any) {
		if _, ok := info["duration"]; ok {
			receiver.Advance(11 * time.Second)
		}
	}))
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		e := client.PlayURL(ctx, "https://example.invalid/test.mp4", 0)
		cancel()
		if e != nil {
			t.Fatal(e)
		}
	}
	state := receiver.Snapshot()
	if state.PlayCount != 2 || state.FairPlaySetups != 4 || state.EncryptedRequests < 6 {
		t.Fatalf("incomplete lifecycle: %+v", state)
	}
	mu.Lock()
	defer mu.Unlock()
	setup, record, teardown, play, acknowledgements := 0, 0, 0, 0, 0
	for _, e := range events {
		if e.Method == "CONNECT" {
			continue
		}
		// A peer may close with an event still in flight during normal teardown.
		if e.Method == "" && strings.Contains(e.Error, "connection reset by peer") {
			continue
		}
		if e.Status != 200 && !(e.Path == "/reverse" && e.Status == 101) {
			t.Fatalf("protocol failure: %+v", e)
		}
		switch e.Method {
		case "EVENT-ACK":
			if !e.Encrypted {
				t.Fatal("unencrypted event acknowledgement")
			}
			acknowledgements++
		case "SETUP":
			setup++
		case "RECORD":
			record++
		case "TEARDOWN":
			teardown++
		}
		if e.Path == "/play" {
			if !e.Encrypted {
				t.Fatal("unencrypted play")
			}
			play++
		}
	}
	if setup != 2 || record != 2 || teardown != 2 || play != 2 {
		t.Fatalf("counts setup=%d record=%d teardown=%d play=%d", setup, record, teardown, play)
	}
	if acknowledgements < 2 {
		t.Fatalf("missing reverse acknowledgements: %d", acknowledgements)
	}
}

func TestFairPlayPINPairing(t *testing.T) {
	r, e := simulator.New(simulator.Config{FairPlay: true, PIN: "1234", Duration: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	props := map[string]string{}
	for _, entry := range r.TXTRecords() {
		k, v, _ := strings.Cut(entry, "=")
		props[k] = v
	}
	c := airplay.New("PIN test", t.TempDir()+"/credentials", "127.0.0.1", airplay.WithPort(r.Port()), airplay.WithProperties(props), airplay.WithFairPlayControl(true), airplay.WithPlaybackInfoHandler(func(info map[string]any) {
		if _, ok := info["duration"]; ok {
			r.Finish()
		}
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if e = c.StartPairing(ctx); e != nil {
		t.Fatal(e)
	}
	if e = c.FinishPairing(ctx, "9999"); e == nil {
		t.Fatal("wrong PIN accepted")
	}
	c.CancelPairing()
	if e = c.StartPairing(ctx); e != nil {
		t.Fatal(e)
	}
	if e = c.FinishPairing(ctx, "1234"); e != nil {
		t.Fatal(e)
	}
	c.CancelPairing()
	if e = c.PlayURL(ctx, "http://example.invalid/pin.mp4", 0); e != nil {
		t.Fatal(e)
	}
	if r.Snapshot().FairPlaySetups != 2 {
		t.Fatal("missing encrypted session")
	}
}

func TestFairPlayPasswordAndCombinedAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name, pin string
		hidden    bool
	}{{"password", "", false}, {"hidden password", "", true}, {"PIN plus password", "1234", false}} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := simulator.New(simulator.Config{FairPlay: true, PIN: tc.pin, Password: "test secret,with punctuation", HidePasswordStatus: tc.hidden, Duration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			props := map[string]string{}
			for _, entry := range r.TXTRecords() {
				k, v, _ := strings.Cut(entry, "=")
				props[k] = v
			}
			if props["pw"] == "true" == tc.hidden {
				t.Fatal("incorrect password advertisement")
			}
			path := t.TempDir() + "/credentials"
			c := airplay.New("password test", path, "127.0.0.1", airplay.WithPort(r.Port()), airplay.WithProperties(props), airplay.WithFairPlayControl(true), airplay.WithPlaybackInfoHandler(func(info map[string]any) {
				if _, ok := info["duration"]; ok {
					waitFor(t, func() bool { s := r.Snapshot(); return s.EventResponses >= 1 && s.TimingReplies >= 3 })
					r.Finish()
				}
			}))
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			if tc.pin != "" {
				if err := c.StartPairing(ctx); err != nil {
					t.Fatal(err)
				}
				if err := c.FinishPairing(ctx, tc.pin); err != nil {
					t.Fatal(err)
				}
				c.CancelPairing()
			} else {
				if err := hap.SaveCredentials(path, r.Credentials()); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.PlayURL(ctx, "https://example.invalid/protected.mp4", 0); err == nil {
				t.Fatal("play without password accepted")
			}
			required, err := c.StartPasswordPairing(ctx)
			if err != nil || !required {
				t.Fatalf("password challenge: %t %v", required, err)
			}
			if err := c.FinishPasswordPairing(ctx, "wrong"); err == nil {
				t.Fatal("wrong password accepted")
			}
			if err := c.FinishPasswordPairing(ctx, "test secret,with punctuation"); err != nil {
				t.Fatal(err)
			}
			if err := c.PlayURL(ctx, "https://example.invalid/protected.mp4", 0); err != nil {
				t.Fatal(err)
			}
			s := r.Snapshot()
			if s.DigestChallenges < 3 || s.EventResponses != 1 || s.TimingReplies != 3 || s.EventErrors != 0 || s.TimingErrors != 0 || s.PlayCount != 1 {
				t.Fatalf("incomplete protected lifecycle: %+v", s)
			}
		})
	}
}
