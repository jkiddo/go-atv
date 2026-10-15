package simulator_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jkiddo/go-atv/airplay"
	"github.com/jkiddo/go-atv/hap"
	"github.com/jkiddo/go-atv/simulator"
)

// Hardware provenance: AppleTV3,2, osBuildVersion 12H1006, srcvers 220.68,
// observed 2026-10-14. Do not generalize the parent lifetime to newer Apple TVs.
func TestFairPlayAppleTV32Build12H1006PlaybackAndReplay(t *testing.T) {
	for _, password := range []string{"", "synthetic hardware password"} {
		name := "open"
		if password != "" {
			name = "password"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var mu sync.Mutex
			var events []simulator.ProtocolEvent
			r, err := simulator.New(simulator.Config{
				FairPlay: true, FairPlayProfile: simulator.FairPlayAppleTV32_12H1006,
				Password: password, Duration: 5 * time.Second,
				Trace: func(e simulator.ProtocolEvent) { mu.Lock(); events = append(events, e); mu.Unlock() },
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { r.Close() })
			props := hardwareProperties(r)
			if props["model"] != "AppleTV3,2" || props["srcvers"] != "220.68" {
				t.Fatalf("wrong model/version: %v", props)
			}
			path := t.TempDir() + "/credentials"
			if err := hap.SaveCredentials(path, r.Credentials()); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+".password", []byte(password), 0600); err != nil {
				t.Fatal(err)
			}
			retired, samples := 0, 0
			maxPosition := 0.0
			c := airplay.New("hardware regression", path, "127.0.0.1",
				airplay.WithPort(r.Port()), airplay.WithProperties(props), airplay.WithFairPlayControl(true),
				airplay.WithDiagnosticHandler(func(e airplay.DiagnosticEvent) {
					if e.Stage == "fairplay-parent" && e.Result == "retired" {
						retired++
					}
				}),
				airplay.WithPlaybackInfoHandler(func(info map[string]any) {
					if position, ok := info["position"].(float64); ok {
						samples++
						maxPosition = max(maxPosition, position)
						r.Advance(time.Second)
					}
				}))
			for play := 1; play <= 2; play++ {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				err := c.PlayURL(ctx, "https://example.invalid/hardware.mp4", 0)
				cancel()
				if err != nil {
					t.Fatal(err)
				}
				if retired != play {
					t.Fatalf("parent retired %d times across %d plays", retired, play)
				}
				if r.Snapshot().PlayerState != "IDLE" {
					t.Fatal("playback did not finish")
				}
			}
			state := r.Snapshot()
			if samples < 10 || maxPosition < 4 || state.PlayCount != 2 || state.DetachedParents != 2 || state.FairPlaySetups != 4 {
				t.Fatalf("incomplete playback/reconnect: samples=%d position=%f state=%+v", samples, maxPosition, state)
			}
			mu.Lock()
			defer mu.Unlock()
			challenges, stops := map[string]bool{}, 0
			for _, e := range events {
				if e.Encrypted && e.Path == "/playback-info" && e.Status == 401 {
					challenges[e.Connection] = true
				}
				if e.Path == "/stop" && e.Status == 200 && e.Encrypted {
					stops++
				}
				if e.Path == "/feedback" {
					t.Fatal("sender reused a closed parent")
				}
			}
			if stops != 2 {
				t.Fatalf("encrypted cleanup count=%d", stops)
			}
			if password != "" && len(challenges) != 4 {
				t.Fatalf("expected independent command/reverse challenges on both plays, got %d", len(challenges))
			}
		})
	}
}

func TestFairPlayAppleTV32Build12H1006CancelAndVideoLoss(t *testing.T) {
	for _, mode := range []string{"cancel", "disconnect"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			r, err := simulator.New(simulator.Config{FairPlay: true, FairPlayProfile: simulator.FairPlayAppleTV32_12H1006, Duration: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { r.Close() })
			ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
			defer cancel()
			c := airplay.New("video loss", t.TempDir()+"/credentials", "127.0.0.1",
				airplay.WithPort(r.Port()), airplay.WithProperties(hardwareProperties(r)), airplay.WithFairPlayControl(true),
				airplay.WithPlaybackInfoHandler(func(info map[string]any) {
					if _, ok := info["duration"]; ok {
						if mode == "cancel" {
							cancel()
						} else {
							r.Disconnect()
						}
					}
				}))
			err = c.PlayURL(ctx, "https://example.invalid/loss.mp4", 0)
			if err == nil {
				t.Fatal("cancellation/video loss reported successful playback")
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel: %v", err)
			}
			if mode == "disconnect" && errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("video loss only noticed at deadline: %v", err)
			}
			waitFor(t, func() bool { return r.Snapshot().PlayerState == "IDLE" })
		})
	}
}

func hardwareProperties(r *simulator.Receiver) map[string]string {
	props := map[string]string{}
	for _, txt := range r.TXTRecords() {
		k, v, _ := strings.Cut(txt, "=")
		props[k] = v
	}
	return props
}

func TestFairPlayHardwareProfileValidation(t *testing.T) {
	for _, cfg := range []simulator.Config{{FairPlayProfile: simulator.FairPlayAppleTV32_12H1006}, {FairPlay: true, FairPlayProfile: "unknown"}} {
		if r, err := simulator.New(cfg); err == nil {
			r.Close()
			t.Fatal("invalid profile accepted")
		}
	}
}
