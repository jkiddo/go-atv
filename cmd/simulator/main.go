// Command simulator runs a protocol receiver for development, not a media player.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/jkiddo/go-atv/simulator"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	var cfg simulator.Config
	flag.StringVar(&cfg.Listen, "listen", "127.0.0.1:0", "receiver bind address")
	flag.StringVar(&cfg.Name, "name", "AirPlay Simulator", "discovery name")
	flag.DurationVar(&cfg.Duration, "duration", 30*time.Second, "simulated media duration")
	flag.StringVar(&cfg.AdvertiseIP, "mdns-ip", "", "opt into discovery using this LAN IP (also set -listen)")
	flag.StringVar(&cfg.DiscoveryBackend, "mdns-backend", "auto", "discovery backend: auto, go, native (macOS Bonjour)")
	flag.BoolVar(&cfg.HidePasswordStatus, "hide-password-status", false, "FairPlay lab: challenge SETUP without advertising password requirement")
	credentials := flag.String("credentials-out", "", "create a new file with simulator-only pre-paired credentials")
	flag.StringVar(&cfg.Password, "password", "", "fixed AirPlay password; legacy mode requires -credentials-out")
	flag.StringVar(&cfg.PIN, "pin", "", "four-digit test PIN for native legacy pairing; requires -fairplay")
	flag.BoolVar(&cfg.FairPlay, "fairplay", false, "enable experimental fp-setup2 receiver and native RTSP control")
	flag.StringVar(&cfg.FairPlayProfile, "fairplay-profile", "", "hardware profile: appletv3,2-12H1006 (requires -fairplay)")
	flag.Parse()
	if cfg.FairPlay {
		cfg.Trace = func(e simulator.ProtocolEvent) { b, _ := json.Marshal(e); log.Print(string(b)) }
	}
	if cfg.Password != "" && !cfg.FairPlay && *credentials == "" {
		return fmt.Errorf("-password requires -credentials-out for the goatv client")
	}
	receiver, err := simulator.New(cfg)
	if err != nil {
		return err
	}
	defer receiver.Close()
	if *credentials != "" {
		f, err := os.OpenFile(*credentials, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := fmt.Fprintln(f, receiver.Credentials().String())
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(map[string]any{"address": receiver.Addr().String(), "name": cfg.Name, "txt": receiver.TXTRecords()}); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	previous := receiver.Snapshot()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			receiver.Advance(now.Sub(last))
			last = now
			state := receiver.Snapshot()
			if state.PlayerState != previous.PlayerState || state.PlayCount != previous.PlayCount || state.Loops != previous.Loops {
				if err := encoder.Encode(state); err != nil {
					return err
				}
			}
			previous = state
		}
	}
}
