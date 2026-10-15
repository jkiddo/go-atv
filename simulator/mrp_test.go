package simulator_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jkiddo/go-atv/hap"
	"github.com/jkiddo/go-atv/mrp"
	"github.com/jkiddo/go-atv/simulator"
)

func TestMRPPyatvInterop(t *testing.T) {
	python := os.Getenv("PYATV_PYTHON")
	if python == "" {
		t.Skip("set PYATV_PYTHON to a virtualenv with pyatv installed")
	}
	receiver, err := simulator.New(simulator.Config{MRP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	initial := mrp.State{PlaybackState: "playing", App: "com.example.music", AppName: "Music", Title: "Independent pyatv test", Artist: "Test artist", ItemID: "test", MediaType: "audio"}
	receiver.SetNowPlaying(initial)
	path := filepath.Join(t.TempDir(), "credentials")
	if err := hap.SaveCredentials(path, receiver.Credentials()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "testdata/pyatv_client.py", strconv.Itoa(receiver.Port()), path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	playing, paused := false, false
	for scanner.Scan() {
		var event struct{ Title, State, App, Artist string }
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		if event.Title != initial.Title || event.App != initial.App || event.Artist != initial.Artist {
			t.Errorf("pyatv metadata: %+v", event)
		}
		switch event.State {
		case "Playing":
			playing = true
			next := initial
			next.PlaybackState = "paused"
			receiver.SetNowPlaying(next)
		case "Paused":
			paused = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Error(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if !playing || !paused {
		t.Fatalf("pyatv missed updates: playing=%v paused=%v", playing, paused)
	}
}
func TestMRPConfigIsolation(t *testing.T) {
	for _, config := range []simulator.Config{{MRP: true, FairPlay: true}, {MRP: true, Password: "test"}, {MRP: true, PIN: "1234"}} {
		if r, err := simulator.New(config); err == nil {
			r.Close()
			t.Fatal("incompatible simulator modes accepted")
		}
	}
}
