package airplay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jkiddo/go-atv/hap"
)

// PlaybackError indicates the receiver reported a playback failure.
type PlaybackError struct{ Message string }

func (e *PlaybackError) Error() string { return "airplay: " + e.Message }

const (
	playRetries         = 3
	playbackWaitRetries = 5
	feedbackInterval    = 2 * time.Second
)

// playHeaders are the extra headers sent with POST /play (pyatv airplayv2.py
// HEADERS; the session id is added per call).
func playHeaders(sessionID string) []header {
	return []header{
		{"X-Apple-ProtocolVersion", "1"},
		{"X-Apple-Session-ID", sessionID},
		{"X-Apple-Stream-ID", "1"},
	}
}

// newUUID returns a random UUIDv4 string.
func newUUID() string {
	id, err := hap.NewPairingID()
	if err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return string(id)
}

// playURLV2 streams a URL with the AirPlay 2 flow: encrypted control
// connection (already enabled by verifyConnection), SETUP with timing/event
// exchange, RECORD, POST /play plus the property/rate commands, then polling
// until playback ends. Port of pyatv's AirPlayV2.play_url and AirPlayPlayer.
func playURLV2(ctx context.Context, rtsp *rtspSession, v *verifier, url string, position float64) error {
	conn := rtsp.conn
	timing, err := newTimingServer(conn.localIP)
	if err != nil {
		return fmt.Errorf("airplay: start timing server: %w", err)
	}
	defer timing.close()

	setupResp, err := rtsp.setup(ctx, map[string]any{
		"deviceID":                 "AA:BB:CC:DD:EE:FF",
		"sessionUUID":              strings.ToUpper(newUUID()),
		"timingPort":               timing.port,
		"timingProtocol":           "NTP",
		"isMultiSelectAirPlay":     true,
		"groupContainsGroupLeader": false,
		"macAddress":               "AA:BB:CC:DD:EE:FF",
		"model":                    "iPhone14,3",
		"name":                     "goatv",
		"osBuildVersion":           "20F66",
		"osName":                   "iPhone OS",
		"osVersion":                "16.5",
		"senderSupportsRelay":      false,
		"sourceVersion":            "690.7.1",
		"statsCollectionEnabled":   false,
	})
	if err != nil {
		return err
	}
	setupBody, err := unpackPlist(setupResp.Body)
	if err != nil {
		return err
	}

	var events *eventChannel
	if eventPort, ok := plistInt(setupBody["eventPort"]); ok && eventPort > 0 {
		if events, err = connectEventChannel(ctx, conn.remoteIP, eventPort, v); err != nil {
			return err
		}
		defer events.close()
	}

	if err := rtsp.feedback(ctx); err != nil {
		return err
	}
	if err := rtsp.record(ctx); err != nil {
		return err
	}

	playBody := map[string]any{
		"Content-Location":       url,
		"Start-Position-Seconds": position,
		"uuid":                   newUUID(),
		"streamType":             1,
		"mediaType":              "file",
		"playbackRestrictions":   0,
		"volume":                 1.0,
		"referenceRestrictions":  3,
		"SenderMACAddress":       "AA:BB:CC:DD:EE:FF",
		"model":                  "iPhone14,3",
		"clientBundleID":         "com.github.jkiddo.goatv",
		"clientProcName":         "goatv",
		"osBuildVersion":         "20G1116",
		"rate":                   1.0,
	}

	if err := postPlayWithRetry(ctx, rtsp, playBody); err != nil {
		return err
	}

	// Commands pyatv sends after /play; "/rate" matters (playback starts
	// paused otherwise), the rest is sent for parity with real senders.
	zeroTime := map[string]any{"flags": 0, "value": 0, "epoch": 0, "timescale": 0}
	steps := []struct {
		method, uri string
		body        map[string]any
	}{
		{"PUT", "/setProperty?isInterestedInDateRange", map[string]any{"value": true}},
		{"PUT", "/setProperty?actionAtItemEnd", map[string]any{"value": 0}},
		{"POST", "/rate?value=1.000000", nil},
		{"PUT", "/setProperty?forwardEndTime", map[string]any{"value": zeroTime}},
		{"PUT", "/setProperty?reverseEndTime", map[string]any{"value": zeroTime}},
	}
	for _, step := range steps {
		var body any
		if step.body != nil {
			body = step.body
		}
		if _, err := rtsp.exchange(ctx, step.method, step.uri, nil, body); err != nil {
			return err
		}
	}

	return waitForPlaybackToEnd(ctx, rtsp)
}

// playURLV1 streams a URL with the AirPlay 1 flow after the caller has
// completed any required pair-verify, then sends a single POST /play.

func playURLV1(ctx context.Context, rtsp *rtspSession, url string, position float64, sessionPath, deviceID string) error {
	sessionID := newUUID()
	previousSessionID := loadLegacySessionID(sessionPath)
	body := map[string]any{
		"Content-Location":   url,
		"Start-Position":     position,
		"X-Apple-Session-ID": sessionID,
	}

	stopInterrupt := interruptOnCancel(ctx, rtsp.conn)
	if err := startPlaybackV1(ctx, rtsp.conn, body, sessionID, previousSessionID, deviceID); err != nil {
		stopInterrupt()
		return err
	}
	if err := saveLegacySessionID(sessionPath, sessionID); err != nil {
		stopInterrupt()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		stopErr := stopPlaybackV1(cleanupCtx, rtsp.conn, sessionID, deviceID)
		cancel()
		if stopErr != nil {
			return fmt.Errorf("airplay: persist active session: %w (session cleanup failed: %v)", err, stopErr)
		}
		return fmt.Errorf("airplay: persist active session: %w", err)
	}

	err := waitForPlaybackToEnd(ctx, rtsp)
	stopInterrupt()
	if ctx.Err() != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = stopPlaybackV1(cleanupCtx, rtsp.conn, sessionID, deviceID)
		cancel()
		return ctx.Err()
	}
	return err
}

func startPlaybackV1(ctx context.Context, conn *connection, body map[string]any, sessionID, previousSessionID, deviceID string) error {
	if err := postPlayV1WithRetry(ctx, conn, body, sessionID, deviceID); err != nil {
		var status *StatusError
		if !errors.As(err, &status) || status.Code != 453 {
			return err
		}
		if previousSessionID == "" {
			return err
		}

		// AirPlay v1 receivers use 453 when a previous control session still
		// owns the single playback slot. This is common after a sender exits or
		// loses its TCP connection without issuing /stop. Address /stop to the
		// persisted session UUID, then retry the exact play request.
		if stopErr := stopPlaybackV1(ctx, conn, previousSessionID, deviceID); stopErr != nil {
			return fmt.Errorf("%w (stale-session cleanup failed: %v)", err, stopErr)
		}
		if err := postPlayV1WithRetry(ctx, conn, body, sessionID, deviceID); err != nil {
			return err
		}
	}
	return nil
}

func stopPlaybackV1(ctx context.Context, conn *connection, sessionID, deviceID string) error {
	response, err := conn.exchangeWithDigestRetry(ctx, request{
		Method:    "POST",
		URI:       "/stop",
		UserAgent: "MediaControl/1.0",
		Headers: []header{
			{"Content-Length", "0"},
			{"X-Apple-Device-ID", deviceID},
			{"X-Apple-Session-ID", sessionID},
		},
	})
	if err != nil {
		return err
	}
	return errStatus(response, "POST /stop")
}

func postPlayV1WithRetry(ctx context.Context, conn *connection, body map[string]any, sessionID, deviceID string) error {
	raw, err := packPlist(body)
	if err != nil {
		return err
	}
	for attempt := 1; ; attempt++ {
		response, err := conn.exchangeWithDigestRetry(ctx, request{
			Method:      "POST",
			URI:         "/play",
			UserAgent:   "MediaControl/1.0",
			ContentType: bplistContentType,
			Headers: []header{
				{"X-Apple-Device-ID", deviceID},
				{"X-Apple-Session-ID", sessionID},
			},
			Body: raw,
		})
		if err != nil {
			return err
		}
		if response.Code == 500 && attempt < playRetries {
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}
		if response.Code == 470 || response.Code == 401 || response.Code == 403 {
			return &InvalidAuth{Message: fmt.Sprintf("device rejected playback (status %d); pairing may be required", response.Code)}
		}
		return errStatus(response, "POST /play")
	}
}

func interruptOnCancel(ctx context.Context, conn *connection) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			conn.interrupt()
		case <-done:
		}
	}()
	return func() {
		close(done)
		<-stopped
	}
}

func loadLegacySessionID(path string) string {
	if path == "" {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sessionID := strings.TrimSpace(string(raw))
	if !isSessionID(sessionID) {
		// A truncated or malformed state (a power cut mid-write on the Pi, or a
		// stale file from an older build) can't be used to clear the receiver's
		// playback slot, so discard it instead of refusing to play forever.
		clearLegacySessionID(path)
		return ""
	}
	return sessionID
}

// isSessionID reports whether id looks like the UUID session identifier we
// persist, so a half-written or tampered file is never used to address /stop.
func isSessionID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		switch {
		case i == 8 || i == 13 || i == 18 || i == 23:
			if c != '-' {
				return false
			}
		case (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'):
		default:
			return false
		}
	}
	return true
}

func saveLegacySessionID(path, sessionID string) error {
	if path == "" {
		return nil
	}
	// Write through a temporary file that is fsynced before the rename, and
	// sync the parent directory afterwards, so a power cut leaves either the
	// previous or the new identifier on disk, never a torn or vanished one.
	temp := path + ".tmp"
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write([]byte(sessionID + "\n")); err != nil {
		file.Close()
		_ = os.Remove(temp)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(temp)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil
	}
	defer directory.Close()
	return directory.Sync()
}

func clearLegacySessionID(path string) error {
	if path == "" {
		return nil
	}
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// postPlayWithRetry sends POST /play, retrying on 500 responses like pyatv's
// AirPlayPlayer ("Internal Server Error" happens sporadically).
func postPlayWithRetry(ctx context.Context, rtsp *rtspSession, body map[string]any) error {
	sessionID := newUUID()
	for attempt := 1; ; attempt++ {
		resp, err := rtsp.exchange(ctx, "POST", "/play", playHeaders(sessionID), body)
		if err != nil {
			return err
		}
		if resp.Code == 500 && attempt < playRetries {
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}
		if resp.Code >= 400 {
			if resp.Code == 470 || resp.Code == 401 || resp.Code == 403 {
				return &InvalidAuth{Message: fmt.Sprintf("device rejected playback (status %d); pairing may be required", resp.Code)}
			}
			return errStatus(resp, "POST /play")
		}
		return nil
	}
}

// waitForPlaybackToEnd polls /playback-info until the media stops playing,
// sending periodic keep-alive feedback. Port of pyatv's
// AirPlayPlayer._wait_for_media_to_end.
func waitForPlaybackToEnd(ctx context.Context, rtsp *rtspSession) error {
	attempts := playbackWaitRetries
	videoStarted := false
	lastFeedback := time.Now()

	for {
		resp, err := rtsp.conn.exchangeWithDigestRetry(ctx, request{Method: "GET", URI: "/playback-info"})
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// An orderly close can mean the remote stopped the video.
			// Timeouts and protocol errors must remain failures.
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		if resp.Code == 401 || resp.Code == 403 || resp.Code == 470 {
			return &InvalidAuth{Message: fmt.Sprintf("device rejected playback-info (status %d)", resp.Code)}
		}
		if err := errStatus(resp, "GET /playback-info"); err != nil {
			return err
		}

		parsed, err := unpackPlist(resp.Body)
		if err != nil {
			parsed = map[string]any{}
		}
		if rtsp.playbackHandler != nil {
			rtsp.playbackHandler(parsed)
		}

		if errInfo, ok := parsed["error"].(map[string]any); ok {
			code, _ := plistInt(errInfo["code"])
			domain, _ := errInfo["domain"].(string)
			return &PlaybackError{Message: fmt.Sprintf("got error %d (%s) when playing video", code, domain)}
		}

		if _, ok := parsed["duration"]; ok {
			videoStarted = true
			attempts = -1
		} else {
			videoStarted = false
			if attempts >= 0 {
				attempts--
			}
		}

		if !videoStarted && attempts < 0 {
			return nil
		}

		if time.Since(lastFeedback) >= feedbackInterval {
			// Best-effort keep-alive; errors are ignored like in pyatv.
			_ = rtsp.feedback(ctx)
			lastFeedback = time.Now()
		}

		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// plistInt converts the numeric types howett.net/plist may produce.
func plistInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case uint64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

var errNotPaired = errors.New("airplay: device requires pairing; run pair-airplay first")
