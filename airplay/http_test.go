package airplay

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFormatRequest(t *testing.T) {
	got := formatRequest(request{
		Method:      "POST",
		URI:         "/play",
		ContentType: "application/x-apple-binary-plist",
		Headers:     []header{{"X-Apple-Stream-ID", "1"}},
		Body:        []byte("body"),
	})
	want := "POST /play HTTP/1.1\r\n" +
		"User-Agent: AirPlay/550.10\r\n" +
		"Content-Type: application/x-apple-binary-plist\r\n" +
		"Content-Length: 4\r\n" +
		"X-Apple-Stream-ID: 1\r\n\r\nbody"
	if string(got) != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestPostPlayV1UsesLegacyHTTPFormat(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	conn := &connection{tcp: clientSide}
	received := make(chan *incomingRequest, 1)
	serverError := make(chan error, 1)
	go func() {
		buffer := make([]byte, 8192)
		var pending []byte
		for {
			count, err := serverSide.Read(buffer)
			if err != nil {
				serverError <- err
				return
			}
			pending = append(pending, buffer[:count]...)
			parsed, _, err := parseRequest(pending)
			if err != nil {
				serverError <- err
				return
			}
			if parsed == nil {
				continue
			}
			received <- parsed
			_, err = serverSide.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			serverError <- err
			return
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sessionID := "11111111-2222-4333-8444-555555555555"
	deviceID := "0x9983af7c388b"
	if err := postPlayV1WithRetry(ctx, conn, map[string]any{
		"Content-Location":   "https://example.test/video.mp4",
		"X-Apple-Session-ID": sessionID,
	}, sessionID, deviceID); err != nil {
		t.Fatal(err)
	}
	request := <-received
	if request.Protocol != "HTTP/1.1" || request.Method != "POST" || request.Path != "/play" {
		t.Fatalf("request line = %s %s %s", request.Method, request.Path, request.Protocol)
	}
	if request.Headers["user-agent"] != "MediaControl/1.0" {
		t.Fatalf("User-Agent = %q", request.Headers["user-agent"])
	}
	if request.Headers["content-type"] != bplistContentType {
		t.Fatalf("Content-Type = %q", request.Headers["content-type"])
	}
	if request.Headers["x-apple-session-id"] != sessionID {
		t.Fatalf("X-Apple-Session-ID = %q", request.Headers["x-apple-session-id"])
	}
	if request.Headers["x-apple-device-id"] != deviceID {
		t.Fatalf("X-Apple-Device-ID = %q", request.Headers["x-apple-device-id"])
	}
	playBody, err := unpackPlist(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if playBody["X-Apple-Session-ID"] != sessionID {
		t.Fatalf("body session ID = %q", playBody["X-Apple-Session-ID"])
	}
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
}

func TestPlayURLV1ClearsStaleSessionOn453(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	conn := &connection{tcp: clientSide}
	serverError := make(chan error, 1)
	requests := make(chan *incomingRequest, 10)
	go func() {
		buffer := make([]byte, 8192)
		var pending []byte
		responses := []string{
			"HTTP/1.1 453 Not Enough Bandwidth\r\nContent-Length: 0\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
		}
		for index, rawResponse := range responses {
			for {
				parsed, rest, err := parseRequest(pending)
				if err != nil {
					serverError <- err
					return
				}
				if parsed != nil {
					pending = rest
					requests <- parsed
					break
				}
				count, err := serverSide.Read(buffer)
				if err != nil {
					serverError <- err
					return
				}
				pending = append(pending, buffer[:count]...)
			}
			if _, err := serverSide.Write([]byte(rawResponse)); err != nil {
				serverError <- err
				return
			}
			if index == len(responses)-1 {
				serverError <- nil
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	currentSessionID := "11111111-2222-4333-8444-555555555555"
	previousSessionID := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	deviceID := "0x9983af7c388b"
	if err := startPlaybackV1(ctx, conn, map[string]any{
		"Content-Location":   "https://example.test/video.mp4",
		"X-Apple-Session-ID": currentSessionID,
	}, currentSessionID, previousSessionID, deviceID); err != nil {
		t.Fatal(err)
	}
	gotRequests := make([]*incomingRequest, 0, 3)
	for len(gotRequests) < 3 {
		gotRequests = append(gotRequests, <-requests)
	}
	want := []string{"/play", "/stop", "/play"}
	for index := range want {
		if gotRequests[index].Path != want[index] {
			t.Fatalf("request %d path = %q, want %q", index, gotRequests[index].Path, want[index])
		}
	}
	for index, request := range gotRequests {
		if got := request.Headers["x-apple-device-id"]; got != deviceID {
			t.Fatalf("request %d device ID = %q, want %q", index, got, deviceID)
		}
	}
	if got := gotRequests[0].Headers["x-apple-session-id"]; got != currentSessionID {
		t.Fatalf("initial /play session ID = %q, want %q", got, currentSessionID)
	}
	if got := gotRequests[1].Headers["x-apple-session-id"]; got != previousSessionID {
		t.Fatalf("/stop session ID = %q, want %q", got, previousSessionID)
	}
	if got := gotRequests[2].Headers["x-apple-session-id"]; got != currentSessionID {
		t.Fatalf("retried /play session ID = %q, want %q", got, currentSessionID)
	}
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
}

func TestLegacySessionIDStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "airplay.credentials.session")
	want := "11111111-2222-4333-8444-555555555555"

	if got := loadLegacySessionID(path); got != "" {
		t.Fatalf("load missing session = %q", got)
	}
	if err := saveLegacySessionID(path, want); err != nil {
		t.Fatal(err)
	}
	if got := loadLegacySessionID(path); got != want {
		t.Fatalf("load saved session = %q; want %q", got, want)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("atomic write left a temporary file behind: %v", err)
	}
	if err := clearLegacySessionID(path); err != nil {
		t.Fatal(err)
	}
	if got := loadLegacySessionID(path); got != "" {
		t.Fatalf("load cleared session = %q", got)
	}

	// A truncated or malformed persisted state (a power cut mid-write, or a
	// stale file from an older build) must be discarded, never treated as a
	// fatal error that blocks playback forever.
	for _, garbage := range []string{"", "broken", strings.Repeat("a", 36)} {
		if err := os.WriteFile(path, []byte(garbage), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := loadLegacySessionID(path); got != "" {
			t.Fatalf("load corrupt session %q = %q, want discarded", garbage, got)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("corrupt session file was not discarded: %v", err)
		}
	}
}

func TestPlayURLV1ProceedsWhenPersistedSessionCorrupt(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	conn := &connection{tcp: clientSide}

	// A torn session file left by a power cut must not stop us from playing.
	sessionPath := filepath.Join(t.TempDir(), "airplay.credentials.session")
	if err := os.WriteFile(sessionPath, []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The receiver has no live session after its own power cycle, so it accepts
	// the play request and then drops the control link, which the sender reads
	// as playback finished rather than a pairing or session error.
	go func() {
		buffer := make([]byte, 16384)
		var pending []byte
		for {
			request, rest, err := parseRequest(pending)
			if err != nil {
				return
			}
			if request == nil {
				count, readErr := serverSide.Read(buffer)
				if readErr != nil {
					return
				}
				pending = append(pending, buffer[:count]...)
				continue
			}
			pending = rest
			if request.Path == "/play" {
				serverSide.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			}
			// Drop the control link so the sender reads playback as finished.
			serverSide.Close()
			return
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := playURLV1(ctx, newRTSPSession(conn), "https://example.test/video.mp4", 0, sessionPath, "0x9983af7c388b")
	if err != nil {
		t.Fatalf("playURLV1 error = %v, want nil", err)
	}
	// The last session identifier stays on disk when playback ends: it is the
	// only handle that can address /stop at a stale receiver session if we
	// replay after a reboot and the receiver still answers 453.
	if got := loadLegacySessionID(sessionPath); !isSessionID(got) {
		t.Fatalf("completed session id was not retained: %q", got)
	}
}

func TestPlayURLV1StopsItsSessionOnCancellation(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()
	conn := &connection{tcp: clientSide}
	playbackInfoSeen := make(chan struct{})
	stopSeen := make(chan *incomingRequest, 1)
	serverError := make(chan error, 1)

	go func() {
		buffer := make([]byte, 8192)
		var pending []byte
		for {
			request, rest, err := parseRequest(pending)
			if err != nil {
				serverError <- err
				return
			}
			if request == nil {
				count, err := serverSide.Read(buffer)
				if err != nil {
					serverError <- err
					return
				}
				pending = append(pending, buffer[:count]...)
				continue
			}
			pending = rest
			switch request.Path {
			case "/play":
				if _, err := serverSide.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")); err != nil {
					serverError <- err
					return
				}
			case "/playback-info":
				close(playbackInfoSeen)
				// Leave this request unanswered so cancellation must interrupt
				// the read without closing the control connection.
			case "/stop":
				stopSeen <- request
				_, err := serverSide.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
				serverError <- err
				return
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	sessionPath := filepath.Join(t.TempDir(), "airplay.credentials.session")
	result := make(chan error, 1)
	go func() {
		result <- playURLV1(ctx, newRTSPSession(conn), "https://example.test/video.mp4", 0, sessionPath, "0x9983af7c388b")
	}()

	select {
	case <-playbackInfoSeen:
	case <-time.After(time.Second):
		t.Fatal("playback-info was not requested")
	}
	persistedID := loadLegacySessionID(sessionPath)
	if persistedID == "" {
		t.Fatalf("active session was not persisted: %q", persistedID)
	}
	cancel()

	var stop *incomingRequest
	select {
	case stop = <-stopSeen:
	case <-time.After(time.Second):
		t.Fatal("session-scoped /stop was not requested")
	}
	if got := stop.Headers["x-apple-session-id"]; got != persistedID {
		t.Fatalf("/stop session ID = %q, want active session %q", got, persistedID)
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("playURLV1 error = %v, want context.Canceled", err)
	}
	if got := loadLegacySessionID(sessionPath); got != persistedID {
		t.Fatalf("session id changed after /stop: %q, want %q", got, persistedID)
	}
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
}

func TestFormatRequestRTSPNoBody(t *testing.T) {
	got := formatRequest(request{
		Method:    "SETUP",
		URI:       "rtsp://10.0.0.2/42",
		Protocol:  "RTSP/1.0",
		UserAgent: "AirPlay/320.20",
	})
	want := "SETUP rtsp://10.0.0.2/42 RTSP/1.0\r\nUser-Agent: AirPlay/320.20\r\n\r\n"
	if string(got) != want {
		t.Fatalf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestParseResponse(t *testing.T) {
	raw := []byte("RTSP/1.0 200 OK\r\nCSeq: 3\r\nContent-Length: 5\r\n\r\nhellorest")
	resp, rest, err := parseResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("expected complete response")
	}
	if resp.Protocol != "RTSP/1.0" || resp.Code != 200 || resp.Message != "OK" {
		t.Fatalf("unexpected status: %+v", resp)
	}
	if resp.Headers["cseq"] != "3" {
		t.Fatalf("unexpected headers: %v", resp.Headers)
	}
	if string(resp.Body) != "hello" {
		t.Fatalf("unexpected body: %q", resp.Body)
	}
	if string(rest) != "rest" {
		t.Fatalf("unexpected rest: %q", rest)
	}
}

func TestParseResponseIncomplete(t *testing.T) {
	for _, raw := range []string{
		"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort",
		"HTTP/1.1 200 OK\r\nContent-Le",
	} {
		resp, rest, err := parseResponse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if resp != nil {
			t.Fatalf("expected incomplete for %q", raw)
		}
		if !bytes.Equal(rest, []byte(raw)) {
			t.Fatalf("incomplete parse should keep data, got %q", rest)
		}
	}
}

func TestParseRequest(t *testing.T) {
	raw := []byte("POST /command HTTP/1.1\r\nContent-Length: 2\r\nCSeq: 7\r\n\r\nhi")
	req, rest, err := parseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if req == nil {
		t.Fatal("expected complete request")
	}
	if req.Method != "POST" || req.Path != "/command" || req.Protocol != "HTTP/1.1" {
		t.Fatalf("unexpected request: %+v", req)
	}
	if string(req.Body) != "hi" || len(rest) != 0 {
		t.Fatalf("unexpected body/rest: %q %q", req.Body, rest)
	}
}

func TestParseFeatures(t *testing.T) {
	features, err := parseFeatures("0x4A7FDFD5,0xBC157FDE")
	if err != nil {
		t.Fatal(err)
	}
	if uint64(features) != 0xBC157FDE4A7FDFD5 {
		t.Fatalf("got %#x", uint64(features))
	}
	if !features.SupportsPlayURL() {
		t.Fatal("expected video support")
	}
	if !features.isVersion2() {
		t.Fatal("expected AirPlay 2")
	}
	if !features.supportsTransient() {
		t.Fatal("expected transient support")
	}

	v1, err := parseFeatures("0x1")
	if err != nil {
		t.Fatal(err)
	}
	if v1.isVersion2() || !v1.SupportsPlayURL() {
		t.Fatalf("unexpected flags for 0x1")
	}

	if _, err := parseFeatures("junk"); err == nil {
		t.Fatal("expected error for invalid feature string")
	}
}
