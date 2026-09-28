package airplay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/jkiddo/go-atv/hap"
	"github.com/jkiddo/go-atv/tlv8"
)

// fakeReceiver is an in-process AirPlay 2 receiver good enough to exercise
// pair-verify, control-channel encryption, the SETUP/RECORD//play sequence,
// playback-info polling and the event channel.
type fakeReceiver struct {
	t        *testing.T
	listener net.Listener

	ltsk  ed25519.PrivateKey // receiver long-term key
	atvID []byte

	mu            sync.Mutex
	shared        []byte // pair-verify shared secret
	playBody      map[string]any
	requestPaths  []string
	playbackPolls int
	eventOK       bool

	eventListener net.Listener

	encryptAfterVerify bool
	closePlaybackInfo  bool
}

func newFakeReceiver(t *testing.T) *fakeReceiver {
	return newFakeReceiverWithOptions(t, true, false)
}

func newFakeReceiverWithOptions(t *testing.T, encryptAfterVerify, closePlaybackInfo bool) *fakeReceiver {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	eventListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	receiver := &fakeReceiver{
		t:                  t,
		listener:           listener,
		eventListener:      eventListener,
		ltsk:               ed25519.NewKeyFromSeed(seed),
		atvID:              []byte("fake-atv-id"),
		encryptAfterVerify: encryptAfterVerify,
		closePlaybackInfo:  closePlaybackInfo,
	}
	go receiver.acceptControl()
	go receiver.acceptEvents()
	t.Cleanup(func() {
		listener.Close()
		eventListener.Close()
	})
	return receiver
}

func (f *fakeReceiver) port() int { return f.listener.Addr().(*net.TCPAddr).Port }

// clientCredentials returns credentials as the client would have stored
// them after pairing with this receiver.
func (f *fakeReceiver) clientCredentials() hap.Credentials {
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	return hap.Credentials{
		LTPK:     f.ltsk.Public().(ed25519.PublicKey),
		LTSK:     seed,
		ATVID:    f.atvID,
		ClientID: []byte("fake-client-id"),
	}
}

func (f *fakeReceiver) acceptControl() {
	conn, err := f.listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	var session *hap.Session // set after pair-verify M3
	var pending []byte
	buf := make([]byte, 16384)

	respond := func(status int, contentType string, body []byte) {
		reply := fmt.Sprintf("RTSP/1.0 %d OK\r\n", status)
		if contentType != "" {
			reply += "Content-Type: " + contentType + "\r\n"
		}
		reply += fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
		out := append([]byte(reply), body...)
		if session != nil {
			out = session.Encrypt(out)
		}
		conn.Write(out)
	}

	var verifyPrivate [32]byte

	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		data := buf[:n]
		if session != nil {
			if data, err = session.Decrypt(data); err != nil {
				f.t.Errorf("receiver decrypt: %v", err)
				return
			}
		}
		pending = append(pending, data...)

		for {
			request, rest, err := parseRequest(pending)
			if err != nil {
				f.t.Errorf("receiver parse: %v", err)
				return
			}
			if request == nil {
				break
			}
			pending = rest

			f.mu.Lock()
			f.requestPaths = append(f.requestPaths, request.Method+" "+request.Path)
			f.mu.Unlock()

			switch {
			case request.Method == "GET" && request.Path == "/info":
				body, _ := packPlist(map[string]any{
					"features": uint64(FeatureVideoV2 | FeatureSupportsUnifiedMediaControl),
				})
				respond(200, bplistContentType, body)

			case request.Method == "POST" && request.Path == "/pair-verify":
				tlv, err := tlv8.Read(request.Body)
				if err != nil {
					f.t.Errorf("pair-verify tlv: %v", err)
					return
				}
				switch tlv[tlv8.TagSeqNo][0] {
				case 0x01:
					clientPublic := tlv[tlv8.TagPublicKey]
					rand.Read(verifyPrivate[:])
					serverPublic, _ := curve25519.X25519(verifyPrivate[:], curve25519.Basepoint)
					shared, _ := curve25519.X25519(verifyPrivate[:], clientPublic)
					f.mu.Lock()
					f.shared = shared
					f.mu.Unlock()

					sessionKey := hap.HKDFExpand("Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", shared)
					cipher, _ := hap.NewCipher(sessionKey, sessionKey, 8)

					var info []byte
					info = append(info, serverPublic...)
					info = append(info, f.atvID...)
					info = append(info, clientPublic...)
					inner := tlv8.Write(
						tlv8.Item{Tag: tlv8.TagIdentifier, Value: f.atvID},
						tlv8.Item{Tag: tlv8.TagSignature, Value: ed25519.Sign(f.ltsk, info)},
					)
					respond(200, "application/octet-stream", tlv8.Write(
						tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x02}},
						tlv8.Item{Tag: tlv8.TagPublicKey, Value: serverPublic},
						tlv8.Item{Tag: tlv8.TagEncryptedData, Value: cipher.Encrypt(inner, []byte("PV-Msg02"), nil)},
					))
				case 0x03:
					respond(200, "application/octet-stream", tlv8.Write(
						tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{0x04}},
					))
					// Enable encryption: the receiver decrypts with the
					// client's output key and encrypts with its input key.
					f.mu.Lock()
					shared := f.shared
					f.mu.Unlock()
					clientOut := hap.HKDFExpand(controlSalt, controlOutputInfo, shared)
					clientIn := hap.HKDFExpand(controlSalt, controlInputInfo, shared)
					if f.encryptAfterVerify {
						if session, err = hap.NewSession(clientIn, clientOut); err != nil {
							f.t.Errorf("receiver session: %v", err)
							return
						}
					}
				}

			case request.Method == "SETUP":
				body, _ := packPlist(map[string]any{
					"eventPort": f.eventListener.Addr().(*net.TCPAddr).Port,
				})
				respond(200, bplistContentType, body)

			case request.Method == "POST" && request.Path == "/play":
				parsed, err := unpackPlist(request.Body)
				if err != nil {
					f.t.Errorf("play body: %v", err)
				}
				f.mu.Lock()
				f.playBody = parsed
				f.mu.Unlock()
				respond(200, "", nil)

			case request.Method == "GET" && request.Path == "/playback-info":
				if request.Protocol != "HTTP/1.1" {
					f.t.Errorf("playback-info protocol = %q, want HTTP/1.1", request.Protocol)
				}
				if f.closePlaybackInfo {
					return
				}
				f.mu.Lock()
				f.playbackPolls++
				polls := f.playbackPolls
				f.mu.Unlock()
				if polls == 1 {
					body, _ := packPlist(map[string]any{"duration": 12.5})
					respond(200, bplistContentType, body)
				} else {
					respond(200, "", nil) // no duration: playback ended
				}

			default:
				// RECORD, /feedback, /rate, /setProperty, ...
				respond(200, "", nil)
			}
		}
	}
}

// acceptEvents handles the event channel: it sends one encrypted request to
// the client and records whether a 200 reply comes back.
func (f *fakeReceiver) acceptEvents() {
	conn, err := f.eventListener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()

	f.mu.Lock()
	shared := f.shared
	f.mu.Unlock()
	if shared == nil {
		f.t.Error("event channel connected before pair-verify")
		return
	}
	// Mirror of the client's event keys (client output = "read" info).
	clientOut := hap.HKDFExpand(eventsSalt, eventsReadInfo, shared)
	clientIn := hap.HKDFExpand(eventsSalt, eventsWriteInfo, shared)
	session, err := hap.NewSession(clientIn, clientOut)
	if err != nil {
		f.t.Errorf("event session: %v", err)
		return
	}

	request := "POST /command HTTP/1.1\r\nCSeq: 0\r\nContent-Length: 0\r\n\r\n"
	if _, err := conn.Write(session.Encrypt([]byte(request))); err != nil {
		return
	}

	var pending []byte
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		plain, err := session.Decrypt(buf[:n])
		if err != nil {
			f.t.Errorf("event decrypt: %v", err)
			return
		}
		pending = append(pending, plain...)
		resp, _, err := parseResponse(pending)
		if err != nil {
			f.t.Errorf("event response: %v", err)
			return
		}
		if resp != nil {
			f.mu.Lock()
			f.eventOK = resp.Code == 200
			f.mu.Unlock()
			return
		}
	}
}

func TestPlayURLLoopback(t *testing.T) {
	receiver := newFakeReceiver(t)

	credentialsPath := filepath.Join(t.TempDir(), "credentials")
	if err := hap.SaveCredentials(credentialsPath, receiver.clientCredentials()); err != nil {
		t.Fatal(err)
	}

	var playbackUpdates []map[string]any
	client := New(
		"test-client",
		credentialsPath,
		"127.0.0.1",
		WithPort(receiver.port()),
		WithPlaybackInfoHandler(func(info map[string]any) {
			playbackUpdates = append(playbackUpdates, info)
		}),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	mediaURL := "https://example.com/video.mp4"
	if err := client.PlayURL(ctx, mediaURL, 3.5); err != nil {
		t.Fatalf("PlayURL: %v", err)
	}

	receiver.mu.Lock()
	defer receiver.mu.Unlock()

	if receiver.playBody == nil {
		t.Fatal("receiver never saw /play")
	}
	if got := receiver.playBody["Content-Location"]; got != mediaURL {
		t.Errorf("Content-Location = %v, want %v", got, mediaURL)
	}
	if got, ok := receiver.playBody["Start-Position-Seconds"].(float64); !ok || got != 3.5 {
		t.Errorf("Start-Position-Seconds = %v, want 3.5", receiver.playBody["Start-Position-Seconds"])
	}
	if !receiver.eventOK {
		t.Error("event channel request was not answered with 200")
	}
	if len(playbackUpdates) == 0 || playbackUpdates[0]["duration"] != 12.5 {
		t.Fatalf("playback updates = %#v, want initial duration 12.5", playbackUpdates)
	}

	joined := strings.Join(receiver.requestPaths, "\n")
	for _, want := range []string{"SETUP", "RECORD", "POST /play", "POST /rate?value=1.000000", "GET /playback-info"} {
		if !strings.Contains(joined, want) {
			t.Errorf("receiver never saw %q; requests:\n%s", want, joined)
		}
	}
}

func TestPlaybackInfoAuthenticates(t *testing.T) {
	receiver := newFakeReceiver(t)

	credentialsPath := filepath.Join(t.TempDir(), "credentials")
	if err := hap.SaveCredentials(credentialsPath, receiver.clientCredentials()); err != nil {
		t.Fatal(err)
	}

	client := New("test-client", credentialsPath, "127.0.0.1", WithPort(receiver.port()))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := client.PlaybackInfo(ctx)
	if err != nil {
		t.Fatalf("PlaybackInfo: %v", err)
	}
	if got, ok := info["duration"].(float64); !ok || got != 12.5 {
		t.Fatalf("duration = %v, want 12.5", info["duration"])
	}

	receiver.mu.Lock()
	defer receiver.mu.Unlock()
	joined := strings.Join(receiver.requestPaths, "\n")
	for _, want := range []string{"POST /pair-verify", "GET /playback-info"} {
		if !strings.Contains(joined, want) {
			t.Errorf("receiver never saw %q; requests:\n%s", want, joined)
		}
	}
}

func TestPlaybackInfoRejectsHAPCredentialsForLegacyReceiver(t *testing.T) {
	receiver := newFakeReceiverWithOptions(t, false, true)

	credentialsPath := filepath.Join(t.TempDir(), "credentials")
	if err := hap.SaveCredentials(credentialsPath, receiver.clientCredentials()); err != nil {
		t.Fatal(err)
	}

	client := New(
		"test-client",
		credentialsPath,
		"127.0.0.1",
		WithPort(receiver.port()),
		WithProperties(map[string]string{"features": "0x1"}),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.PlaybackInfo(ctx)
	if err == nil || !strings.Contains(err.Error(), "incompatible HAP credentials") {
		t.Fatalf("PlaybackInfo error = %v, want incompatible credentials", err)
	}
}
