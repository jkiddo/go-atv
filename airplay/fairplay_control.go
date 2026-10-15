package airplay

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/jkiddo/go-atv/hap"
	"github.com/jkiddo/go-atv/internal/fairplay"
	"github.com/jkiddo/go-atv/internal/fpcontrol"
	"golang.org/x/crypto/curve25519"
	"io"
	"net"
	"syscall"
	"time"
)

// WithFairPlayControl opts into the experimental native legacy video path.
// It negotiates fresh SAP and fp-setup2 on each video connection; it never
// silently falls back after a failed authentication or encryption upgrade.
func WithFairPlayControl(enabled bool) Option { return func(c *Client) { c.fairPlayControl = enabled } }

func verifyLegacyPD(ctx context.Context, conn *connection, credentials hap.Credentials, peerKey []byte) ([]byte, error) {
	if !credentials.IsLegacy() {
		return nil, errors.New("airplay: FairPlay requires legacy credentials")
	}
	var private [32]byte
	defer clear(private[:])
	if _, e := rand.Read(private[:]); e != nil {
		return nil, e
	}
	public, e := curve25519.X25519(private[:], curve25519.Basepoint)
	if e != nil {
		return nil, e
	}
	signing := ed25519.NewKeyFromSeed(credentials.LTSK)
	requestBody := append([]byte{1, 0, 0, 0}, public...)
	requestBody = append(requestBody, signing.Public().(ed25519.PublicKey)...)
	post := func(body []byte) ([]byte, error) {
		response, e := conn.exchange(ctx, request{Method: "POST", URI: "/pair-verify", ContentType: "application/octet-stream", Headers: []header{{"X-Apple-PD", "1"}, {"Connection", "keep-alive"}}, Body: body})
		if e != nil {
			return nil, e
		}
		if e = errStatus(response, "POST /pair-verify"); e != nil {
			return nil, e
		}
		return response.Body, nil
	}
	response, e := post(requestBody)
	if e != nil {
		return nil, e
	}
	if len(response) != 96 {
		return nil, errors.New("airplay: malformed pair-verify response")
	}
	peer := response[:32]
	secret, e := curve25519.X25519(private[:], peer)
	clear(private[:])
	if e != nil {
		return nil, e
	}
	key := sha512.Sum512(append([]byte("Pair-Verify-AES-Key"), secret...))
	iv := sha512.Sum512(append([]byte("Pair-Verify-AES-IV"), secret...))
	block, _ := aes.NewCipher(key[:16])
	stream := cipher.NewCTR(block, iv[:16])
	signature := make([]byte, 64)
	stream.XORKeyStream(signature, response[32:])
	if len(peerKey) > 0 && (len(peerKey) != 32 || !ed25519.Verify(peerKey, append(append([]byte(nil), peer...), public...), signature)) {
		clear(secret)
		return nil, &InvalidAuth{Message: "invalid receiver pair-verify signature"}
	}
	signature = ed25519.Sign(signing, append(append([]byte(nil), public...), peer...))
	stream.XORKeyStream(signature, signature)
	if _, e = post(append([]byte{0, 0, 0, 0}, signature...)); e != nil {
		clear(secret)
		return nil, e
	}
	return secret, nil
}

func setupFairPlay(ctx context.Context, conn *connection, headers []header) (*fairplay.Sender, error) {
	sap, e := fairplay.NewSender(rand.Reader)
	if e != nil {
		return nil, e
	}
	post := func(body []byte) ([]byte, error) {
		response, e := conn.post(ctx, "/fp-setup", "application/octet-stream", headers, body)
		if e != nil {
			return nil, e
		}
		if e = errStatus(response, "POST /fp-setup"); e != nil {
			return nil, e
		}
		return response.Body, nil
	}
	m2, e := post(sap.Start())
	if e != nil {
		return nil, e
	}
	m3, e := sap.Challenge(m2)
	if e != nil {
		return nil, e
	}
	m4, e := post(m3)
	if e != nil {
		return nil, e
	}
	if e = sap.Confirm(m4); e != nil {
		return nil, e
	}
	return sap, nil
}

func upgradeFairPlay(ctx context.Context, conn *connection, sap *fairplay.Sender, secret []byte, headers []header) error {
	if conn.session != nil {
		return errors.New("airplay: cannot combine HAP and FairPlay encryption")
	}
	var material [64]byte
	if _, e := rand.Read(material[:]); e != nil {
		return e
	}
	defer clear(material[:])
	envelope, e := sap.Wrap(material, rand.Reader)
	if e != nil {
		return e
	}
	response, e := conn.post(ctx, "/fp-setup2", "application/octet-stream", headers, envelope[:])
	if e != nil {
		return e
	}
	if response.Code != 200 || len(response.Body) != 0 {
		conn.close()
		return fmt.Errorf("airplay: fp-setup2 requires empty 200 response (got %d, %d bytes)", response.Code, len(response.Body))
	}
	out, in, e := fpcontrol.Sender(material, secret, true)
	if e != nil {
		conn.close()
		return e
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.tcp = fpcontrol.NewConn(conn.tcp, conn.pending, out, in)
	conn.pending = nil
	return nil
}

func (c *Client) playURLFairPlay(ctx context.Context, parent *rtspSession, credentials *hap.Credentials, mediaURL string, position float64) error {
	if credentials == nil {
		anonymous, e := newLegacyCredentials()
		if e != nil {
			return e
		}
		credentials = &anonymous
	}
	if !credentials.IsLegacy() {
		return errors.New("airplay: native FairPlay video requires legacy pairing")
	}
	var peerKey []byte
	if text := c.properties["pk"]; text != "" {
		var e error
		peerKey, e = hex.DecodeString(text)
		if e != nil || len(peerKey) != 32 {
			return errors.New("airplay: invalid advertised receiver public key")
		}
	}
	parentSecret, e := verifyLegacyPD(ctx, parent.conn, *credentials, peerKey)
	if e != nil {
		return e
	}
	defer clear(parentSecret)
	sap, e := setupFairPlay(ctx, parent.conn, []header{{"X-Apple-ET", "32"}})
	if e != nil {
		return e
	}
	timing, e := newTimingServer(parent.conn.localIP)
	if e != nil {
		return e
	}
	defer timing.close()
	var audioKey, audioIV [16]byte
	rand.Read(audioKey[:])
	rand.Read(audioIV[:])
	ekey, e := sap.WrapStream(audioKey, rand.Reader)
	clear(audioKey[:])
	if e != nil {
		return e
	}
	sessionID := newUUID()
	body := map[string]any{"deviceID": legacyDeviceID(*credentials), "name": c.name, "model": "go-atv", "sourceVersion": "220.68", "sessionUUID": sessionID, "sessionCorrelationUUID": sessionID, "timingProtocol": "NTP", "timingPort": timing.port, "et": 32, "ekey": ekey[:], "eiv": audioIV[:], "isScreenMirroringSession": false}
	response, e := parent.setup(ctx, body)
	if response != nil && response.Code == 401 {
		password, err := c.loadLegacyPassword()
		if err != nil {
			return err
		}
		if password == "" {
			return &InvalidAuth{Message: "receiver requires an AirPlay code"}
		}
		parent.conn.digest, err = parseDigestChallenge(response.Headers["www-authenticate"], "iTunes", password)
		if err != nil {
			return err
		}
		response, e = parent.setup(ctx, body)
	}
	if e != nil {
		return e
	}
	parentActive := true
	defer func() {
		if !parentActive {
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		parent.exchange(cleanup, "TEARDOWN", "", nil, map[string]any{})
	}()
	setupInfo, e := unpackPlist(response.Body)
	if e != nil {
		return e
	}
	if port, ok := plistInt(setupInfo["eventPort"]); ok && port > 0 {
		if port > 65535 {
			return errors.New("airplay: invalid event port")
		}
		event, err := dial(ctx, c.address, port)
		if err != nil {
			return fmt.Errorf("airplay: parent event channel: %w", err)
		}
		defer event.close()
		done := make(chan error, 1)
		go func() { done <- acknowledgeFairPlayEvents(event.tcp, nil) }()
		defer func() { event.close(); <-done }()
	}
	// Native video control uses its own pair-verify/SAP context, distinct from
	// the parent RTSP socket. Parent keepalives continue during URL playback.
	if e = parent.record(ctx); e != nil {
		return e
	}
	headers := []header{{"X-Apple-Session-ID", sessionID}, {"X-Apple-ET", "32"}}
	video, receiverInfo, e := c.fairPlayVideoConnection(ctx, *credentials, peerKey, headers, true)
	if e != nil {
		return e
	}
	defer video.close()
	reverse, _, e := c.fairPlayVideoConnection(ctx, *credentials, peerKey, headers, false)
	if e != nil {
		return e
	}
	defer reverse.close()
	upgradeHeaders := append(append([]header(nil), headers...), header{"Connection", "Upgrade"}, header{"Upgrade", "PTTH/1.0"})
	reply, e := reverse.post(ctx, "/reverse", "", upgradeHeaders, nil)
	if e != nil {
		return e
	}
	if reply.Code != 101 {
		return fmt.Errorf("airplay: reverse upgrade returned %d", reply.Code)
	}
	if e = reverse.tcp.SetDeadline(time.Time{}); e != nil {
		return e
	}
	eventDone := make(chan error, 1)
	go func() { eventDone <- acknowledgeFairPlayEvents(reverse.tcp, reverse.pending) }()
	eventStopped := false
	defer func() {
		reverse.close()
		if !eventStopped {
			<-eventDone
		}
	}()
	c.emitDiagnostic(DiagnosticEvent{Stage: "fp-setup2", Result: "encrypted", StatusCode: 200})
	stop := interruptOnCancel(ctx, video)
	playStarted := false
	defer func() {
		stop()
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if !playStarted {
			return
		}
		reply, err := video.post(cleanup, "/stop", "", headers, nil)
		if err != nil {
			// An interrupted GCM record invalidates that transport. Cleanup
			// uses fresh verification/SAP/keys, retaining only the session ID.
			fresh, _, e := c.fairPlayVideoConnection(cleanup, *credentials, peerKey, headers, false)
			if e != nil {
				return
			}
			defer fresh.close()
			reply, err = fresh.post(cleanup, "/stop", "", headers, nil)
		}
		if err == nil && errStatus(reply, "POST /stop") == nil {
			clearLegacySessionID(c.legacySessionPath())
		}
	}()
	playBody, e := packPlist(map[string]any{"Content-Location": mediaURL, "Start-Position-Seconds": position, "Start-Position": 0.0, "X-Apple-Session-ID": sessionID, "rate": 1.0, "streamType": 1, "mediaType": "file", "uuid": newUUID()})
	if e != nil {
		return e
	}
	response, e = video.post(ctx, "/play", bplistContentType, headers, playBody)
	if e != nil {
		return e
	}
	if response.Code == 453 {
		if previous := loadLegacySessionID(c.legacySessionPath()); previous != "" {
			staleHeaders := []header{{"X-Apple-Session-ID", previous}, {"X-Apple-ET", "32"}}
			stopped, err := video.post(ctx, "/stop", "", staleHeaders, nil)
			if err != nil {
				return err
			}
			if err = errStatus(stopped, "stale session stop"); err != nil {
				return err
			}
			response, e = video.post(ctx, "/play", bplistContentType, headers, playBody)
			if e != nil {
				return e
			}
		}
	}
	if e = errStatus(response, "POST /play"); e != nil {
		return e
	}
	playStarted = true
	if e = saveLegacySessionID(c.legacySessionPath(), sessionID); e != nil {
		return e
	}

	zeroTime := map[string]any{"flags": 0, "value": 0, "epoch": 0, "timescale": 0}
	for _, step := range []struct {
		method, uri string
		value       any
	}{
		{"PUT", "/setProperty?forwardEndTime", zeroTime},
		{"PUT", "/setProperty?reverseEndTime", zeroTime},
		{"PUT", "/setProperty?actionAtItemEnd", 0},
		{"POST", "/rate?value=1.000000", nil},
	} {
		var body []byte
		if step.value != nil {
			body, e = packPlist(map[string]any{"value": step.value})
			if e != nil {
				return e
			}
		}
		reply, err := video.exchange(ctx, request{Method: step.method, URI: step.uri, ContentType: bplistContentType, Headers: headers, Body: body})
		if err != nil {
			return err
		}
		if err = errStatus(reply, step.uri); err != nil {
			return err
		}
	}
	started := false
	empty := 0
	lastFeedback := time.Now()
	for {
		response, e = video.get(ctx, "/playback-info", headers)
		if e != nil {
			return e
		}
		if e = errStatus(response, "GET /playback-info"); e != nil {
			return e
		}
		info, e := unpackPlist(response.Body)
		if e != nil {
			return e
		}
		if c.playbackHandler != nil {
			c.playbackHandler(info)
		}
		if _, ok := info["duration"]; ok {
			started = true
		} else {
			empty++
			if started {
				return nil
			}
			if empty > playbackWaitRetries {
				return errors.New("airplay: receiver never reported playback")
			}
		}
		if parentActive && time.Since(lastFeedback) >= feedbackInterval {
			if e = parent.feedback(ctx); e != nil {
				// This hardware retires its RTSP bootstrap connection after
				// /play. Only retire it after a successful encrypted status
				// response above; video/reverse errors still end the session.
				if !canRetireFairPlayParent(receiverInfo, e) {
					return e
				}
				parentActive = false
				parent.conn.close()
				c.emitDiagnostic(DiagnosticEvent{Stage: "fairplay-parent", Result: "retired"})
			}
			lastFeedback = time.Now()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-eventDone:
			eventStopped = true
			return fmt.Errorf("airplay: reverse event channel closed: %w", err)
		case <-time.After(time.Second):
		}
	}
}

// Each HTTP video socket has independent verification, SAP and GCM state.
func (c *Client) fairPlayVideoConnection(ctx context.Context, credentials hap.Credentials, peerKey []byte, headers []header, getInfo bool) (_ *connection, info map[string]any, err error) {
	conn, err := dial(ctx, c.address, c.port)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			conn.close()
		}
	}()
	secret, err := verifyLegacyPD(ctx, conn, credentials, peerKey)
	if err != nil {
		return nil, nil, err
	}
	defer clear(secret)
	if getInfo {
		reply, e := conn.get(ctx, "/server-info", headers)
		if e != nil {
			return nil, nil, e
		}
		if e = errStatus(reply, "GET /server-info"); e != nil {
			return nil, nil, e
		}
		info, e = unpackPlist(reply.Body)
		if e != nil {
			return nil, nil, e
		}
	}
	sap, err := setupFairPlay(ctx, conn, headers)
	if err != nil {
		return nil, nil, err
	}
	if err = upgradeFairPlay(ctx, conn, sap, secret, headers); err != nil {
		return nil, nil, err
	}
	// Pair verification and FairPlay do not authorize password-protected
	// HTTP requests. Each encrypted socket needs its own Digest challenge.
	password, err := c.loadLegacyPassword()
	if err != nil {
		return nil, nil, err
	}
	if err = primeLegacyDigestWithDiagnostics(ctx, conn, password, c.emitDiagnostic, headers...); err != nil {
		return nil, nil, err
	}
	return conn, info, nil
}

// canRetireFairPlayParent is deliberately limited to the hardware/firmware
// observed on 2026-10-14. Other receivers keep the strict parent lifecycle.
func canRetireFairPlayParent(info map[string]any, err error) bool {
	if info["model"] != "AppleTV3,2" || info["osBuildVersion"] != "12H1006" || info["srcvers"] != "220.68" {
		return false
	}
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

func acknowledgeFairPlayEvents(conn net.Conn, pending []byte) error {
	buf := make([]byte, 16384)
	for {
		if len(pending) > 1<<20 {
			return errors.New("airplay: oversized reverse event")
		}
		event, rest, err := parseRequest(pending)
		if err != nil {
			return err
		}
		if event != nil {
			if event.Protocol != "HTTP/1.1" && event.Protocol != "RTSP/1.0" {
				return errors.New("airplay: invalid reverse event protocol")
			}
			pending = rest
			reply := event.Protocol + " 200 OK\r\nContent-Length: 0\r\n"
			if seq := event.Headers["cseq"]; seq != "" {
				reply += "CSeq: " + seq + "\r\n"
			}
			reply += "\r\n"
			conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if n, e := io.WriteString(conn, reply); e != nil {
				return e
			} else if n != len(reply) {
				return io.ErrShortWrite
			}
			continue
		}
		n, err := conn.Read(buf)
		if n > 0 {
			pending = append(pending, buf[:n]...)
		}
		if err != nil {
			return err
		}
	}
}
