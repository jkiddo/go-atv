package simulator

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/jkiddo/go-atv/internal/fairplay"
	"github.com/jkiddo/go-atv/internal/fpcontrol"
	"howett.net/plist"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (r *Receiver) nativeFeatures() uint64 { return 0x1e5a7ffff7 }
func (r *Receiver) statusFlags() uint64 {
	flags := uint64(4)
	if r.config.PIN != "" {
		flags |= 0x80
	}
	if r.config.Password != "" && !r.config.HidePasswordStatus {
		flags |= 0x10
	}
	return flags
}

type ProtocolEvent struct {
	Connection string   `json:"connection"`
	Method     string   `json:"method,omitempty"`
	Path       string   `json:"path,omitempty"`
	Status     int      `json:"status,omitempty"`
	Encrypted  bool     `json:"encrypted"`
	Error      string   `json:"error,omitempty"`
	Keys       []string `json:"plistKeys,omitempty"`
}

func (r *Receiver) fairPlayTXT() []string {
	return []string{"deviceid=" + r.deviceID(), "model=AppleTV3,2", fmt.Sprintf("features=0x%X,0x%X", uint32(r.nativeFeatures()), r.nativeFeatures()>>32), "srcvers=220.68", fmt.Sprintf("flags=0x%X", r.statusFlags()), "vv=2", "pw=" + strconv.FormatBool(r.config.Password != "" && !r.config.HidePasswordStatus), "pi=" + r.pairingID(), "pk=" + hex.EncodeToString(ed25519.NewKeyFromSeed(r.credentials.LTSK).Public().(ed25519.PublicKey))}
}
func (r *Receiver) deviceID() string {
	return "02:" + r.id[:2] + ":" + r.id[2:4] + ":" + r.id[4:6] + ":" + r.id[6:8] + ":" + r.id[8:10]
}
func (r *Receiver) serverInfo() map[string]any {
	var txt []byte
	for _, field := range r.fairPlayTXT() {
		txt = append(txt, byte(len(field)))
		txt = append(txt, field...)
	}
	return map[string]any{"txtAirPlay": txt, "features": r.nativeFeatures(), "model": "AppleTV3,2", "name": r.config.Name, "deviceID": r.deviceID(), "macAddress": r.deviceID(), "sourceVersion": "220.68", "statusFlags": r.statusFlags(), "vv": 2, "pi": r.pairingID(), "pk": ed25519.NewKeyFromSeed(r.credentials.LTSK).Public().(ed25519.PublicKey), "displays": []any{map[string]any{"uuid": r.pairingID(), "width": 1920, "height": 1080, "widthPixels": 1920, "heightPixels": 1080, "widthPhysical": 0, "heightPhysical": 0, "refreshRate": 1.0 / 60.0, "features": 14, "rotation": true}}, "audioFormats": []any{map[string]any{"type": 100, "audioOutputFormats": 67108860, "audioInputFormats": 67108860}, map[string]any{"type": 101, "audioOutputFormats": 67108860, "audioInputFormats": 67108860}}, "keepAliveLowPower": true, "keepAliveSendStatsAsBody": true}
}

func (r *Receiver) serveFairPlay(socket net.Conn) {
	conn := socket
	reader := bufio.NewReader(conn)
	sap, err := fairplay.NewReceiver(rand.Reader)
	if err != nil {
		return
	}
	var verify *legacyVerify
	var pin *labPIN
	var pinStarted bool
	var secret []byte
	defer func() { clear(secret) }()
	var parentSession string
	var channels *parentChannels
	var setupDone, recorded, sapReady, tornDown bool
	defer func() {
		if channels != nil {
			channels.close()
		}
	}()
	var controller string
	stopParent := func() {
		r.mu.Lock()
		owned := r.fairPlayPlaybackParent == socket || (parentSession != "" && r.session == parentSession)
		changed := owned && r.state.PlayerState != "IDLE"
		if owned {
			r.state.PlayerState = "IDLE"
			r.fairPlayPlaybackParent = nil
		}
		if r.fairPlayParents[controller] == socket {
			delete(r.fairPlayParents, controller)
		}
		delete(r.recordedParents, socket)
		r.mu.Unlock()
		if changed {
			r.notify()
		}
	}
	defer stopParent()
	var mixed, verified, encrypted, reverse bool
	trace := func(e ProtocolEvent) {
		e.Connection = socket.RemoteAddr().String()
		if r.config.Trace != nil {
			r.config.Trace(e)
		}
	}
	trace(ProtocolEvent{Method: "CONNECT"})
	for {
		line, headers, body, err := readLabMessage(reader)
		if err != nil {
			if err != io.EOF {
				trace(ProtocolEvent{Encrypted: encrypted, Error: "read: " + err.Error()})
			}
			return
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			return
		}
		method, target, protocol := parts[0], parts[1], parts[2]
		if !reverse && protocol != "HTTP/1.1" && protocol != "RTSP/1.0" {
			return
		}

		if reverse {
			if method != "HTTP/1.1" || target != "200" {
				return
			}
			trace(ProtocolEvent{Method: "EVENT-ACK", Status: 200, Encrypted: encrypted})
			continue
		}
		uri, err := url.Parse(target)
		if err != nil {
			return
		}
		path := uri.Path
		// Playback commands are available only after the authenticated upgrade.
		passwordProbe := !encrypted && path == "/playback-info" && method == "GET" && verified && r.config.Password != ""
		if !encrypted && !passwordProbe && (path == "/play" || path == "/reverse" || path == "/stop" || path == "/rate" || path == "/scrub" || path == "/playback-info" || path == "/setProperty" || path == "/getProperty") {
			trace(ProtocolEvent{Method: method, Path: path, Status: 403})
			io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			return
		}
		code := 200
		extra := ""
		contentType := "application/x-apple-binary-plist"
		var response []byte
		var info map[string]any
		var upgrade *[64]byte
		var keys []string
		var props map[string]any
		if len(body) > 0 && (bytes.HasPrefix(body, []byte("bplist")) || bytes.HasPrefix(body, []byte("<?xml"))) {
			if _, e := plist.Unmarshal(body, &props); e == nil {
				for k := range props {
					keys = append(keys, k)
				}
			}
		}
		needsPassword := method == "SETUP" || passwordProbe
		username := "iTunes"
		if passwordProbe {
			username = "AirPlay"
		}
		switch {
		case needsPassword && r.passwordAuth.enabled() && !r.passwordAuth.authorizeAs(method, target, headers.Get("Authorization"), username):
			code = 401
			extra = "WWW-Authenticate: " + r.passwordAuth.challengeHeader() + "\r\n"
			r.mu.Lock()
			r.state.DigestChallenges++
			r.mu.Unlock()
		case (method == "SETUP" || method == "RECORD" || method == "TEARDOWN" || method == "SET_PARAMETER" || path == "/feedback") && (!verified || tornDown):
			code = 455

		case method == "POST" && path == "/pair-setup" && r.config.PIN == "":
			contentType = "application/octet-stream"
			if len(body) != 32 {
				code = 400
			} else {
				response = ed25519.NewKeyFromSeed(r.credentials.LTSK).Public().(ed25519.PublicKey)
			}
		case method == "POST" && path == "/pair-pin-start" && r.config.PIN != "":
			pinStarted = true
		case method == "POST" && path == "/pair-setup-pin" && r.config.PIN != "":
			if !pinStarted {
				code = 403
				break
			}
			info, err = r.pinExchange(&pin, props)
			if err != nil {
				code = 403
				pinStarted = false
			}
		case method == "POST" && path == "/pair-verify":
			if encrypted || verified {
				code = 400
				break
			}
			if len(body) == 68 && body[0] == 1 {
				controller = string(body[36:68])
				verify, response, err = r.startVerify(body)
				mixed = headers.Get("X-Apple-PD") == "1"
				if err != nil {
					code = 403
				}
			} else if len(body) == 68 && body[0] == 0 && verify != nil {
				if !verify.finish(body) {
					code = 403
				} else {
					secret = append([]byte(nil), verify.shared...)
					verified = true
				}
				verify = nil
			} else {
				code = 400
			}
			contentType = "application/octet-stream"
		case method == "POST" && path == "/fp-setup":
			if r.config.PIN != "" && !verified {
				code = 403
				break
			}
			if encrypted {
				code = 400
				break
			}
			response, err = sap.Exchange(body)
			if err == nil && len(response) > 6 && response[6] == 4 {
				sapReady = true
			}
			if err != nil {
				code = 403
			}
			contentType = "application/octet-stream"
		case method == "POST" && path == "/fp-setup2":
			if encrypted || !sapReady || (mixed && !verified) {
				code = 403
				break
			}
			material, e := sap.Unwrap(body)
			if e != nil {
				code = 403
				err = e
			} else {
				upgrade = &material
			}
			contentType = "application/octet-stream"
		case method == "GET" && (path == "/info" || path == "/server-info"):
			info = r.serverInfo()
		case method == "OPTIONS":
			extra = "Public: OPTIONS, SETUP, RECORD, TEARDOWN, GET_PARAMETER, SET_PARAMETER\r\n"
		case method == "SETUP":
			if !sapReady || setupDone {
				code = 455
				break
			}
			if r.config.PIN != "" && !verified {
				code = 403
				break
			}
			if key, ok := props["ekey"].([]byte); ok {
				if _, err = sap.UnwrapStream(key); err != nil {
					code = 403
					break
				}
			}
			senderPort, ok := labInt(props["timingPort"])
			if !ok || senderPort < 1 || senderPort > 65535 {
				code = 400
				break
			}
			channels, err = r.newParentChannels(socket, senderPort)
			if err != nil {
				code = 500
				break
			}
			setupDone = true
			info = map[string]any{"timingPort": channels.timingPort(), "eventPort": channels.eventPort()}
			parentSession, _ = props["sessionUUID"].(string)
			if verified {
				r.mu.Lock()
				if r.fairPlayParents == nil {
					r.fairPlayParents = make(map[string]net.Conn)
				}
				r.fairPlayParents[controller] = socket
				r.mu.Unlock()
			}
			extra = "Session: 1\r\n"
		case method == "TEARDOWN":
			if !setupDone {
				code = 455
				break
			}
			stopParent()
			channels.close()
			tornDown = true
		case method == "RECORD":
			if !setupDone || recorded {
				code = 455
				break
			}
			recorded = true
			r.mu.Lock()
			r.recordedParents[socket] = true
			r.mu.Unlock()
		case method == "SET_PARAMETER" || (method == "POST" && path == "/feedback"):
			if !recorded {
				code = 455
			}
		case method == "GET_PARAMETER":
			contentType = "text/parameters"
			response = []byte("volume: 0.000000\r\n")
		case method == "POST" && path == "/reverse":
			code = 101
			extra = "Connection: Upgrade\r\nUpgrade: PTTH/1.0\r\n"
		case method == "POST" && path == "/play":
			r.mu.Lock()
			parentReady := r.recordedParents[r.fairPlayParents[controller]]
			r.mu.Unlock()
			if !parentReady {
				code = 455
				break
			}
			location, _ := props["Content-Location"].(string)
			if location == "" {
				code = 400
				break
			}
			position, _ := props["Start-Position"].(float64)
			if position < 0 || position > 1 || math.IsNaN(position) || math.IsInf(position, 0) {
				code = 400
				break
			}
			seconds, hasSeconds := props["Start-Position-Seconds"].(float64)
			if hasSeconds && (seconds < 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0)) {
				code = 400
				break
			}
			r.mu.Lock()
			session := headers.Get("X-Apple-Session-ID")
			if r.failNext {
				r.failNext = false
				r.mu.Unlock()
				code = 500
				break
			}
			if r.state.PlayerState != "IDLE" && r.session != session {
				r.mu.Unlock()
				code = 453
				break
			}
			r.session = session
			r.fairPlayPlaybackParent = r.fairPlayParents[controller]
			r.state.URL = location
			r.state.Position = position * r.state.Duration
			if hasSeconds {
				r.state.Position = min(seconds, r.state.Duration)
			}
			r.state.PlayerState = "PLAYING"
			r.state.PlayCount++
			r.mu.Unlock()
		case method == "GET" && path == "/playback-info":
			state := r.Snapshot()
			info = map[string]any{}
			if state.PlayerState != "IDLE" {
				rate := 1.0
				if state.PlayerState == "PAUSED" {
					rate = 0
				}
				info = map[string]any{"duration": state.Duration, "position": state.Position, "rate": rate, "readyToPlay": true, "playbackBufferEmpty": false, "playbackBufferFull": true, "playbackLikelyToKeepUp": true, "loadedTimeRanges": []any{map[string]any{"start": 0.0, "duration": state.Duration}}, "seekableTimeRanges": []any{map[string]any{"start": 0.0, "duration": state.Duration}}}
			}
		case method == "POST" && path == "/stop":
			r.mu.Lock()
			owned := r.session == "" || r.session == headers.Get("X-Apple-Session-ID")
			r.mu.Unlock()
			if !owned {
				code = 453
				break
			}
			r.Finish()
		case path == "/scrub":
			if method == "POST" {
				if value, e := strconv.ParseFloat(uri.Query().Get("position"), 64); e == nil {
					if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
						code = 400
						break
					}
					r.mu.Lock()
					r.state.Position = min(value, r.state.Duration)
					r.mu.Unlock()
				} else {
					code = 400
				}
			}
			state := r.Snapshot()
			contentType = "text/parameters"
			response = []byte(fmt.Sprintf("duration: %f\r\nposition: %f\r\n", state.Duration, state.Position))
		case method == "POST" && path == "/rate":
			value, e := strconv.ParseFloat(uri.Query().Get("value"), 64)
			if e != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 2 {
				code = 400
			} else {
				r.mu.Lock()
				r.state.PlayerState = "PAUSED"
				if value != 0 {
					r.state.PlayerState = "PLAYING"
				}
				r.mu.Unlock()
			}
		case path == "/setProperty" || path == "/getProperty":
			info = map[string]any{"errorCode": 0}
		default:
			code = 501
		}
		if info != nil {
			response, err = plist.Marshal(info, plist.BinaryFormat)
			if err != nil {
				code = 500
			}
		}
		if seq := headers.Get("Cseq"); seq != "" {
			extra += "CSeq: " + seq + "\r\n"
		}
		sort.Strings(keys)
		event := ProtocolEvent{Method: method, Path: path, Status: code, Encrypted: encrypted, Keys: keys}
		if err != nil {
			event.Error = err.Error()
		}
		trace(event)
		if encrypted {
			r.mu.Lock()
			r.state.EncryptedRequests++
			r.mu.Unlock()
		}
		wire := []byte(fmt.Sprintf("%s %d %s\r\nServer: AirTunes/220.68\r\n%sContent-Type: %s\r\nContent-Length: %d\r\n\r\n", protocol, code, http.StatusText(code), extra, contentType, len(response)))
		wire = append(wire, response...)
		conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if n, e := conn.Write(wire); e != nil || n != len(wire) {
			return
		}
		if code >= 400 && (path == "/pair-verify" || path == "/fp-setup" || path == "/fp-setup2") {
			return
		}
		if path == "/reverse" && code == 101 {
			reverse = true
			defer r.registerReverse(conn, headers.Get("X-Apple-Session-ID"))()
		}
		if code == 200 && (path == "/play" || path == "/rate") {
			r.notify()
		}
		if upgrade != nil {
			clientWrite, clientRead, e := fpcontrol.Sender(*upgrade, secret, mixed)
			if e != nil {
				return
			}
			buffered := make([]byte, reader.Buffered())
			io.ReadFull(reader, buffered)
			conn = fpcontrol.NewConn(socket, buffered, clientRead, clientWrite)
			reader = bufio.NewReader(conn)
			encrypted = true
			r.mu.Lock()
			r.state.FairPlaySetups++
			r.mu.Unlock()
		}
	}
}

func (r *Receiver) pairingID() string {
	return r.id[:8] + "-" + r.id[8:12] + "-" + r.id[12:16] + "-" + r.id[16:20] + "-" + r.id[20:]
}
