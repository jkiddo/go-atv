package simulator

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/mdns"
	"github.com/jkiddo/go-atv/hap"
	"golang.org/x/crypto/curve25519"
	"howett.net/plist"
)

func (r *Receiver) listen() error {
	r.credentials = hap.Credentials{ClientID: make([]byte, 8), LTSK: make([]byte, 32)}
	if _, err := rand.Read(r.credentials.ClientID); err != nil {
		return err
	}
	if _, err := rand.Read(r.credentials.LTSK); err != nil {
		return err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	r.nonce = hex.EncodeToString(nonce)
	var err error
	r.listener, err = net.Listen("tcp", r.config.Listen)
	return err
}

// Credentials returns pre-paired, simulator-only credentials. This receiver
// validates legacy pair-verify; interactive PIN setup is not implemented.
func (r *Receiver) Credentials() hap.Credentials {
	return hap.Credentials{ClientID: append([]byte(nil), r.credentials.ClientID...), LTSK: append([]byte(nil), r.credentials.LTSK...)}
}

func (r *Receiver) TXTRecords() []string {
	pw := "false"
	if r.config.Password != "" {
		pw = "true"
	}
	return []string{"deviceid=02:" + r.id[:2] + ":" + r.id[2:4] + ":" + r.id[4:6] + ":" + r.id[6:8] + ":" + r.id[8:10], "model=AppleTV3,2", "features=0x1", "srcvers=220.68", "pw=" + pw, "name=" + r.config.Name}
}

func (r *Receiver) advertise(ip net.IP) error {
	iface, err := interfaceForIP(ip)
	if err != nil {
		return err
	}
	zone, err := mdns.NewMDNSService(r.config.Name, "_airplay._tcp", "local.", "airplay-sim-"+r.id[:12]+".local.", r.Port(), []net.IP{ip}, r.TXTRecords())
	if err != nil {
		return err
	}
	server, err := mdns.NewServer(&mdns.Config{Zone: zone, Iface: iface, Logger: log.New(io.Discard, "", 0)})
	if err == nil {
		r.shutdownDiscovery = func() { _ = server.Shutdown() }
	}
	return err
}

func (r *Receiver) notify() {} // AirPlay clients poll /playback-info.

func (r *Receiver) serve(conn net.Conn) {
	reader := bufio.NewReader(conn)
	var verify *legacyVerify
	for {
		// Read HTTP and RTSP on the same connection, without net/http's HTTP-only parser.
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			return
		}
		method, target, protocol := parts[0], parts[1], parts[2]
		if protocol != "HTTP/1.1" && protocol != "RTSP/1.0" {
			return
		}
		headers, err := textproto.NewReader(reader).ReadMIMEHeader()
		if err != nil {
			return
		}
		length := 0
		if s := headers.Get("Content-Length"); s != "" {
			length, err = strconv.Atoi(s)
			if err != nil || length < 0 || length > 1<<20 {
				return
			}
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(reader, body); err != nil {
			return
		}
		uri, err := url.Parse(target)
		if err != nil {
			return
		}
		code := 200
		var response []byte
		extra := ""
		if uri.Path == "/pair-verify" && method == "POST" {
			if len(body) == 68 && body[0] == 1 {
				verify, response, err = r.startVerify(body)
				if err != nil {
					code = 403
				}
			} else if len(body) == 68 && body[0] == 0 && verify != nil {
				if !verify.finish(body) {
					code = 403
				}
				verify = nil
			} else {
				code = 400
			}
		} else if uri.Path != "/info" && uri.Path != "/server-info" && r.config.Password != "" && !r.authorized(method, target, headers.Get("Authorization")) {
			code = 401
			extra = fmt.Sprintf("WWW-Authenticate: Digest realm=\"AirPlay\", nonce=\"%s\"\r\n", r.nonce)
		} else {
			r.mu.Lock()
			var info map[string]any
			switch {
			case method == "GET" && (uri.Path == "/info" || uri.Path == "/server-info"):
				info = map[string]any{"features": uint64(1), "model": "AppleTV3,2", "name": r.config.Name}
			case method == "POST" && uri.Path == "/play":
				var play map[string]any
				if _, err := plist.Unmarshal(body, &play); err != nil {
					code = 400
					break
				}
				mediaURL, _ := play["Content-Location"].(string)
				if mediaURL == "" {
					code = 400
					break
				}
				if r.failNext {
					r.failNext = false
					code = 500
					break
				}
				session := headers.Get("X-Apple-Session-ID")
				if r.state.PlayerState != "IDLE" && session != r.session {
					code = 453
					break
				}
				position, _ := play["Start-Position"].(float64)
				if position < 0 || position > 1 {
					code = 400
					break
				}
				r.session = session
				r.state.URL = mediaURL
				r.state.Position = position * r.state.Duration
				r.state.PlayerState = "PLAYING"
				r.state.PlayCount++
			case method == "GET" && uri.Path == "/playback-info":
				info = map[string]any{}
				if r.state.PlayerState != "IDLE" {
					rate := 1.0
					if r.state.PlayerState == "PAUSED" {
						rate = 0
					}
					info = map[string]any{"duration": r.state.Duration, "position": r.state.Position, "rate": rate, "readyToPlay": true, "playbackBufferEmpty": false, "playbackBufferFull": true, "playbackLikelyToKeepUp": true}
				}
			case method == "POST" && uri.Path == "/stop":
				if r.session != "" && headers.Get("X-Apple-Session-ID") != r.session {
					code = 453
					break
				}
				r.state.PlayerState = "IDLE"
				r.session = ""
			case method == "POST" && uri.Path == "/rate":
				value, err := strconv.ParseFloat(uri.Query().Get("value"), 64)
				if err != nil {
					code = 400
					break
				}
				if r.state.URL != "" {
					r.state.PlayerState = "PAUSED"
					if value != 0 {
						r.state.PlayerState = "PLAYING"
					}
				}
			case method == "POST" && uri.Path == "/feedback":
			default:
				code = 501
			}
			if info != nil {
				response, err = plist.Marshal(info, plist.BinaryFormat)
				if err != nil {
					code = 500
				}
			}
			r.mu.Unlock()
		}
		if seq := headers.Get("Cseq"); seq != "" {
			extra += "CSeq: " + seq + "\r\n"
		}
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := fmt.Fprintf(conn, "%s %d %s\r\n%sContent-Type: application/x-apple-binary-plist\r\nContent-Length: %d\r\n\r\n", protocol, code, http.StatusText(code), extra, len(response)); err != nil {
			return
		}
		if _, err := conn.Write(response); err != nil {
			return
		}
	}
}

func digest(value string) string { sum := md5.Sum([]byte(value)); return hex.EncodeToString(sum[:]) }
func (r *Receiver) authorized(method, target, authorization string) bool {
	if !strings.HasPrefix(authorization, "Digest ") {
		return false
	}
	fields := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(authorization, "Digest "), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			fields[k] = strings.Trim(v, "\"")
		}
	}
	if fields["realm"] != "AirPlay" || fields["nonce"] != r.nonce || fields["uri"] != target || fields["username"] != "AirPlay" {
		return false
	}
	want := digest(digest("AirPlay:AirPlay:"+r.config.Password) + ":" + r.nonce + ":" + digest(method+":"+target))
	return subtle.ConstantTimeCompare([]byte(want), []byte(fields["response"])) == 1
}

type legacyVerify struct {
	stream                  cipher.Stream
	client, server, signing []byte
}

func (r *Receiver) startVerify(body []byte) (*legacyVerify, []byte, error) {
	signing := ed25519.NewKeyFromSeed(r.credentials.LTSK).Public().(ed25519.PublicKey)
	if subtle.ConstantTimeCompare(signing, body[36:]) != 1 {
		return nil, nil, fmt.Errorf("unknown client")
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}
	server, err := curve25519.X25519(seed, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	shared, err := curve25519.X25519(seed, body[4:36])
	if err != nil {
		return nil, nil, err
	}
	key := sha512.Sum512(append([]byte("Pair-Verify-AES-Key"), shared...))
	iv := sha512.Sum512(append([]byte("Pair-Verify-AES-IV"), shared...))
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, nil, err
	}
	v := &legacyVerify{stream: cipher.NewCTR(block, iv[:16]), client: append([]byte(nil), body[4:36]...), server: server, signing: signing}
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed), append(append([]byte(nil), server...), v.client...))
	v.stream.XORKeyStream(signature, signature)
	return v, append(append([]byte(nil), server...), signature...), nil
}
func (v *legacyVerify) finish(body []byte) bool {
	signature := append([]byte(nil), body[4:]...)
	v.stream.XORKeyStream(signature, signature)
	return ed25519.Verify(v.signing, append(append([]byte(nil), v.client...), v.server...), signature)
}
