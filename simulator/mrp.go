package simulator

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jkiddo/go-atv/hap"
	"github.com/jkiddo/go-atv/internal/hapconn"
	pb "github.com/jkiddo/go-atv/internal/mrpwire"
	"github.com/jkiddo/go-atv/mrp"
	"github.com/jkiddo/go-atv/tlv8"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
	"howett.net/plist"
)

func (r *Receiver) initMRP() {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	r.mrpSigning = private
	r.credentials.LTPK = public
	r.credentials.ATVID = []byte(r.id)
	r.credentials.ClientID = []byte(pb.UUID())
	r.mrpState = mrp.State{PlaybackState: "idle"}
	r.mrpPeers = make(map[*mrpPeer]struct{})
}

// SetNowPlaying replaces the simulator's active media and pushes it to all MRP
// subscribers. Empty App clears the active client. It is safe to call concurrently.
func (r *Receiver) SetNowPlaying(state mrp.State) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mrpState = cloneMRPState(state)
	r.state.PlayerState = strings.ToUpper(state.PlaybackState)
	if state.Position != nil {
		r.state.Position = *state.Position
	}
	if state.Duration != nil {
		r.state.Duration = *state.Duration
	}
	r.signalMRPLocked()
}
func cloneMRPState(s mrp.State) mrp.State {
	if s.Position != nil {
		s.Position = proto.Float64(*s.Position)
	}
	if s.Duration != nil {
		s.Duration = proto.Float64(*s.Duration)
	}
	if s.PlaybackRate != nil {
		s.PlaybackRate = proto.Float64(*s.PlaybackRate)
	}
	if s.PositionTimestamp != nil {
		v := *s.PositionTimestamp
		s.PositionTimestamp = &v
	}
	if s.SeasonNumber != nil {
		s.SeasonNumber = proto.Int32(*s.SeasonNumber)
	}
	if s.EpisodeNumber != nil {
		s.EpisodeNumber = proto.Int32(*s.EpisodeNumber)
	}
	return s
}
func (r *Receiver) signalMRPLocked() {
	for p := range r.mrpPeers {
		select {
		case p.changed <- struct{}{}:
		default:
		}
	}
}
func (r *Receiver) advanceMRP(elapsed time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := &r.mrpState
	if elapsed <= 0 || s.PlaybackState != "playing" || s.Position == nil {
		return
	}
	rate := 1.0
	if s.PlaybackRate != nil {
		rate = *s.PlaybackRate
	}
	*s.Position += elapsed.Seconds() * rate
	if s.Duration != nil && *s.Position >= *s.Duration {
		*s.Position = *s.Duration
		s.PlaybackState = "stopped"
		s.PlaybackRate = proto.Float64(0)
	}
	now := time.Now().UTC()
	s.PositionTimestamp = &now
	r.state.Position = *s.Position
	r.state.PlayerState = strings.ToUpper(s.PlaybackState)
	r.signalMRPLocked()
}
func (r *Receiver) finishMRP() {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := &r.mrpState
	s.PlaybackState = "stopped"
	s.PlaybackRate = proto.Float64(0)
	if s.Duration != nil {
		s.Position = proto.Float64(*s.Duration)
	}
	r.state.PlayerState = "IDLE"
	r.signalMRPLocked()
}

// mrpPeer owns all side channels of one verified RTSP control connection.
type mrpPeer struct {
	r         *Receiver
	shared    []byte
	mu        sync.Mutex
	closed    bool
	listeners []net.Listener
	conns     []net.Conn
	wg        sync.WaitGroup
	changed   chan struct{}
	done      chan struct{}
}

func (p *mrpPeer) close() {
	p.mu.Lock()
	p.closed = true
	close(p.done)
	for _, l := range p.listeners {
		l.Close()
	}
	for _, c := range p.conns {
		c.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
	p.r.mu.Lock()
	delete(p.r.mrpPeers, p)
	p.r.mu.Unlock()
}
func (p *mrpPeer) listen(parent net.Conn, salt, outInfo, inInfo string, serve func(net.Conn)) (int, error) {
	l, err := net.Listen("tcp", net.JoinHostPort(parent.LocalAddr().(*net.TCPAddr).IP.String(), "0"))
	if err != nil {
		return 0, err
	}
	p.mu.Lock()
	p.listeners = append(p.listeners, l)
	p.mu.Unlock()
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		conn, err := l.Accept()
		l.Close()
		if err != nil {
			return
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			conn.Close()
			return
		}
		p.conns = append(p.conns, conn)
		p.mu.Unlock()
		defer conn.Close()
		encrypted, err := hapconn.New(conn, hap.HKDFExpand(salt, outInfo, p.shared), hap.HKDFExpand(salt, inInfo, p.shared))
		if err != nil {
			return
		}
		serve(encrypted)
	}()
	return l.Addr().(*net.TCPAddr).Port, nil
}
func (p *mrpPeer) events(conn net.Conn) {
	p.r.mu.Lock()
	p.r.state.EventConnections++
	p.r.mu.Unlock()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "POST /command RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 0\r\n\r\n"); err != nil {
		return
	}
	p.r.mu.Lock()
	p.r.state.EventRequests++
	p.r.mu.Unlock()
	reader := bufio.NewReader(conn)
	line, h, _, err := readLabMessage(reader)
	p.r.mu.Lock()
	if err != nil || !strings.Contains(line, " 200 ") || h.Get("CSeq") != "1" {
		p.r.state.EventErrors++
	} else {
		p.r.state.EventResponses++
	}
	p.r.mu.Unlock()
	conn.SetDeadline(time.Time{})
	io.Copy(io.Discard, reader)
}

func (r *Receiver) serveMRPControl(raw net.Conn) {
	var conn net.Conn = raw
	reader := bufio.NewReader(conn)
	p := &mrpPeer{r: r, changed: make(chan struct{}, 1), done: make(chan struct{})}
	defer p.close()
	var clientPublic, serverPublic []byte
	var pairCipher *hap.Cipher
	verified, events, recorded, data := false, false, false, false
	respond := func(protocol string, status int, cseq string, body []byte) error {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err := fmt.Fprintf(conn, "%s %d %s\r\nCSeq: %s\r\nContent-Length: %d\r\nContent-Type: application/x-apple-binary-plist\r\n\r\n", protocol, status, http.StatusText(status), cseq, len(body))
		if err != nil {
			return err
		}
		_, err = conn.Write(body)
		return err
	}
	for {
		line, h, body, err := readLabMessage(reader)
		if err != nil {
			return
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			return
		}
		method, path, protocol := parts[0], parts[1], parts[2]
		if !verified && method == "POST" && path == "/pair-verify" {
			tags, err := tlv8.Read(body)
			if err != nil {
				return
			}
			seq := tags[tlv8.TagSeqNo]
			var response []byte
			success := false
			if bytes.Equal(seq, []byte{1}) && len(tags[tlv8.TagPublicKey]) == 32 {
				private := make([]byte, 32)
				rand.Read(private)
				clientPublic = tags[tlv8.TagPublicKey]
				serverPublic, _ = curve25519.X25519(private, curve25519.Basepoint)
				p.shared, err = curve25519.X25519(private, clientPublic)
				if err != nil {
					return
				}
				key := hap.HKDFExpand("Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info", p.shared)
				pairCipher, _ = hap.NewCipher(key, key, 8)
				signed := append(append(append([]byte{}, serverPublic...), r.credentials.ATVID...), clientPublic...)
				inner := tlv8.Write(tlv8.Item{Tag: tlv8.TagIdentifier, Value: r.credentials.ATVID}, tlv8.Item{Tag: tlv8.TagSignature, Value: ed25519.Sign(r.mrpSigning, signed)})
				response = tlv8.Write(tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{2}}, tlv8.Item{Tag: tlv8.TagPublicKey, Value: serverPublic}, tlv8.Item{Tag: tlv8.TagEncryptedData, Value: pairCipher.Encrypt(inner, []byte("PV-Msg02"), nil)})
			} else if bytes.Equal(seq, []byte{3}) && pairCipher != nil {
				plain, err := pairCipher.Decrypt(tags[tlv8.TagEncryptedData], []byte("PV-Msg03"), nil)
				if err == nil {
					inner, e := tlv8.Read(plain)
					signed := append(append(append([]byte{}, clientPublic...), r.credentials.ClientID...), serverPublic...)
					public := ed25519.NewKeyFromSeed(r.credentials.LTSK).Public().(ed25519.PublicKey)
					success = e == nil && bytes.Equal(inner[tlv8.TagIdentifier], r.credentials.ClientID) && ed25519.Verify(public, signed, inner[tlv8.TagSignature])
				}
				if success {
					response = tlv8.Write(tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{4}})
				} else {
					response = tlv8.Write(tlv8.Item{Tag: tlv8.TagSeqNo, Value: []byte{4}}, tlv8.Item{Tag: tlv8.TagError, Value: []byte{2}})
				}
			} else {
				return
			}
			if err := respond(protocol, 200, h.Get("CSeq"), response); err != nil {
				return
			}
			if success {
				conn, err = hapconn.New(raw, hap.HKDFExpand("Control-Salt", "Control-Read-Encryption-Key", p.shared), hap.HKDFExpand("Control-Salt", "Control-Write-Encryption-Key", p.shared))
				if err != nil {
					return
				}
				reader = bufio.NewReader(conn)
				verified = true
			}
			continue
		}
		var result map[string]any
		status := 200
		if method == "GET" && path == "/info" {
			result = map[string]any{"features": uint64(1) << 38, "model": "AppleTV14,1", "name": r.config.Name}
		} else if !verified {
			status = 470
		} else {
			r.mu.Lock()
			r.state.EncryptedRequests++
			r.mu.Unlock()
			switch method {
			case "SETUP":
				var setup map[string]any
				if _, err := plist.Unmarshal(body, &setup); err != nil {
					return
				}
				if remote, _ := setup["isRemoteControlOnly"].(bool); remote && !events {
					if setup["timingProtocol"] != "None" {
						return
					}
					port, err := p.listen(raw, "Events-Salt", "Events-Write-Encryption-Key", "Events-Read-Encryption-Key", p.events)
					if err != nil {
						return
					}
					result = map[string]any{"eventPort": port}
					events = true
				} else if streams, ok := setup["streams"].([]any); ok && len(streams) == 1 && recorded && !data {
					stream, ok := streams[0].(map[string]any)
					if !ok {
						return
					}
					kind, _ := labInt(stream["type"])
					control, _ := labInt(stream["controlType"])
					seed, ok := stream["seed"].(uint64)
					if !ok || kind != 130 || control != 2 || stream["clientTypeUUID"] != "1910A70F-DBC0-4242-AF95-115DB30604E1" {
						return
					}
					port, err := p.listen(raw, "DataStream-Salt"+strconv.FormatUint(seed, 10), "DataStream-Input-Encryption-Key", "DataStream-Output-Encryption-Key", p.data)
					if err != nil {
						return
					}
					result = map[string]any{"streams": []any{map[string]any{"dataPort": port, "type": 130}}}
					data = true
				} else {
					status = 400
				}
			case "RECORD":
				if !events {
					status = 400
				} else {
					recorded = true
				}
			case "POST":
				if path != "/feedback" {
					status = 404
				}
			default:
				status = 501
			}
		}
		var out []byte
		if result != nil {
			out, err = plist.Marshal(result, plist.BinaryFormat)
			if err != nil {
				return
			}
		}
		if err := respond(protocol, status, h.Get("CSeq"), out); err != nil {
			return
		}
	}
}

func (p *mrpPeer) data(conn net.Conn) {
	channel := pb.NewChannel(conn)
	type received struct {
		messages []*pb.ProtocolMessage
		err      error
	}
	incoming := make(chan received, 1)
	done := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			messages, err := channel.Receive()
			select {
			case incoming <- received{messages, err}:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() { close(done); conn.Close(); <-readerDone }()
	stage := 0
	reply := func(request *pb.ProtocolMessage, kind uint32) error {
		response := pb.NewMessage(kind)
		response.Identifier = request.Identifier
		return channel.Send(response)
	}
	for {
		select {
		case <-p.done:
			return
		case <-p.changed:
			if stage >= 3 {
				if err := p.sendState(channel); err != nil {
					return
				}
			}
		case r := <-incoming:
			if r.err != nil {
				return
			}
			for _, msg := range r.messages {
				switch msg.GetType() {
				case pb.DeviceInfo:
					if stage != 0 || msg.GetDeviceInfo() == nil {
						return
					}
					response := pb.NewMessage(pb.DeviceInfo)
					response.Identifier = msg.Identifier
					response.DeviceInfo = &pb.DeviceInfoMessage{Name: proto.String(p.r.config.Name), UniqueIdentifier: proto.String(p.r.id), ProtocolVersion: proto.Int32(1), DeviceClass: proto.Uint32(4)}
					if err := channel.Send(response); err != nil {
						return
					}
					stage = 1
				case pb.ConnectionState:
					if stage != 1 || msg.GetConnectionState().GetState() != 2 {
						return
					}
					stage = 2
				case pb.ClientUpdates:
					if stage < 2 {
						return
					}
					p.r.mu.Lock()
					p.r.mrpPeers[p] = struct{}{}
					p.r.mu.Unlock()
					stage = 3
					if err := p.sendState(channel); err != nil {
						return
					}
					if err := reply(msg, pb.Generic); err != nil {
						return
					}
				case pb.KeyboardSession, pb.Generic:
					if stage < 3 {
						return
					}
					if err := reply(msg, pb.Generic); err != nil {
						return
					}
				}
			}
		}
	}
}

func (p *mrpPeer) sendState(channel *pb.Channel) error {
	p.r.mu.Lock()
	s := cloneMRPState(p.r.mrpState)
	p.r.mu.Unlock()
	client := &pb.NowPlayingClient{BundleIdentifier: proto.String(s.App), DisplayName: proto.String(s.AppName)}
	active := pb.NewMessage(pb.NowPlayingClientMessage)
	active.NowPlayingClient = &pb.ClientMessage{Client: client}
	if s.App == "" {
		return channel.Send(active)
	}
	playerID := s.PlayerID
	if playerID == "" {
		playerID = "MediaRemote-DefaultPlayer"
	}
	path := &pb.PlayerPath{Client: client, Player: &pb.NowPlayingPlayer{Identifier: proto.String(playerID), IsDefaultPlayer: proto.Bool(true)}}
	player := pb.NewMessage(pb.NowPlayingPlayerMessage)
	player.NowPlayingPlayer = &pb.PlayerMessage{PlayerPath: path}
	state := pb.NewMessage(pb.SetState)
	value := uint32(0)
	switch s.PlaybackState {
	case "playing":
		value = 1
	case "paused":
		value = 2
	case "stopped":
		value = 3
	case "interrupted":
		value = 4
	case "seeking":
		value = 5
	}
	queue := &pb.PlaybackQueue{Location: proto.Int32(0)}
	if s.ItemID != "" || s.Title != "" {
		meta := &pb.ContentItemMetadata{AssetURLString: proto.String(s.ContentURL), Title: proto.String(s.Title), TrackArtistName: proto.String(s.Artist), AlbumName: proto.String(s.Album), Genre: proto.String(s.Genre), SeriesName: proto.String(s.SeriesName), SeasonNumber: s.SeasonNumber, EpisodeNumber: s.EpisodeNumber, Duration: s.Duration, ElapsedTime: s.Position, IsAlwaysLive: proto.Bool(s.Live)}
		if s.PlaybackRate != nil {
			meta.PlaybackRate = proto.Float32(float32(*s.PlaybackRate))
		}
		if s.PositionTimestamp != nil {
			meta.ElapsedTimeTimestamp = proto.Float64(float64(s.PositionTimestamp.Unix()-978307200) + float64(s.PositionTimestamp.Nanosecond())/1e9)
		}
		switch s.MediaType {
		case "audio":
			meta.MediaType = proto.Uint32(1)
		case "video":
			meta.MediaType = proto.Uint32(2)
		}
		id := s.ItemID
		if id == "" {
			id = "simulator-item"
		}
		queue.ContentItems = []*pb.ContentItem{{Identifier: proto.String(id), Metadata: meta}}
	}
	state.SetState = &pb.SetStateMessage{PlayerPath: path, PlaybackState: &value, PlaybackQueue: queue}
	return channel.Send(state, player, active)
}
