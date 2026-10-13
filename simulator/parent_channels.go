package simulator

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"howett.net/plist"
)

// These channels belong to the RTSP parent, not the encrypted HTTP reverse
// socket. The legacy event channel is plaintext; modern HAP is a separate path.
type parentChannels struct {
	receiver *Receiver
	event    net.Listener
	timing   *net.UDPConn
	mu       sync.Mutex
	conn     net.Conn
	closed   bool
	once     sync.Once
	wg       sync.WaitGroup
}

func (r *Receiver) newParentChannels(parent net.Conn, senderPort int) (*parentChannels, error) {
	ip := parent.LocalAddr().(*net.TCPAddr).IP
	event, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		return nil, err
	}
	timing, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
	if err != nil {
		event.Close()
		return nil, err
	}
	p := &parentChannels{receiver: r, event: event, timing: timing}
	peer := parent.RemoteAddr().(*net.TCPAddr)
	p.wg.Add(2)
	go func() { defer p.wg.Done(); p.serveEvents() }()
	go func() {
		defer p.wg.Done()
		if err := p.probeTiming(&net.UDPAddr{IP: peer.IP, Port: senderPort}, 3); err != nil {
			p.failure(false, err)
		}
	}()
	return p, nil
}
func (p *parentChannels) eventPort() int  { return p.event.Addr().(*net.TCPAddr).Port }
func (p *parentChannels) timingPort() int { return p.timing.LocalAddr().(*net.UDPAddr).Port }
func (p *parentChannels) count(f func(*State)) {
	p.receiver.mu.Lock()
	f(&p.receiver.state)
	p.receiver.mu.Unlock()
}
func (p *parentChannels) failure(event bool, err error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if !closed {
		if p.receiver.config.Trace != nil {
			method := "PARENT-TIMING"
			if event {
				method = "PARENT-EVENT"
			}
			p.receiver.config.Trace(ProtocolEvent{Method: method, Error: err.Error()})
		}
		p.count(func(s *State) {
			if event {
				s.EventErrors++
			} else {
				s.TimingErrors++
			}
		})
	}
}
func (p *parentChannels) serveEvents() {
	conn, err := p.event.Accept()
	if err != nil {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		conn.Close()
		return
	}
	p.conn = conn
	p.mu.Unlock()
	defer conn.Close()
	p.count(func(s *State) { s.EventConnections++ })
	body, _ := plist.Marshal(map[string]any{"type": "forceKeyFrame"}, plist.BinaryFormat)
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = fmt.Fprintf(conn, "POST /command RTSP/1.0\r\nCSeq: 1\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: %d\r\n\r\n", len(body)); err == nil {
		_, err = conn.Write(body)
	}
	if err != nil {
		p.failure(true, err)
		return
	}
	p.count(func(s *State) { s.EventRequests++ })
	reader := bufio.NewReader(conn)
	if err = readParentEventResponse(reader, 1); err != nil {
		p.failure(true, err)
		return
	}
	p.count(func(s *State) { s.EventResponses++ })
	if p.receiver.config.Trace != nil {
		p.receiver.config.Trace(ProtocolEvent{Method: "PARENT-EVENT", Status: 200})
	}
	conn.SetDeadline(time.Time{})
	io.Copy(io.Discard, reader)
}
func readParentEventResponse(reader *bufio.Reader, seq int) error {
	line, h, _, err := readLabMessage(reader)
	if err != nil {
		return err
	}
	// QuickTime returns 200 without CSeq. With exactly one outstanding request,
	// that reply is unambiguous; an explicitly wrong sequence is still rejected.
	parts := strings.Fields(line)
	if len(h.Values("CSeq")) > 1 || len(parts) < 2 || (parts[0] != "RTSP/1.0" && parts[0] != "HTTP/1.1") || parts[1] != "200" || (h.Get("CSeq") != "" && h.Get("CSeq") != strconv.Itoa(seq)) {
		return fmt.Errorf("invalid parent event acknowledgement: status=%q cseq=%q", line, h.Get("CSeq"))
	}
	return nil
}
func (p *parentChannels) probeTiming(peer *net.UDPAddr, count int) error {
	for seq := 1; seq <= count; seq++ {
		var request [32]byte
		request[0] = 0x80
		request[1] = 0xd2
		binary.BigEndian.PutUint16(request[2:4], uint16(seq))
		now := time.Now()
		stamp := (uint64(now.Unix()+2208988800) << 32) | (uint64(now.Nanosecond())<<32)/1000000000
		binary.BigEndian.PutUint64(request[24:], stamp)
		p.timing.SetDeadline(time.Now().Add(time.Second))
		if _, err := p.timing.WriteToUDP(request[:], peer); err != nil {
			return err
		}
		p.count(func(s *State) { s.TimingProbes++ })
		var reply [33]byte
		n, from, err := p.timing.ReadFromUDP(reply[:])
		if err != nil {
			return err
		}
		if !from.IP.Equal(peer.IP) || from.Port != peer.Port || n != 32 || reply[0] != 0x80 || reply[1] != 0xd3 || !bytes.Equal(reply[8:16], request[24:32]) || binary.BigEndian.Uint64(reply[16:24]) == 0 || binary.BigEndian.Uint64(reply[24:32]) == 0 {
			return fmt.Errorf("invalid timing response")
		}
		p.count(func(s *State) { s.TimingReplies++ })
		if p.receiver.config.Trace != nil {
			p.receiver.config.Trace(ProtocolEvent{Method: "PARENT-TIMING", Status: 200})
		}
	}
	return nil
}
func (p *parentChannels) close() {
	p.once.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.event.Close()
		p.timing.Close()
		if p.conn != nil {
			p.conn.Close()
		}
		p.mu.Unlock()
	})
	p.wg.Wait()
}
