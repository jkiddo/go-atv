package simulator

import (
	"fmt"
	"howett.net/plist"
	"net"
	"sync"
	"time"
)

type reversePeer struct {
	conn    net.Conn
	session string
	mu      sync.Mutex
}

func (r *Receiver) registerReverse(conn net.Conn, session string) func() {
	p := &reversePeer{conn: conn, session: session}
	r.mu.Lock()
	if r.reversePeers == nil {
		r.reversePeers = make(map[*reversePeer]struct{})
	}
	r.reversePeers[p] = struct{}{}
	r.mu.Unlock()
	return func() { r.mu.Lock(); delete(r.reversePeers, p); r.mu.Unlock() }
}
func (r *Receiver) notifyFairPlay() {
	r.mu.Lock()
	state := r.state.PlayerState
	session := r.session
	var peers []*reversePeer
	for p := range r.reversePeers {
		if p.session == session {
			peers = append(peers, p)
		}
	}
	r.mu.Unlock()
	value := "stopped"
	if state == "PLAYING" {
		value = "playing"
	} else if state == "PAUSED" {
		value = "paused"
	}
	body, _ := plist.Marshal(map[string]any{"category": "video", "state": value}, plist.XMLFormat)
	for _, p := range peers {
		wire := []byte(fmt.Sprintf("POST /event HTTP/1.1\r\nContent-Type: text/x-apple-plist+xml\r\nX-Apple-Session-ID: %s\r\nContent-Length: %d\r\n\r\n", p.session, len(body)))
		wire = append(wire, body...)
		p.mu.Lock()
		p.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, e := p.conn.Write(wire)
		p.mu.Unlock()
		if e != nil {
			p.conn.Close()
		}
	}
}
