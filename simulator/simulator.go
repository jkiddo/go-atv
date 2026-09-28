// Package simulator provides a small, stateful receiver for integration tests.
// It speaks the device's network protocol but never fetches or decodes media.
// Playback time advances only when Advance is called.
package simulator

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/jkiddo/go-atv/hap"
)

// Config configures an isolated receiver. The zero value listens on loopback
// with an ephemeral port, has a 30-second media duration and disables mDNS.
type Config struct {
	Listen   string
	Name     string
	Duration time.Duration
	// AdvertiseIP opts into LAN discovery. Bind Listen to this IP or a wildcard.
	AdvertiseIP string
	Password    string
}

// State is a copy of receiver playback state. URLs are recorded, never fetched.
type State struct {
	URL         string  `json:"url"`
	PlayerState string  `json:"playerState"`
	Position    float64 `json:"position"`
	Duration    float64 `json:"duration"`
	RepeatMode  string  `json:"repeatMode,omitempty"`
	PlayCount   int     `json:"playCount"`
	Loops       int     `json:"loops"`
}

type Receiver struct {
	id                string
	mu                sync.Mutex
	config            Config
	listener          net.Listener
	connections       map[net.Conn]struct{}
	wg                sync.WaitGroup
	once              sync.Once
	closed            bool
	shutdownDiscovery func()
	state             State
	failNext          bool
	credentials       hap.Credentials
	nonce             string
	session           string
}

// New starts a receiver. Close it after use. Discovery is opt-in.
func New(config Config) (*Receiver, error) {
	if config.Listen == "" {
		config.Listen = "127.0.0.1:0"
	}
	if config.Name == "" {
		config.Name = "Broadster Simulator"
	}
	if config.Duration == 0 {
		config.Duration = 30 * time.Second
	}
	if config.Duration < 0 {
		return nil, errors.New("duration must be positive")
	}
	r := &Receiver{config: config, connections: make(map[net.Conn]struct{}), state: State{PlayerState: "IDLE", Duration: config.Duration.Seconds()}}
	identity := make([]byte, 16)
	if _, err := rand.Read(identity); err != nil {
		return nil, err
	}
	r.id = hex.EncodeToString(identity)
	if err := r.listen(); err != nil {
		return nil, err
	}
	if config.AdvertiseIP != "" {
		ip := net.ParseIP(config.AdvertiseIP)
		bind := r.listener.Addr().(*net.TCPAddr).IP
		if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || (!bind.IsUnspecified() && !bind.Equal(ip)) {
			r.listener.Close()
			return nil, errors.New("AdvertiseIP must be a non-loopback IP reachable through Listen")
		}
		if err := r.advertise(ip); err != nil {
			r.listener.Close()
			return nil, err
		}
	}
	r.wg.Add(1)
	go r.accept()
	return r, nil
}

func (r *Receiver) Addr() net.Addr  { return r.listener.Addr() }
func (r *Receiver) Port() int       { return r.listener.Addr().(*net.TCPAddr).Port }
func (r *Receiver) Snapshot() State { r.mu.Lock(); defer r.mu.Unlock(); return r.state }

// FailNextPlay rejects one subsequent playback request without replacing media.
func (r *Receiver) FailNextPlay() { r.mu.Lock(); r.failNext = true; r.mu.Unlock() }

// Advance moves the simulated playback clock. It is safe to call concurrently.
// Paused/idle playback does not advance. Cast single-item repeat loops in place.
func (r *Receiver) Advance(elapsed time.Duration) {
	r.mu.Lock()
	changed := false
	if elapsed > 0 && r.state.PlayerState == "PLAYING" {
		r.state.Position += elapsed.Seconds()
		if r.state.Position >= r.state.Duration {
			if r.state.RepeatMode == "REPEAT_SINGLE" || r.state.RepeatMode == "REPEAT_ALL" {
				loops := int(r.state.Position / r.state.Duration)
				r.state.Loops += loops
				r.state.Position -= float64(loops) * r.state.Duration
			} else {
				r.state.Position = r.state.Duration
				r.state.PlayerState = "IDLE"
			}
			changed = true
		}
	}
	r.mu.Unlock()
	if changed {
		r.notify()
	}
}

// Finish ends the current item immediately, ignoring repeat mode.
func (r *Receiver) Finish() {
	r.mu.Lock()
	r.state.Position = r.state.Duration
	r.state.PlayerState = "IDLE"
	r.mu.Unlock()
	r.notify()
}

// Disconnect drops control connections while retaining the receiver's state.
// New clients can reconnect; this is distinct from stopping media.
func (r *Receiver) Disconnect() {
	r.mu.Lock()
	for conn := range r.connections {
		conn.Close()
	}
	r.mu.Unlock()
}

// Close stops advertising, closes all connections and waits for workers.
func (r *Receiver) Close() error {
	r.once.Do(func() {
		r.mu.Lock()
		r.closed = true
		r.mu.Unlock()
		if r.shutdownDiscovery != nil {
			r.shutdownDiscovery()
		}
		r.listener.Close()
		r.Disconnect()
	})
	r.wg.Wait()
	return nil
}

func (r *Receiver) accept() {
	defer r.wg.Done()
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			return
		}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			conn.Close()
			return
		}
		r.connections[conn] = struct{}{}
		r.wg.Add(1)
		r.mu.Unlock()
		go func() {
			defer r.wg.Done()
			defer func() { conn.Close(); r.mu.Lock(); delete(r.connections, conn); r.mu.Unlock() }()
			r.serve(conn)
		}()
	}
}

// Use only the interface owning the advertised address, not VPN/VM interfaces.
func interfaceForIP(ip net.IP) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			candidate, _, err := net.ParseCIDR(address.String())
			if err == nil && candidate.Equal(ip) {
				return &iface, nil
			}
		}
	}
	return nil, errors.New("AdvertiseIP is not assigned to a local interface")
}
