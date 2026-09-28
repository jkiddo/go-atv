package airplay

import (
	"encoding/binary"
	"net"
	"time"
)

// timingServer answers the receiver's NTP-style timing requests over UDP
// (pyatv's TimingServer). Video receivers rarely query it, but the port must
// exist since it is announced during SETUP.
type timingServer struct {
	conn *net.UDPConn
	port int
}

const timingPacketSize = 32 // proto, type, seqno, padding + 3 timestamps

// newTimingServer starts a timing server on a random UDP port bound to
// localIP.
func newTimingServer(localIP string) (*timingServer, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(localIP)})
	if err != nil {
		return nil, err
	}
	server := &timingServer{conn: conn, port: conn.LocalAddr().(*net.UDPAddr).Port}
	go server.serve()
	return server, nil
}

func (t *timingServer) close() {
	t.conn.Close()
}

func (t *timingServer) serve() {
	buf := make([]byte, 128)
	for {
		n, addr, err := t.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < timingPacketSize {
			continue
		}

		recvSec, recvFrac := ntpNow()
		resp := make([]byte, timingPacketSize)
		resp[0] = buf[0]                         // proto
		resp[1] = 0x53 | 0x80                    // type: timing reply
		binary.BigEndian.PutUint16(resp[2:4], 7) // seqno
		// padding stays zero
		copy(resp[8:16], buf[24:32]) // reftime = request sendtime
		binary.BigEndian.PutUint32(resp[16:20], recvSec)
		binary.BigEndian.PutUint32(resp[20:24], recvFrac)
		binary.BigEndian.PutUint32(resp[24:28], recvSec)
		binary.BigEndian.PutUint32(resp[28:32], recvFrac)

		if _, err := t.conn.WriteToUDP(resp, addr); err != nil {
			return
		}
	}
}

// ntpNow returns the current time as NTP seconds (epoch 1900) and fraction.
func ntpNow() (uint32, uint32) {
	now := time.Now()
	seconds := uint32(now.Unix() + 0x83AA7E80)
	frac := uint32((uint64(now.Nanosecond()) << 32) / 1_000_000_000)
	return seconds, frac
}
