package airplay

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/jkiddo/go-atv/hap"
)

// eventChannel is the encrypted side channel an AirPlay 2 receiver opens
// during SETUP. The Apple TV acts as HTTP client on it; we only need to
// answer every request with 200 OK to keep the session alive (pyatv's
// EventChannel).
type eventChannel struct {
	done    chan struct{}
	conn    net.Conn
	session *hap.Session
}

// connectEventChannel dials the event port announced in the SETUP response
// and starts answering requests. Connection attempts are retried a few times
// since some receivers open the port slightly after announcing it.
func connectEventChannel(ctx context.Context, address string, port int, v *verifier) (*eventChannel, error) {
	// Argument order mirrors pyatv: the channel's output (client to device)
	// key is derived from the "read" info string and vice versa.
	outputKey, inputKey := v.encryptionKeys(eventsSalt, eventsReadInfo, eventsWriteInfo)
	session, err := hap.NewSession(outputKey, inputKey)
	if err != nil {
		return nil, err
	}

	var dialer net.Dialer
	var conn net.Conn
	for attempt := 0; ; attempt++ {
		conn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
		if err == nil {
			break
		}
		if attempt >= 4 || ctx.Err() != nil {
			return nil, fmt.Errorf("airplay: connect event channel: %w", err)
		}
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	channel := &eventChannel{conn: conn, session: session, done: make(chan struct{})}
	go channel.serve()
	return channel, nil
}

func (e *eventChannel) close() {
	e.conn.Close()
	<-e.done
}

// serve answers every incoming request with 200 OK until the connection is
// closed by either side.
func (e *eventChannel) serve() {
	defer close(e.done)
	var pending []byte
	buf := make([]byte, 4096)
	for {
		n, err := e.conn.Read(buf)
		if err != nil {
			return
		}
		plain, err := e.session.Decrypt(buf[:n])
		if err != nil {
			return
		}
		pending = append(pending, plain...)

		for {
			request, rest, err := parseRequest(pending)
			if err != nil {
				return
			}
			if request == nil {
				break
			}
			pending = rest

			reply := fmt.Sprintf("%s 200 OK\r\nContent-Length: 0\r\nAudio-Latency: 0\r\n", request.Protocol)
			if server, ok := request.Headers["server"]; ok {
				reply += "Server: " + server + "\r\n"
			}
			if cseq, ok := request.Headers["cseq"]; ok {
				reply += "CSeq: " + cseq + "\r\n"
			}
			reply += "\r\n"
			if _, err := e.conn.Write(e.session.Encrypt([]byte(reply))); err != nil {
				return
			}
		}
	}
}
