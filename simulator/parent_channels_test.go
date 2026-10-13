package simulator

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParentEventAcknowledgementValidation(t *testing.T) {
	for _, tc := range []struct {
		name, wire string
		want       bool
	}{
		{"valid", "RTSP/1.0 200 OK\r\nCSeq: 7\r\nContent-Length: 3\r\n\r\nack", true},
		{"duplicate sequence", "RTSP/1.0 200 OK\r\nCSeq: 7\r\nCSeq: 7\r\n\r\n", false},
		{"wrong sequence", "RTSP/1.0 200 OK\r\nCSeq: 8\r\n\r\n", false},
		{"rejected", "RTSP/1.0 500 Error\r\nCSeq: 7\r\n\r\n", false},
		{"QuickTime omits sequence", "RTSP/1.0 200 OK\r\n\r\n", true},
		{"duplicate length", "RTSP/1.0 200 OK\r\nCSeq: 7\r\nContent-Length: 0\r\nContent-Length: 2\r\n\r\n", false},
		{"huge header", "RTSP/1.0 200 OK\r\nX: " + strings.Repeat("x", 20000) + "\r\n\r\n", false},
		{"huge body", "RTSP/1.0 200 OK\r\nCSeq: 7\r\nContent-Length: 1048577\r\n\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := readParentEventResponse(bufio.NewReader(strings.NewReader(tc.wire)), 7)
			if (err == nil) != tc.want {
				t.Fatalf("response validation: %v", err)
			}
		})
	}
}
func TestLabReaderPreservesPipelinedBodies(t *testing.T) {
	wire := "POST /first RTSP/1.0\r\nContent-Length: 3\r\n\r\nonePOST /second RTSP/1.0\r\nContent-Length: 3\r\n\r\ntwo"
	r := bufio.NewReaderSize(bytes.NewBufferString(wire), 16)
	for _, want := range []string{"one", "two"} {
		_, _, body, err := readLabMessage(r)
		if err != nil || string(body) != want {
			t.Fatalf("body %q, %v", body, err)
		}
	}
}
func TestTimingProbeRejectsMalformedReplies(t *testing.T) {
	for _, kind := range []string{"valid", "wrong type", "wrong reference", "short", "wrong source", "missing timestamps"} {
		t.Run(kind, func(t *testing.T) {
			recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer recv.Close()
			sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			p := &parentChannels{receiver: &Receiver{}, timing: recv}
			done := make(chan error, 1)
			go func() {
				var q [32]byte
				sender.SetDeadline(time.Now().Add(time.Second))
				n, peer, err := sender.ReadFromUDP(q[:])
				if err != nil {
					done <- err
					return
				}
				if n != 32 {
					done <- fmt.Errorf("request length")
					return
				}
				reply := q
				reply[1] = 0xd3
				copy(reply[8:16], q[24:])
				binary.BigEndian.PutUint64(reply[16:24], 1)
				socket := sender
				length := 32
				switch kind {
				case "wrong type":
					reply[1] = 0xd2
				case "wrong reference":
					reply[8] ^= 1
				case "short":
					length = 31
				case "missing timestamps":
					clear(reply[16:24])
				case "wrong source":
					socket, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
					if err != nil {
						done <- err
						return
					}
					defer socket.Close()
				}
				_, err = socket.WriteToUDP(reply[:length], peer)
				done <- err
			}()
			err = p.probeTiming(sender.LocalAddr().(*net.UDPAddr), 1)
			if (err == nil) != (kind == "valid") {
				t.Fatalf("probe %s: %v", kind, err)
			}
			if e := <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}
