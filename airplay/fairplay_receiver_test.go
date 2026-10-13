package airplay

import (
	"bufio"
	"context"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jkiddo/go-atv/simulator"
)

func TestFairPlayReceiverEnforcesParentSessionOrder(t *testing.T) {
	r, err := simulator.New(simulator.Config{FairPlay: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	conn, err := dial(ctx, "127.0.0.1", r.Port())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.close()
	creds := r.Credentials()
	parent := newRTSPSession(conn, &creds)
	check := func(method string, body any, want int) {
		t.Helper()
		reply, err := parent.exchange(ctx, method, "", nil, body)
		if err != nil || reply.Code != want {
			t.Fatalf("%s: reply=%+v err=%v want=%d", method, reply, err, want)
		}
	}
	for _, method := range []string{"SETUP", "RECORD", "TEARDOWN", "SET_PARAMETER"} {
		check(method, map[string]any{}, 455)
	}
	secret, err := verifyLegacyPD(ctx, conn, creds, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	check("RECORD", nil, 455)
	check("SETUP", map[string]any{}, 455)
	sap, err := setupFairPlay(ctx, conn, nil)
	if err != nil {
		t.Fatal(err)
	}
	timing, err := newTimingServer(conn.localIP)
	if err != nil {
		t.Fatal(err)
	}
	defer timing.close()
	var key [16]byte
	rand.Read(key[:])
	wrapped, err := sap.WrapStream(key, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"ekey": wrapped[:], "sessionUUID": newUUID(), "timingPort": timing.port}
	check("SETUP", body, 200)
	check("SETUP", body, 455)
	check("RECORD", nil, 200)
	check("RECORD", nil, 455)
	check("TEARDOWN", nil, 200)
	check("RECORD", nil, 455)
}

func TestFairPlayParentEventsFragmentationPipeliningAndCancel(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(2 * time.Second))
	b.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() { done <- acknowledgeFairPlayEvents(a, []byte("POST /comm")) }()
	writeDone := make(chan error, 1)
	go func() {
		_, err := io.WriteString(b, "and RTSP/1.0\r\nCSeq: 71\r\nContent-Length: 3\r\n\r\nonePOST /command RTSP/1.0\r\nCSeq: 72\r\nContent-Length: 3\r\n\r\ntwo")
		writeDone <- err
	}()
	reader := bufio.NewReader(b)
	for _, seq := range []string{"71", "72"} {
		var header strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			header.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		if !strings.Contains(header.String(), "CSeq: "+seq+"\r\n") || !strings.HasPrefix(header.String(), "RTSP/1.0 200 OK") {
			t.Fatalf("bad response: %s", header.String())
		}
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	a.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("event worker did not exit")
	}
}
