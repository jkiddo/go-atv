package hapconn

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jkiddo/go-atv/hap"
)

func TestEncryptedFragmentedStream(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(time.Second))
	b.SetDeadline(time.Now().Add(time.Second))
	key := bytes.Repeat([]byte{7}, 32)
	client, _ := New(a, key, key)
	server, _ := hap.NewSession(key, key)
	want := bytes.Repeat([]byte("metadata"), 500)
	wire := server.Encrypt(want)
	done := make(chan error, 1)
	go func() {
		for i := 0; i < len(wire); i += 7 {
			end := min(i+7, len(wire))
			if _, err := b.Write(wire[i:end]); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("stream corrupted")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestRejectTamperingAndOversizedHAPRecords(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	s, _ := hap.NewSession(key, key)
	bad := s.Encrypt([]byte("metadata"))
	bad[len(bad)-1] ^= 1
	for _, wire := range [][]byte{bad, {1, 4}} {
		a, b := net.Pipe()
		client, _ := New(a, key, key)
		go func() { b.Write(wire); b.Close() }()
		if _, err := client.Read(make([]byte, 50)); err == nil {
			t.Error("invalid frame accepted")
		}
		a.Close()
	}
}
