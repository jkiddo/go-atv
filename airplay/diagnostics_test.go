package airplay

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jkiddo/go-atv/hap"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLegacyHandshakeDiagnostics(t *testing.T) {
	for _, challenge := range []bool{false, true} {
		t.Run(fmt.Sprintf("challenge=%t", challenge), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(conn)
				// Two pair-verify steps plus the digest-priming status probe and
				// the follow-up /playback-info query.
				steps := 3
				if challenge {
					steps = 4
				}
				for i := 0; i < steps; i++ {
					req, err := http.ReadRequest(reader)
					if err != nil {
						done <- err
						return
					}
					io.Copy(io.Discard, req.Body)
					req.Body.Close()
					want := "/pair-verify"
					if i >= 2 {
						want = "/playback-info"
					}
					if req.URL.Path != want {
						done <- fmt.Errorf("path=%s, want %s", req.URL.Path, want)
						return
					}
					code, body, headers := 200, []byte{}, ""
					if i == 0 {
						body = decodeHex(t, legacyVerifyResponse)
					}
					if i == 2 && challenge {
						code = 401
						headers = "WWW-Authenticate: Digest realm=\"private-realm\", nonce=\"private-nonce\"\r\n"
					} else if i >= 2 {
						code = 453
					}
					if i == 3 && challenge && !strings.Contains(req.Header.Get("Authorization"), `username="AirPlay"`) {
						done <- errors.New("saved code was not submitted using the AirPlay username")
						return
					}
					fmt.Fprintf(conn, "HTTP/1.1 %d Test\r\n%sContent-Length: %d\r\n\r\n", code, headers, len(body))
					conn.Write(body)
				}
				done <- nil
			}()
			credentials, err := hap.ParseCredentials(legacyTestCredentials)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "credentials")
			if err := hap.SaveCredentials(path, credentials); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path+".password", []byte("0299"), 0600); err != nil {
				t.Fatal(err)
			}
			var events []DiagnosticEvent
			client := New("test", path, "127.0.0.1", WithPort(listener.Addr().(*net.TCPAddr).Port), WithProperties(map[string]string{"features": "0x1"}), WithDiagnosticHandler(func(e DiagnosticEvent) { events = append(events, e) }))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			info, err := client.PlaybackInfo(ctx)
			var status *StatusError
			if !errors.As(err, &status) || status.Code != 453 || info != nil {
				t.Fatalf("playback-info = %v, error = %v; want receiver refusal", info, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if events[0].Stage != "credentials" || events[0].Result != "loaded" || len(events[0].Identity) != 16 {
				t.Fatalf("credentials=%+v", events)
			}
			if events[1].Stage != "pair-verify" || events[1].Result != "accepted" {
				t.Fatalf("verify=%+v", events)
			}
			if events[2].Stage != "saved-airplay-code" || !events[2].SavedCode {
				t.Fatalf("code=%+v", events)
			}
			expected := 453
			if challenge {
				expected = 401
			}
			if events[3].Stage != "digest-probe" || events[3].StatusCode != expected || events[3].Challenge != challenge {
				t.Fatalf("probe=%+v", events)
			}
			if challenge && (len(events) != 5 || events[4].Stage != "playback-info" || events[4].StatusCode != 453) {
				t.Fatalf("final=%+v", events)
			}
			encoded, _ := json.Marshal(events)
			for _, secret := range []string{"0299", "private-nonce", "private-realm", legacyTestCredentials, strings.Split(legacyTestCredentials, ":")[1]} {
				if strings.Contains(string(encoded), secret) {
					t.Fatal("diagnostics disclosed a secret")
				}
			}
			var reloaded DiagnosticEvent
			restarted := New("test", path, "127.0.0.1", WithDiagnosticHandler(func(e DiagnosticEvent) { reloaded = e }))
			if _, err := restarted.loadCredentials(); err != nil {
				t.Fatal(err)
			}
			if reloaded.Identity != events[0].Identity {
				t.Fatal("identity changed after recreating client")
			}
		})
	}
}

func TestCodeRefreshUsesAirPlayDigestAndKeepsIdentity(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	verifyResponse := decodeHex(t, legacyVerifyResponse)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		for i := 0; i < 5; i++ {
			req, err := http.ReadRequest(reader)
			if err != nil {
				done <- err
				return
			}
			io.Copy(io.Discard, req.Body)
			req.Body.Close()
			code, body, headers := 200, []byte{}, ""
			if i == 0 {
				body = verifyResponse
			}
			if i == 2 || i == 3 {
				code = 401
				headers = "WWW-Authenticate: Digest realm=\"AirPlay\", nonce=\"fixture-nonce\"\r\n"
			}
			if i >= 3 && !strings.Contains(req.Header.Get("Authorization"), `username="AirPlay"`) {
				done <- errors.New("wrong Digest username for AirPlay video")
				return
			}
			if i == 4 && !strings.Contains(req.Header.Get("Authorization"), `response="3cdfa2b6532da7758665e98cb5b3dec3"`) {
				done <- errors.New("wrong Digest response after retrying code")
				return
			}
			fmt.Fprintf(conn, "HTTP/1.1 %d Test\r\n%sContent-Length: %d\r\n\r\n", code, headers, len(body))
			conn.Write(body)
		}
		done <- nil
	}()
	path := filepath.Join(t.TempDir(), "credentials")
	credentials, err := hap.ParseCredentials(legacyTestCredentials)
	if err != nil {
		t.Fatal(err)
	}
	if err := hap.SaveCredentials(path, credentials); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var events []DiagnosticEvent
	client := New("test", path, "127.0.0.1", WithPort(listener.Addr().(*net.TCPAddr).Port), WithProperties(map[string]string{"features": "0x1"}), WithDiagnosticHandler(func(e DiagnosticEvent) { events = append(events, e) }))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	required, err := client.StartPasswordPairing(ctx)
	if err != nil || !required {
		t.Fatalf("start=%t, %v", required, err)
	}
	var invalid *InvalidAuth
	if err := client.FinishPasswordPairing(ctx, "0000"); !errors.As(err, &invalid) {
		t.Fatalf("wrong-code error=%v", err)
	}
	if err := client.FinishPasswordPairing(ctx, "1234"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("code refresh replaced pairing identity")
	}
	code, err := os.ReadFile(path + ".password")
	if err != nil || strings.TrimSpace(string(code)) != "1234" {
		t.Fatal("successful code was not saved")
	}
	var submissions []int
	for _, e := range events {
		if e.Stage == "code-submit" {
			submissions = append(submissions, e.StatusCode)
		}
	}
	if fmt.Sprint(submissions) != "[401 200]" {
		t.Fatalf("submission statuses=%v", submissions)
	}
}
