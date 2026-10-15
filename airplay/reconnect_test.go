package airplay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jkiddo/go-atv/hap"
)

func TestPlaybackConnectionReset(t *testing.T) {
	for _, standalone := range []bool{false, true} {
		name := "owning playback loop"
		if standalone {
			name = "standalone status"
		}
		t.Run(name, func(t *testing.T) {
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
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					done <- err
					return
				}
				req.Body.Close()
				if req.Method != "GET" || req.URL.Path != "/playback-info" {
					done <- fmt.Errorf("unexpected request: %s %s", req.Method, req.URL.Path)
					return
				}
				// Abort after consuming the request, without supplying playback
				// evidence. SetLinger(0) forces a TCP reset instead of EOF.
				done <- conn.(*net.TCPConn).SetLinger(0)
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			port := listener.Addr().(*net.TCPAddr).Port
			if standalone {
				client := New("test", filepath.Join(t.TempDir(), "credentials"), "127.0.0.1", WithPort(port), WithAuthMode("open"), WithProperties(map[string]string{"features": "0x1"}))
				info, err := client.PlaybackInfo(ctx)
				if !errors.Is(err, syscall.ECONNRESET) || info != nil {
					t.Errorf("standalone reset must remain an error, not idle: info=%v err=%v", info, err)
				}
			} else {
				conn, err := dial(ctx, "127.0.0.1", port)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.close()
				if err := waitForPlaybackToEnd(ctx, newRTSPSession(conn)); err != nil {
					t.Errorf("owning connection reset should end playback: %v", err)
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

type playbackReadErrorConn struct {
	net.Conn
	err error
}

func (c playbackReadErrorConn) Write(b []byte) (int, error) { return len(b), nil }
func (c playbackReadErrorConn) Read([]byte) (int, error)    { return 0, c.err }

func TestPlaybackPollPreservesTransportFailures(t *testing.T) {
	for _, failure := range []error{context.DeadlineExceeded, context.Canceled, io.ErrUnexpectedEOF, syscall.ECONNREFUSED} {
		t.Run(failure.Error(), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			transport := playbackReadErrorConn{Conn: client, err: &net.OpError{Op: "read", Net: "tcp", Err: failure}}
			err := waitForPlaybackToEnd(t.Context(), newRTSPSession(&connection{tcp: transport}))
			if !errors.Is(err, failure) {
				t.Fatalf("got %v, want %v", err, failure)
			}
		})
	}
}

func TestPlaybackRetriesEndpointDigestChallenge(t *testing.T) {
	for _, tc := range []struct {
		name, password string
		oldNonce       bool
		finalStatus    int
	}{
		{"first challenge on play", "1234", false, 200},
		{"nonce changed since status", "1234", true, 200},
		{"saved code rejected", "1234", true, 401},
		{"no saved code", "", false, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			conn := &connection{tcp: clientSide, legacyPassword: tc.password}
			if tc.oldNonce {
				conn.digest = &digestAuth{username: "AirPlay", realm: "AirPlay", nonce: "old", password: tc.password}
			}
			done := make(chan error, 1)
			go func() {
				serverSide.SetDeadline(time.Now().Add(3 * time.Second))
				reader := bufio.NewReader(serverSide)
				var originalBody []byte
				count := 2
				if tc.password == "" {
					count = 1
				}
				for i := 0; i < count; i++ {
					req, err := http.ReadRequest(reader)
					if err != nil {
						done <- err
						return
					}
					body, err := io.ReadAll(req.Body)
					req.Body.Close()
					if err != nil {
						done <- err
						return
					}
					if req.Method != "POST" || req.URL.Path != "/play" || req.Header.Get("X-Apple-Session-ID") != "session" {
						done <- fmt.Errorf("unexpected playback request")
						return
					}
					if i == 0 {
						originalBody = body
					} else {
						if !bytes.Equal(body, originalBody) {
							done <- errors.New("retry changed playback body")
							return
						}
						// Calculate the expected wire response independently of digestAuth.
						ha1 := fmt.Sprintf("%x", md5.Sum([]byte("AirPlay:AirPlay:1234")))
						ha2 := fmt.Sprintf("%x", md5.Sum([]byte("POST:/play")))
						want := fmt.Sprintf("%x", md5.Sum([]byte(ha1+":fresh:"+ha2)))
						if !strings.Contains(req.Header.Get("Authorization"), `response="`+want+`"`) || !strings.Contains(req.Header.Get("Authorization"), `nonce="fresh"`) {
							done <- errors.New("retry did not authenticate with new nonce and saved code")
							return
						}
					}
					status := 401
					if i == 1 {
						status = tc.finalStatus
					}
					fmt.Fprintf(serverSide, "HTTP/1.1 %d Test\r\nWWW-Authenticate: Digest realm=\"AirPlay\", nonce=\"fresh\"\r\nContent-Length: 0\r\n\r\n", status)
				}
				done <- nil
			}()
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			err := postPlayV1WithRetry(ctx, conn, map[string]any{"Content-Location": "http://example.test/video", "X-Apple-Session-ID": "session"}, "session", "0x123456789abc")
			if tc.finalStatus == 200 {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var auth *InvalidAuth
				if !errors.As(err, &auth) {
					t.Fatalf("want auth rejection after bounded retry, got %v", err)
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBusyReceiverDoesNotStartCodePairing(t *testing.T) {
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
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(conn)
		for i := 0; i < 3; i++ {
			req, err := http.ReadRequest(reader)
			if err != nil {
				done <- err
				return
			}
			io.Copy(io.Discard, req.Body)
			req.Body.Close()
			body := []byte{}
			if i == 0 {
				body = verifyResponse
			}
			status := 200
			if i == 2 {
				status = 453
			}
			fmt.Fprintf(conn, "HTTP/1.1 %d Test\r\nContent-Length: %d\r\n\r\n", status, len(body))
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
	if err := os.WriteFile(path+".password", []byte("1234"), 0600); err != nil {
		t.Fatal(err)
	}
	client := New("test", path, "127.0.0.1", WithPort(listener.Addr().(*net.TCPAddr).Port), WithProperties(map[string]string{"features": "0x1"}))
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	required, err := client.StartPasswordPairing(ctx)
	var status *StatusError
	if required || !errors.As(err, &status) || status.Code != 453 {
		t.Fatalf("required=%t err=%v", required, err)
	}
	if err := client.FinishPasswordPairing(ctx, "9999"); err == nil {
		t.Fatal("accepted code without a challenge")
	}
	password, err := os.ReadFile(path + ".password")
	if err != nil || string(password) != "1234" {
		t.Fatal("overwrote saved password after refusal")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPlaybackPollRejectionIsNotSuccessfulCompletion(t *testing.T) {
	for _, code := range []int{401, 403, 470, 453, 500} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			done := make(chan error, 1)
			go func() {
				serverSide.SetDeadline(time.Now().Add(2 * time.Second))
				req, err := http.ReadRequest(bufio.NewReader(serverSide))
				if err != nil {
					done <- err
					return
				}
				req.Body.Close()
				_, err = fmt.Fprintf(serverSide, "HTTP/1.1 %d Test\r\nContent-Length: 0\r\n\r\n", code)
				done <- err
			}()
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			err := waitForPlaybackToEnd(ctx, newRTSPSession(&connection{tcp: clientSide}))
			if code == 401 || code == 403 || code == 470 {
				var auth *InvalidAuth
				if !errors.As(err, &auth) {
					t.Fatalf("want authentication failure, got %v", err)
				}
			} else {
				var status *StatusError
				if !errors.As(err, &status) || status.Code != code {
					t.Fatalf("want status %d, got %v", code, err)
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPlayURLPrimesLegacyDigestOnOwningConnection(t *testing.T) {
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
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(conn)
		for i, path := range []string{"/pair-verify", "/pair-verify", "/playback-info", "/play"} {
			req, err := http.ReadRequest(reader)
			if err != nil {
				done <- err
				return
			}
			io.Copy(io.Discard, req.Body)
			req.Body.Close()
			if req.URL.Path != path {
				done <- fmt.Errorf("request %d: got %s, want %s", i, req.URL.Path, path)
				return
			}
			if i == 3 {
				ha1 := fmt.Sprintf("%x", md5.Sum([]byte("AirPlay:AirPlay:1234")))
				ha2 := fmt.Sprintf("%x", md5.Sum([]byte("POST:/play")))
				want := fmt.Sprintf("%x", md5.Sum([]byte(ha1+":owning-connection:"+ha2)))
				if !strings.Contains(req.Header.Get("Authorization"), `response="`+want+`"`) {
					done <- errors.New("first play request did not use the status challenge on its owning connection")
					return
				}
			}
			status, headers, body := 200, "", []byte{}
			if i == 0 {
				body = verifyResponse
			}
			if i == 2 {
				status = 401
				headers = "WWW-Authenticate: Digest realm=\"AirPlay\", nonce=\"owning-connection\"\r\n"
			}
			fmt.Fprintf(conn, "HTTP/1.1 %d Test\r\n%sContent-Length: %d\r\n\r\n", status, headers, len(body))
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
	if err := os.WriteFile(path+".password", []byte("1234"), 0600); err != nil {
		t.Fatal(err)
	}
	client := New("test", path, "127.0.0.1", WithPort(listener.Addr().(*net.TCPAddr).Port), WithProperties(map[string]string{"features": "0x1"}))
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := client.PlayURL(ctx, "http://example.test/video.mp4", 0); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !isSessionID(loadLegacySessionID(path + ".session")) {
		t.Fatal("accepted playback session was not persisted")
	}
}
