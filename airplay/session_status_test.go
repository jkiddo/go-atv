package airplay

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jkiddo/go-atv/hap"
)

func TestLegacyPlaybackInfoSessionSurvivesDigestChallenges(t *testing.T) {
	for _, sessionID := range []string{"", "24b3fd94-1b6d-42b1-89a3-47108bfbac89"} {
		t.Run("session="+sessionID, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			verifyResponse := decodeHex(t, legacyVerifyResponse)
			playbackBody, err := packPlist(map[string]any{"duration": 30.0, "position": 5.0})
			if err != nil {
				t.Fatal(err)
			}
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
				for i := 0; i < 5; i++ {
					req, err := http.ReadRequest(reader)
					if err != nil {
						done <- err
						return
					}
					io.Copy(io.Discard, req.Body)
					req.Body.Close()
					code, body, headers := 200, []byte{}, ""
					if i < 2 {
						if req.URL.Path != "/pair-verify" {
							done <- fmt.Errorf("unexpected pairing path: %s", req.URL.Path)
							return
						}
						if i == 0 {
							body = verifyResponse
						}
					} else {
						if req.Method != "GET" || req.URL.Path != "/playback-info" || req.Header.Get("X-Apple-Session-ID") != sessionID {
							done <- fmt.Errorf("status request %d lost persisted session header", i-2)
							return
						}
						if i == 2 && req.Header.Get("Authorization") != "" {
							done <- fmt.Errorf("initial challenge request unexpectedly authenticated")
							return
						}
						if i == 2 || i == 3 {
							code = 401
							nonce := "initial"
							if i == 3 {
								nonce = "renewed"
							}
							headers = fmt.Sprintf("WWW-Authenticate: Digest realm=\"AirPlay\", nonce=\"%s\"\r\n", nonce)
						} else {
							if !strings.Contains(req.Header.Get("Authorization"), `nonce="renewed"`) {
								done <- fmt.Errorf("retry did not use renewed challenge")
								return
							}
							body = playbackBody
						}
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
			if err := os.WriteFile(path+".password", []byte("1234\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if sessionID != "" {
				if err := saveLegacySessionID(path+".session", sessionID); err != nil {
					t.Fatal(err)
				}
			}
			client := New("test", path, "127.0.0.1", WithPort(listener.Addr().(*net.TCPAddr).Port), WithProperties(map[string]string{"features": "0x1"}))
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			info, err := client.PlaybackInfo(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if info["position"] != 5.0 {
				t.Fatalf("unexpected playback info: %v", info)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
