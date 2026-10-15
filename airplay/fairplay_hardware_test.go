package airplay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"syscall"
	"testing"
	"time"

	"github.com/jkiddo/go-atv/simulator"
)

func TestFairPlayParentRetirementIsVersionAndErrorScoped(t *testing.T) {
	for _, tc := range []struct {
		name, model, build, version string
		err                         error
		want                        bool
	}{
		{"observed EOF", "AppleTV3,2", "12H1006", "220.68", fmt.Errorf("feedback: %w", io.EOF), true},
		{"reset", "AppleTV3,2", "12H1006", "220.68", syscall.ECONNRESET, true},
		{"broken pipe", "AppleTV3,2", "12H1006", "220.68", syscall.EPIPE, true},
		{"other model", "AppleTV11,1", "12H1006", "220.68", io.EOF, false},
		{"other build", "AppleTV3,2", "12H9999", "220.68", io.EOF, false},
		{"unknown build", "AppleTV3,2", "", "220.68", io.EOF, false},
		{"other AirPlay", "AppleTV3,2", "12H1006", "221.0", io.EOF, false},
		{"timeout", "AppleTV3,2", "12H1006", "220.68", context.DeadlineExceeded, false},
		{"canceled", "AppleTV3,2", "12H1006", "220.68", context.Canceled, false},
		{"HTTP rejection", "AppleTV3,2", "12H1006", "220.68", &StatusError{Code: 401}, false},
		{"truncated response", "AppleTV3,2", "12H1006", "220.68", io.ErrUnexpectedEOF, false},
		{"other failure", "AppleTV3,2", "12H1006", "220.68", errors.New("invalid response"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := map[string]any{"model": tc.model, "osBuildVersion": tc.build, "srcvers": tc.version}
			if got := canRetireFairPlayParent(info, tc.err); got != tc.want {
				t.Fatalf("retire=%t, want %t", got, tc.want)
			}
		})
	}
}

// Exercise the receiver independently of the sender's Digest preparation.
// Both hardware video sockets demanded authentication after fp-setup2.
func TestFairPlayAppleTV32Build12H1006PerSocketDigest(t *testing.T) {
	const password = "synthetic receiver password"
	r, err := simulator.New(simulator.Config{FairPlay: true, FairPlayProfile: simulator.FairPlayAppleTV32_12H1006, Password: password})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	connect := func() *connection {
		t.Helper()
		conn, err := dial(ctx, "127.0.0.1", r.Port())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(conn.close)
		secret, err := verifyLegacyPD(ctx, conn, r.Credentials(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(secret)
		sap, err := setupFairPlay(ctx, conn, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := upgradeFairPlay(ctx, conn, sap, secret, nil); err != nil {
			t.Fatal(err)
		}
		return conn
	}
	first, second := connect(), connect()
	probe := func(conn *connection, password string) *digestAuth {
		t.Helper()
		reply, err := conn.get(ctx, "/playback-info", nil)
		if err != nil {
			t.Fatal(err)
		}
		if reply.Code != 401 {
			t.Fatalf("encrypted probe returned %d", reply.Code)
		}
		auth, err := parseDigestChallenge(reply.Headers["www-authenticate"], "AirPlay", password)
		if err != nil {
			t.Fatal(err)
		}
		return auth
	}
	first.digest = probe(first, password)
	secondAuth := probe(second, password)
	// A command socket's valid challenge must not authorize the reverse socket.
	second.digest = first.digest
	reply, err := second.post(ctx, "/reverse", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != 401 {
		t.Fatalf("cross-socket Digest accepted: %d", reply.Code)
	}
	second.digest = secondAuth
	reply, err = second.post(ctx, "/reverse", "", []header{{"Connection", "Upgrade"}, {"Upgrade", "PTTH/1.0"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != 101 {
		t.Fatalf("authenticated reverse returned %d", reply.Code)
	}
	// The command socket must check every protected endpoint, not just a probe.
	first.digest = nil
	for _, uri := range []string{"/play", "/stop", "/rate?value=1", "/scrub?position=0", "/setProperty?actionAtItemEnd"} {
		reply, err := first.post(ctx, uri, "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if reply.Code != 401 {
			t.Fatalf("unauthenticated %s returned %d", uri, reply.Code)
		}
	}
	first.digest = probe(first, "wrong password")
	reply, err = first.get(ctx, "/playback-info", nil)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != 401 {
		t.Fatalf("wrong password returned %d", reply.Code)
	}
}
