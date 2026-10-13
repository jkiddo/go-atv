package simulator

import (
	"fmt"
	"strings"
	"testing"
)

func TestDigestRejectsAmbiguousOrDifferentRequests(t *testing.T) {
	a, err := newReceiverDigestAuth("secret")
	if err != nil {
		t.Fatal(err)
	}
	uri := "/session?name=a,b"
	response := digestResponse("iTunes", a.realm, "secret", a.nonce, "SETUP", uri)
	header := fmt.Sprintf(`Digest username="iTunes", realm="%s", nonce="%s", uri="%s", response="%s"`, a.realm, a.nonce, uri, response)
	if !a.authorizeAs("SETUP", uri, header, "iTunes") {
		t.Fatal("valid quoted comma rejected")
	}
	for _, tc := range []struct{ name, method, uri, header string }{
		{"method", "RECORD", uri, header}, {"target", "SETUP", "/other", header},
		{"duplicate", "SETUP", uri, header + `, response="` + response + `"`},
		{"qop", "SETUP", uri, header + `, qop="auth"`},
		{"injection", "SETUP", uri, header + "\r\nX: value"},
		{"nonce", "SETUP", uri, strings.Replace(header, a.nonce, "wrong", 1)},
		{"password", "SETUP", uri, strings.Replace(header, response, strings.Repeat("0", 32), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if a.authorizeAs(tc.method, tc.uri, tc.header, "iTunes") {
				t.Fatal("invalid digest accepted")
			}
		})
	}
	if a.authorizeAs("SETUP", uri, header, "AirPlay") {
		t.Fatal("different username accepted")
	}
}
