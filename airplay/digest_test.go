package airplay

import "testing"

func TestDigestChallengeAndAuthorization(t *testing.T) {
	digest, err := parseDigestChallenge(
		`Digest realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093"`,
		"Mufasa",
		"Circle Of Life",
	)
	if err != nil {
		t.Fatal(err)
	}
	want := `Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html", response="670fd8c2df070c60b045671b8b24ff02"`
	if got := digest.authorization("GET", "/dir/index.html"); got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}
}

func TestDigestChallengeAllowsUnquotedFields(t *testing.T) {
	digest, err := parseDigestChallenge(`Digest realm=airplay, nonce="abc", stale=false`, "iTunes", "0299")
	if err != nil {
		t.Fatal(err)
	}
	if digest.realm != "airplay" || digest.nonce != "abc" || digest.password != "0299" {
		t.Fatalf("unexpected digest state: %+v", digest)
	}
}

func TestDigestChallengeRejectsMissingValues(t *testing.T) {
	if _, err := parseDigestChallenge(`Digest realm="airplay"`, "iTunes", "0299"); err == nil {
		t.Fatal("expected missing nonce to fail")
	}
}
