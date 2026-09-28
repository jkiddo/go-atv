package airplay

import (
	"github.com/jkiddo/go-atv/hap"
	"path/filepath"
	"testing"
)

func TestLegacySenderIdentitySurvivesCredentialReload(t *testing.T) {
	credentials := hap.Credentials{ClientID: []byte{0, 1, 2, 3, 4, 5, 6, 0xab}, LTSK: make([]byte, 32)}
	path := filepath.Join(t.TempDir(), "credentials")
	if err := hap.SaveCredentials(path, credentials); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		loaded, err := hap.LoadCredentials(path)
		if err != nil {
			t.Fatal(err)
		}
		session := newRTSPSession(nil, &loaded)
		if session.dacpID != "00010203040506AB" {
			t.Fatalf("sender identity changed after reload: %s", session.dacpID)
		}
	}
}
