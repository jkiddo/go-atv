package hap

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLegacyCredentialsRoundTrip(t *testing.T) {
	original := Credentials{
		ClientID: []byte{0x75, 0xfb, 0xee, 0xc7, 0x73, 0xcf, 0xc5, 0x63},
		LTSK:     make([]byte, 32),
	}
	encoded := original.String()
	if encoded != "75fbeec773cfc563:0000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("String() = %q", encoded)
	}
	parsed, err := ParseCredentials(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.IsLegacy() || parsed.IsHAP() {
		t.Fatalf("parsed credentials type = %#v", parsed)
	}
	if parsed.String() != encoded {
		t.Fatalf("round trip = %q, want %q", parsed.String(), encoded)
	}
}

func TestSaveCredentialsIsAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "credentials")
	creds := Credentials{LTPK: bytes.Repeat([]byte{1}, 32), LTSK: bytes.Repeat([]byte{2}, 32), ATVID: []byte("atv"), ClientID: []byte("client")}
	if err := SaveCredentials(path, creds); err != nil {
		t.Fatal(err)
	}
	// Overwriting must replace the contents and leave no temporary file.
	creds.ATVID = []byte("other")
	if err := SaveCredentials(path, creds); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCredentials(path)
	if err != nil || string(loaded.ATVID) != "other" {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("directory entries = %v err=%v", entries, err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v err=%v", info.Mode(), err)
		}
	}
}
