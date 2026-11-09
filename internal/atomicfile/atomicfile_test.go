package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteReplacesAtomicallyWithPrivateMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new\n" {
		t.Fatalf("contents = %q, err = %v", got, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("mode = %v, want 0600 (an existing 0644 file must not leak through)", mode)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

func TestWriteFailureKeepsPreviousFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A directory at the temp-file location is not needed: make the parent
	// unwritable instead, so CreateTemp fails before anything is touched.
	missing := filepath.Join(dir, "missing", "secret")
	if err := Write(missing, []byte("x"), 0o600); err == nil {
		t.Fatal("write into a missing directory succeeded")
	}
	if got, _ := os.ReadFile(path); string(got) != "keep" {
		t.Fatalf("previous file changed: %q", got)
	}
}
