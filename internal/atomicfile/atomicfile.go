// Package atomicfile writes small secret-bearing files (pairing credentials,
// saved codes, session identifiers) so that a crash or power cut leaves either
// the previous contents or the new ones on disk, never a torn file.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Write replaces path with data. It writes a private temporary file in the
// same directory, fsyncs it, renames it over path and then syncs the parent
// directory. The file is created with perm and never exceeds owner-only
// access while it is being written.
func Write(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temp := file.Name()
	fail := func(err error) error {
		file.Close()
		_ = os.Remove(temp)
		return err
	}
	if err := file.Chmod(perm); err != nil {
		return fail(err)
	}
	if _, err := file.Write(data); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	// Directory sync is best effort: it is unsupported on some platforms.
	if directory, err := os.Open(dir); err == nil {
		_ = directory.Sync()
		directory.Close()
	}
	return nil
}
