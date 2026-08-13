// Package cleaner deletes the malware's files from disk: the executable
// itself, and its parent directory if the malware was the only thing
// living there. It refuses to touch anything under the Windows directory.
package cleaner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"defuse/config"
)

// IsProtected reports whether path sits under the Windows directory. Run
// keys and Startup entries can point at things like `cmd.exe`, so this
// check exists specifically to stop the deleter from ever removing part of
// the OS itself, no matter what a registry value claims.
func IsProtected(path string) bool {
	windowsDir := strings.ToLower(config.WindowsDir())
	return strings.HasPrefix(strings.ToLower(path), windowsDir)
}

// DeleteFile removes one file, retrying briefly to ride out the short
// file lock Windows can hold right after the owning process is killed.
// It refuses to delete anything under the Windows directory.
func DeleteFile(path string) error {
	if IsProtected(path) {
		return fmt.Errorf("refusing to delete protected path %s", path)
	}

	if _, err := os.Stat(path); err != nil {
		return err
	}

	var lastErr error
	for attempt := 0; attempt < config.FileDeleteAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(config.FileDeleteRetryDelay)
		}
		if lastErr = os.Remove(path); lastErr == nil {
			return nil
		}
	}
	return lastErr
}

// DeleteEmptyMalwareDir removes exePath's parent directory, but only if
// that directory is now empty. It's meant to be called after the malware's
// executable has already been deleted, so an empty result means the
// malware was the only thing living there — a folder it created for
// itself in AppData or Temp, not a shared directory. The bool return says
// whether the directory was actually removed, so callers can tell "left it
// alone, other files are there" apart from "removed it".
func DeleteEmptyMalwareDir(exePath string) (bool, error) {
	dir := filepath.Dir(exePath)

	if IsProtected(dir) {
		return false, fmt.Errorf("refusing to delete protected path %s", dir)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	if len(entries) > 0 {
		return false, nil // other files live here, leave it alone
	}

	if err := os.Remove(dir); err != nil {
		return false, err
	}
	return true, nil
}
