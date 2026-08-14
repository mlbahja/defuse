package cleaner
import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"defuse/config"
)

func IsProtected(path string) bool {
	windowsDir := strings.ToLower(strings.TrimRight(config.WindowsDir(), `\`)) + `\`
	return strings.HasPrefix(strings.ToLower(path), windowsDir)
}

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
		return false, nil 
	}


	os.Chmod(dir, 0777)

	var lastErr error
	for attempt := 0; attempt < config.FileDeleteAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(config.FileDeleteRetryDelay)
		}
		if lastErr = os.Remove(dir); lastErr == nil {
			return true, nil
		}
	}
	return false, lastErr
}
