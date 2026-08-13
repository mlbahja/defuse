//go:build windows

// Package persist finds and removes the two persistence mechanisms Defuse
// handles: registry Run/RunOnce values, and files dropped in the Startup
// folders. Both get Windows to run something at logon without the user
// asking for it.
package persist

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"defuse/config"
	"defuse/proc"
)

// RegistryHit is one Run/RunOnce value that appears to point at the target.
type RegistryHit struct {
	Hive     registry.Key
	HiveName string
	Path     string // key path, e.g. `Software\Microsoft\Windows\CurrentVersion\Run`
	Name     string // the value's name
	Value    string // the value's data, usually a command line
}

// FindRegistryPersistence scans every Run/RunOnce location in both hives
// and returns the values whose name or referenced executable matches the
// target. It only reads — nothing is deleted here.
func FindRegistryPersistence(target string) []RegistryHit {
	want := proc.Normalize(target)
	var hits []RegistryHit

	for _, loc := range config.RegistryLocations() {
		key, err := registry.OpenKey(loc.Hive, loc.Path, registry.READ)
		if err != nil {
			// Most often HKLM without admin rights, or the key doesn't
			// exist on this machine. Either way, keep going.
			fmt.Printf("  [warn] open %s\\%s: %v\n", loc.HiveName, loc.Path, err)
			continue
		}

		names, err := key.ReadValueNames(0)
		if err != nil {
			key.Close()
			continue
		}

		for _, name := range names {
			value, _, err := key.GetStringValue(name)
			if err != nil {
				continue
			}

			if matchesTarget(name, value, want) {
				hits = append(hits, RegistryHit{
					Hive: loc.Hive, HiveName: loc.HiveName, Path: loc.Path,
					Name: name, Value: value,
				})
			}
		}
		key.Close()
	}

	return hits
}

// matchesTarget checks a Run-key value's name and referenced executable
// against the normalized target name, so "MalTrack" as a value name and
// `"C:\...\maltrack.exe"` as its data both count as a match.
func matchesTarget(name, value, want string) bool {
	if proc.Normalize(name) == want {
		return true
	}
	return proc.Normalize(filepath.Base(extractExePath(value))) == want
}

// extractExePath pulls the executable path out of a Run-key command line,
// which may be a bare path, a quoted path, or a path followed by
// arguments (`"C:\x\y.exe" -flag`). It looks for the first ".exe" and cuts
// there, which handles all three shapes without a full command-line parser.
func extractExePath(value string) string {
	v := strings.TrimSpace(value)
	v = strings.TrimPrefix(v, `\??\`)
	v = strings.Trim(v, `"`)

	lower := strings.ToLower(v)
	if i := strings.Index(lower, ".exe"); i != -1 {
		return v[:i+4]
	}
	return v
}

// ExePath returns the executable path referenced by this registry value,
// so callers can static-scan or delete the file it points at.
func (h RegistryHit) ExePath() string {
	return extractExePath(h.Value)
}

// RemoveRegistryPersistence deletes one Run/RunOnce value. Only the value
// is deleted, never the key itself — Run and RunOnce are part of Windows
// and other, legitimate software uses them too.
func RemoveRegistryPersistence(hit RegistryHit) error {
	key, err := registry.OpenKey(hit.Hive, hit.Path, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open %s\\%s for write: %w", hit.HiveName, hit.Path, err)
	}
	defer key.Close()

	return key.DeleteValue(hit.Name)
}

// StartupHit is one file in a Startup folder that appears to be the target.
type StartupHit struct {
	Path string
}

// FindStartupPersistence lists both Startup folders and returns the files
// whose normalized name matches the target. Only reads — nothing is
// deleted here.
func FindStartupPersistence(target string) []StartupHit {
	want := proc.Normalize(target)
	var hits []StartupHit

	for _, folder := range config.StartupFolders() {
		entries, err := os.ReadDir(folder)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if proc.Normalize(entry.Name()) == want {
				hits = append(hits, StartupHit{Path: filepath.Join(folder, entry.Name())})
			}
		}
	}

	return hits
}

// RemoveStartupPersistence deletes one file from a Startup folder.
func RemoveStartupPersistence(hit StartupHit) error {
	return os.Remove(hit.Path)
}
