
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


type RegistryHit struct {
	Hive     registry.Key
	HiveName string
	Path     string // key path, e.g. `Software\Microsoft\Windows\CurrentVersion\Run`
	Name     string // the value's name
	Value    string // the value's data, usually a command line
}


func FindRegistryPersistence(target string) []RegistryHit {
	want := proc.Normalize(target)
	var hits []RegistryHit

	for _, loc := range config.RegistryLocations() {
		key, err := registry.OpenKey(loc.Hive, loc.Path, registry.READ)
		if err != nil {
			
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

func matchesTarget(name, value, want string) bool {
	if proc.Normalize(name) == want {
		return true
	}
	return proc.Normalize(filepath.Base(extractExePath(value))) == want
}


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


func (h RegistryHit) ExePath() string {
	return extractExePath(h.Value)
}

func RemoveRegistryPersistence(hit RegistryHit) error {
	key, err := registry.OpenKey(hit.Hive, hit.Path, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open %s\\%s for write: %w", hit.HiveName, hit.Path, err)
	}
	defer key.Close()

	return key.DeleteValue(hit.Name)
}


type StartupHit struct {
	Path string
}


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

func RemoveStartupPersistence(hit StartupHit) error {
	return os.Remove(hit.Path)
}
