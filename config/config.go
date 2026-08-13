// Package config holds every constant Defuse needs: where persistence
// lives in the registry and on disk, and how long to wait between steps.
// Nothing in here does any work — it's just the addresses and timings the
// rest of the program reads.
package config

import (
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/registry"
)

// RegistryLocation is one Run/RunOnce value list under one hive.
type RegistryLocation struct {
	Hive     registry.Key // registry.CURRENT_USER or registry.LOCAL_MACHINE
	HiveName string       // "HKCU" or "HKLM", for logging
	Path     string       // key path below the hive root
}

// RegistryLocations lists every Run/RunOnce key Windows executes at logon,
// under both the per-user hive (HKCU) and the machine-wide hive (HKLM).
// Malware favors HKCU because it needs no admin rights; HKLM is checked too
// in case it ran elevated.
func RegistryLocations() []RegistryLocation {
	const runPath = `Software\Microsoft\Windows\CurrentVersion\Run`
	const runOncePath = `Software\Microsoft\Windows\CurrentVersion\RunOnce`

	return []RegistryLocation{
		{registry.CURRENT_USER, "HKCU", runPath},
		{registry.CURRENT_USER, "HKCU", runOncePath},
		{registry.LOCAL_MACHINE, "HKLM", runPath},
		{registry.LOCAL_MACHINE, "HKLM", runOncePath},
	}
}

// StartupFolders lists the per-user and machine-wide Startup folders.
// Windows silently runs everything dropped in either one at logon, which
// makes both a favorite persistence spot for malware.
func StartupFolders() []string {
	return []string{
		filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
		filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\Startup`),
	}
}

// WindowsDir returns the Windows install directory so cleanup code has one
// place to check before it ever deletes a file or folder.
func WindowsDir() string {
	if dir := os.Getenv("SystemRoot"); dir != "" {
		return dir
	}
	return `C:\Windows`
}

// FileDeleteAttempts and FileDeleteRetryDelay govern how long we retry
// deleting a file that Windows still has locked briefly after the owning
// process is killed.
const FileDeleteAttempts = 5

const FileDeleteRetryDelay = 300 * time.Millisecond

// KillSettleDelay is how long we pause after killing the process tree
// before touching the registry, giving Windows a moment to release any
// handles the process held.
const KillSettleDelay = 250 * time.Millisecond
