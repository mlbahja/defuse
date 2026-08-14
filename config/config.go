
package config

import (
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/registry"
)

type RegistryLocation struct {
	Hive     registry.Key 
	HiveName string       
	Path     string      
}


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


func StartupFolders() []string {
	return []string{
		filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
		filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\Startup`),
	}
}

func WindowsDir() string {
	if dir := os.Getenv("SystemRoot"); dir != "" {
		return dir
	}
	return `C:\Windows`
}


const FileDeleteAttempts = 5
const FileDeleteRetryDelay = 300 * time.Millisecond
const KillSettleDelay = 250 * time.Millisecond
