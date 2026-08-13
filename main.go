//go:build windows

// Command defuse finds a Windows malware process by name, kills its whole
// process tree, strips its persistence, deletes its files, and verifies
// none of it survived.
//
// Order matters: the process tree is killed before persistence is removed,
// so the malware never gets a chance to rewrite its own Run key in the gap
// between the two steps. And persistence/file cleanup always runs, even if
// no matching process is currently running — an infection can survive with
// its process not running, waiting for the next logon.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"defuse/cleaner"
	"defuse/config"
	"defuse/netinfo"
	"defuse/persist"
	"defuse/proc"
	"defuse/verify"
)

func main() {
	target := flag.String("target", "", "process name to hunt and remove (required), e.g. maltrack")
	dryRun := flag.Bool("dry-run", false, "report what would be done without changing anything")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "defuse: -target is required")
		flag.Usage()
		os.Exit(2)
	}

	checkElevation()

	summary := verify.Summary{Target: *target, DryRun: *dryRun}

	// Steps 1-2: find matching processes and their full child trees.
	matches, err := proc.FindMatching(*target)
	if err != nil {
		fmt.Printf("[warn] list processes: %v\n", err)
	}

	allProcs, err := proc.List()
	if err != nil {
		fmt.Printf("[warn] snapshot processes: %v\n", err)
	}
	killTargets := proc.KillOrder(matches, allProcs)

	if len(matches) == 0 {
		fmt.Printf("No running process matches %q. Continuing with persistence and file cleanup anyway.\n", *target)
	} else {
		fmt.Printf("Found %d matching process(es), %d including children.\n", len(matches), len(killTargets))
	}

	// Find persistence now, before anything is killed or deleted, so we
	// know every executable path worth scanning even if the process has
	// already exited.
	registryHits := persist.FindRegistryPersistence(*target)
	startupHits := persist.FindStartupPersistence(*target)

	// exePaths feeds step 8 (delete the executable + its parent dir). It
	// deliberately excludes Startup-folder hits: those are deleted in step
	// 7 by removeStartupHits, and including them here too would just be a
	// second, always-failing delete attempt on a file that's already gone.
	exePaths := gatherExePaths(matches, registryHits)

	// scanPaths feeds the read-only IP scan, so it can look at every copy
	// of the malware we found, including the Startup-folder one.
	scanPaths := addStartupPaths(exePaths, startupHits)

	// Steps 3-4: attacker IP, from live TCP connections plus a static scan
	// of the executable bytes for the case where nothing is connected.
	pidSet := make(map[uint32]bool, len(killTargets))
	for _, p := range killTargets {
		pidSet[p.PID] = true
	}
	liveEndpoints, err := netinfo.LiveEndpoints(pidSet)
	if err != nil {
		fmt.Printf("[warn] read TCP connections: %v\n", err)
	}
	summary.AttackerIPs = collectAttackerIPs(liveEndpoints, scanPaths)

	// Step 5: kill the whole process tree, children before parents.
	summary.ProcessesKilled = killProcesses(killTargets, *dryRun)
	if summary.ProcessesKilled > 0 && !*dryRun {
		time.Sleep(config.KillSettleDelay)
	}

	// Steps 6-7: persistence and file cleanup.
	summary.RegistryRemoved = removeRegistryHits(registryHits, *dryRun)
	summary.StartupRemoved = removeStartupHits(startupHits, *dryRun)
	summary.FilesDeleted = deleteFiles(exePaths, *dryRun)

	// Steps 8-9: verify and report.
	if !verify.Run(summary) {
		os.Exit(1)
	}
}

// checkElevation warns when Defuse isn't running as Administrator, since
// HKLM registry changes and opening some other users' processes need it.
// It's a warning, not a hard stop: HKCU-only infections are still fully
// handled without elevation.
func checkElevation() {
	if windows.GetCurrentProcessToken().IsElevated() {
		return
	}
	fmt.Println("[warn] not running elevated — HKLM registry and some process operations may fail. Re-run as Administrator for full coverage.")
}

// gatherExePaths collects every executable path that step 8 (delete the
// executable + its parent dir) should act on: the matched processes' own
// paths, plus whatever the found registry persistence entries point at.
// Startup-folder hits are deliberately excluded — those files are already
// deleted by removeStartupHits as part of persistence cleanup. Deduplicated
// so the same file is never targeted twice.
func gatherExePaths(matches []proc.Process, registryHits []persist.RegistryHit) []string {
	var paths []string
	seen := make(map[string]bool)

	for _, m := range matches {
		paths = addPath(paths, seen, m.ExePath)
	}
	for _, h := range registryHits {
		paths = addPath(paths, seen, h.ExePath())
	}
	return paths
}

// addStartupPaths extends paths with every Startup-folder hit not already
// present, for callers (the IP scan) that want every copy of the malware
// we found, unlike gatherExePaths which deliberately excludes them.
func addStartupPaths(paths []string, startupHits []persist.StartupHit) []string {
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		seen[strings.ToLower(filepath.Clean(p))] = true
	}
	for _, h := range startupHits {
		paths = addPath(paths, seen, h.Path)
	}
	return paths
}

// addPath appends p to paths if it's non-empty and not already present
// (case-insensitively, after cleaning), recording it in seen either way.
func addPath(paths []string, seen map[string]bool, p string) []string {
	if p == "" {
		return paths
	}
	key := strings.ToLower(filepath.Clean(p))
	if seen[key] {
		return paths
	}
	seen[key] = true
	return append(paths, p)
}

// collectAttackerIPs merges live TCP remote addresses with IPv4 strings
// found by scanning the executables' own bytes, deduplicated.
func collectAttackerIPs(live []netinfo.Endpoint, exePaths []string) []string {
	seen := make(map[string]bool)
	var ips []string

	add := func(ip string) {
		if ip == "" || seen[ip] {
			return
		}
		seen[ip] = true
		ips = append(ips, ip)
	}

	for _, e := range live {
		add(e.IP)
	}

	for _, path := range exePaths {
		found, err := netinfo.ScanFileForIPv4(path)
		if err != nil {
			fmt.Printf("[warn] scan %s for IPs: %v\n", path, err)
			continue
		}
		for _, ip := range found {
			add(ip)
		}
	}

	return ips
}

// killProcesses terminates every process in targets, in the order given
// (children before parents), skipping the kill and only logging in
// dry-run mode.
func killProcesses(targets []proc.Process, dryRun bool) int {
	if len(targets) == 0 {
		return 0
	}

	fmt.Println("\nKilling process tree...")
	killed := 0
	for _, p := range targets {
		if dryRun {
			fmt.Printf("  [dry-run] would kill %s (PID %d)\n", p.Name, p.PID)
			killed++
			continue
		}
		if err := proc.Kill(p.PID); err != nil {
			// Already-exited child, or a process we can't touch. Log and
			// move on rather than treating it as fatal.
			fmt.Printf("  [fail] kill %s (PID %d): %v\n", p.Name, p.PID, err)
			continue
		}
		fmt.Printf("  [ok] killed %s (PID %d)\n", p.Name, p.PID)
		killed++
	}
	return killed
}

// removeRegistryHits deletes every found Run/RunOnce value, skipping the
// delete and only logging in dry-run mode.
func removeRegistryHits(hits []persist.RegistryHit, dryRun bool) int {
	if len(hits) == 0 {
		return 0
	}

	fmt.Println("\nRemoving registry persistence...")
	removed := 0
	for _, h := range hits {
		if dryRun {
			fmt.Printf("  [dry-run] would delete %s\\%s value %q\n", h.HiveName, h.Path, h.Name)
			removed++
			continue
		}
		if err := persist.RemoveRegistryPersistence(h); err != nil {
			fmt.Printf("  [fail] delete %s\\%s value %q: %v\n", h.HiveName, h.Path, h.Name, err)
			continue
		}
		fmt.Printf("  [ok] deleted %s\\%s value %q\n", h.HiveName, h.Path, h.Name)
		removed++
	}
	return removed
}

// removeStartupHits deletes every found Startup folder file, skipping the
// delete and only logging in dry-run mode.
func removeStartupHits(hits []persist.StartupHit, dryRun bool) int {
	if len(hits) == 0 {
		return 0
	}

	fmt.Println("\nRemoving Startup folder persistence...")
	removed := 0
	for _, h := range hits {
		if dryRun {
			fmt.Printf("  [dry-run] would delete %s\n", h.Path)
			removed++
			continue
		}
		if err := persist.RemoveStartupPersistence(h); err != nil {
			fmt.Printf("  [fail] delete %s: %v\n", h.Path, err)
			continue
		}
		fmt.Printf("  [ok] deleted %s\n", h.Path)
		removed++
	}
	return removed
}

// deleteFiles deletes every executable path found, then removes its
// parent directory if the malware was the only thing in it. Anything under
// the Windows directory is refused by cleaner and logged rather than
// deleted.
func deleteFiles(paths []string, dryRun bool) int {
	if len(paths) == 0 {
		return 0
	}

	fmt.Println("\nDeleting files...")
	deleted := 0
	for _, path := range paths {
		if dryRun {
			fmt.Printf("  [dry-run] would delete %s and its folder if left empty\n", path)
			deleted++
			continue
		}

		if err := cleaner.DeleteFile(path); err != nil {
			fmt.Printf("  [fail] delete %s: %v\n", path, err)
			continue
		}
		fmt.Printf("  [ok] deleted %s\n", path)
		deleted++

		removedDir, err := cleaner.DeleteEmptyMalwareDir(path)
		switch {
		case err != nil:
			fmt.Printf("  [warn] remove parent folder of %s: %v\n", path, err)
		case removedDir:
			fmt.Printf("  [ok] removed now-empty folder %s\n", filepath.Dir(path))
		}
	}
	return deleted
}
