package main
//dfhgsfdh
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
	matches, err := proc.FindMatching(*target)
	//fmt.Println("matchessss ========> ", matches)
	
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
	registryHits := persist.FindRegistryPersistence(*target)
	startupHits := persist.FindStartupPersistence(*target)
	exePaths := gatherExePaths(matches, registryHits)
	scanPaths := addStartupPaths(exePaths, startupHits)
	
	pidSet := make(map[uint32]bool, len(killTargets))
	for _, p := range killTargets {
		pidSet[p.PID] = true
	}
	liveEndpoints, err := netinfo.LiveEndpoints(pidSet)
	if err != nil {
		fmt.Printf("[warn] read TCP connections: %v\n", err)
	}
	summary.AttackerIPs = collectAttackerIPs(liveEndpoints, scanPaths)
	summary.ProcessesKilled = killProcesses(killTargets, *dryRun)
	if summary.ProcessesKilled > 0 && !*dryRun {
		time.Sleep(config.KillSettleDelay)
	}
	summary.RegistryRemoved = removeRegistryHits(registryHits, *dryRun)
	summary.StartupRemoved = removeStartupHits(startupHits, *dryRun)
	summary.FilesDeleted = deleteFiles(exePaths, *dryRun)
	if !verify.Run(summary) {
		os.Exit(1)
	}
}

func checkElevation() {
	if windows.GetCurrentProcessToken().IsElevated() {
		return
	}
	fmt.Println("[warn] not running elevated — HKLM registry and some process operations may fail. Re-run as Administrator for full coverage.")

}

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
			
			fmt.Printf("  [fail] kill %s (PID %d): %v\n", p.Name, p.PID, err)
			continue
		}
		fmt.Printf("  [ok] killed %s (PID %d)\n", p.Name, p.PID)
		killed++
	}
	return killed
}
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
