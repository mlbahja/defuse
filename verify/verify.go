
package verify

import (
	"fmt"

	"defuse/persist"
	"defuse/proc"
)


type Summary struct {

	Target          string
	DryRun          bool
	AttackerIPs     []string
	ProcessesKilled int
	RegistryRemoved int
	StartupRemoved  int
	FilesDeleted    int

}

func Run(s Summary) bool {
	printSummary(s)
	if s.DryRun {
		fmt.Println("\n[dry-run] no changes were made, so nothing to verify.")
		return true
	}
	fmt.Println("\nVerifying cleanup...")
	remainingProcs, err := proc.FindMatching(s.Target)
	if err != nil {
		fmt.Printf("  [warn] could not re-check processes: %v\n", err)
	}
	remainingRegistry := persist.FindRegistryPersistence(s.Target)
	clean := len(remainingProcs) == 0 && len(remainingRegistry) == 0
	if len(remainingProcs) == 0 {
		fmt.Println("  [OK]   no matching process remains")
	} else {
		fmt.Printf("  [FAIL] %d matching process(es) still running\n", len(remainingProcs))
	}
	if len(remainingRegistry) == 0 {
		fmt.Println("  [OK]   no matching registry persistence remains")
	} else {
		fmt.Printf("  [FAIL] %d matching registry value(s) still present\n", len(remainingRegistry))
	}
	if clean {
		fmt.Println("\nResult: CLEAN")
	} else {
		fmt.Println("\nResult: INCOMPLETE — see failures above")
	}
	return clean
}

func printSummary(s Summary) {
	action := "removed"
	if s.DryRun {
		action = "would remove"
	}

	fmt.Println("\n=== Summary ===")
	fmt.Printf("Target:                 %s\n", s.Target)

	if len(s.AttackerIPs) == 0 {
		fmt.Println("Attacker IP(s):         none found")
	} else {
		fmt.Printf("Attacker IP(s):         %v\n", s.AttackerIPs)
	}
	fmt.Printf("Processes %s: %d\n", action, s.ProcessesKilled)
	fmt.Printf("Registry values %s: %d\n", action, s.RegistryRemoved)
	fmt.Printf("Startup files %s: %d\n", action, s.StartupRemoved)
	fmt.Printf("Files %s: %d\n", action, s.FilesDeleted)
}
