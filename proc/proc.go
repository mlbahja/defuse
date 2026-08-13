//go:build windows

// Package proc finds, describes, and kills Windows processes. It is the
// only package that talks to the process APIs, so every other package asks
// it for process info instead of calling Windows directly.
package proc

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Process is one running process, as much as we could learn about it.
type Process struct {
	PID     uint32
	PPID    uint32
	Name    string // as reported by Windows, e.g. "maltrack.exe"
	ExePath string // full path, empty if we couldn't read it
}

// Normalize reduces a process or file name to a bare comparison key:
// lowercase, no ".exe" suffix, no punctuation. This is what lets
// "Mal-Track", "maltrack.exe" and "maltrack" all be recognized as the same
// target, since attackers rename freely but rarely change letters.
func Normalize(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".exe")

	var b strings.Builder
	for _, r := range n {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// List snapshots every running process on the system. CreateToolhelp32Snapshot
// plus Process32First/Next is the standard way to walk all processes without
// needing to open a handle to each one first — handles come later, only for
// the processes we actually care about.
func List() ([]Process, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("create process snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	var procs []Process
	for err = windows.Process32First(snapshot, &entry); err == nil; err = windows.Process32Next(snapshot, &entry) {
		procs = append(procs, Process{
			PID:  entry.ProcessID,
			PPID: entry.ParentProcessID,
			Name: windows.UTF16ToString(entry.ExeFile[:]),
		})
	}

	return procs, nil
}

// ExePath asks Windows for a process's full executable path via
// QueryFullProcessImageName. PROCESS_QUERY_LIMITED_INFORMATION is enough to
// call it even for processes we don't own, which matters since the target
// is someone else's malware, not our own child process.
func ExePath(pid uint32) (string, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return "", fmt.Errorf("query image path for pid %d: %w", pid, err)
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// FindMatching returns every running process whose normalized name matches
// the normalized target name, with each match's executable path filled in
// where we're able to read one.
func FindMatching(target string) ([]Process, error) {
	all, err := List()
	if err != nil {
		return nil, err
	}

	want := Normalize(target)
	var matches []Process
	for _, p := range all {
		if Normalize(p.Name) != want {
			continue
		}
		if path, err := ExePath(p.PID); err == nil {
			p.ExePath = path
		}
		matches = append(matches, p)
	}
	return matches, nil
}

// KillOrder walks the process tree rooted at each of roots against the full
// process list and returns every process in those trees — descendants
// before their parent, and each root last in its own subtree. Killing in
// this order guarantees a child is always dead before its parent, so a
// parent can't respawn a child we already terminated.
func KillOrder(roots []Process, all []Process) []Process {
	seen := make(map[uint32]bool)
	var order []Process

	var visit func(pid uint32)
	visit = func(pid uint32) {
		for _, p := range all {
			if p.PPID == pid && !seen[p.PID] {
				seen[p.PID] = true
				visit(p.PID)
				order = append(order, p)
			}
		}
	}

	for _, root := range roots {
		if seen[root.PID] {
			continue
		}
		seen[root.PID] = true
		visit(root.PID)
		order = append(order, root)
	}
	return order
}

// Kill terminates a single process by PID. A process that already exited
// (e.g. a child that died with its parent) simply returns an error here —
// callers log it and move on rather than treating it as fatal.
func Kill(pid uint32) error {
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	return windows.TerminateProcess(handle, 1)
}
