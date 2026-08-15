package proc

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Process struct {
	PID     uint32
	PPID    uint32
	Name    string
	ExePath string
}

func Normalize(name string) string {
	//	fmt.Println("name ===========> ", name)

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

func List() ([]Process, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)

	//fmt.Println("snapshot ======> ", snapshot)
	if err != nil {
		return nil, fmt.Errorf("create process snapshot: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	//fmt.Println("entry.Size =====> ", entry.Size, "entry ==> ", entry)

	var procs []Process
	err = windows.Process32First(snapshot, &entry)
	for err == nil {

		procs = append(procs, Process{
			PID:  entry.ProcessID,
			PPID: entry.ParentProcessID,
			Name: windows.UTF16ToString(entry.ExeFile[:]),
		})

		err = windows.Process32Next(snapshot, &entry)

	}

	return procs, nil
}

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

func FindMatching(t string) ([]Process, error) {
	allProcess, err := List()
	if err != nil {
		return nil, err
	}
	want := Normalize(t)
	var result []Process
	for _, p := range allProcess {
		if p.Name != want {
			//skip^
			continue
		}
		if path, err := ExePath(p.PID); err == nil {
			p.ExePath = path
		}
		result = append(result, p)
	}
	return result, nil

}

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

func Kill(pid uint32) error {
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	
	defer windows.CloseHandle(handle)

	return windows.TerminateProcess(handle, 1)
}
