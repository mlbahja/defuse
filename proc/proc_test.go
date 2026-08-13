//go:build windows

package proc

import "testing"

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"maltrack.exe":     "maltrack",
		"Mal-Track.exe":    "maltrack",
		"MALTRACK":         "maltrack",
		"Mal-Track":        "maltrack",
		"mal_track.EXE":    "maltrack",
		"  maltrack.exe  ": "maltrack",
		"notepad.exe":      "notepad",
	}

	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestKillOrder builds a synthetic process forest — one three-level tree
// and one unrelated single process — and checks that every child appears
// before its parent in the returned order, and that the unrelated process
// isn't pulled in at all. This is the property the whole "kill children
// before parents" requirement depends on, and it's far easier to pin down
// with fake PIDs than by spawning real ones.
func TestKillOrder(t *testing.T) {
	// Tree: 1 (root) -> 2 -> 3 (grandchild), plus an unrelated root 4 and
	// an unrelated process 5 that isn't a root or a descendant of one.
	all := []Process{
		{PID: 1, PPID: 0, Name: "maltrack.exe"},
		{PID: 2, PPID: 1, Name: "watchdog.exe"},
		{PID: 3, PPID: 2, Name: "helper.exe"},
		{PID: 4, PPID: 0, Name: "unrelated.exe"},
		{PID: 5, PPID: 4, Name: "unrelated-child.exe"},
	}
	roots := []Process{all[0]} // only PID 1 matched the target name

	order := KillOrder(roots, all)

	pos := make(map[uint32]int, len(order))
	for i, p := range order {
		pos[p.PID] = i
	}

	if len(order) != 3 {
		t.Fatalf("KillOrder returned %d processes, want 3 (got %+v)", len(order), order)
	}
	if _, ok := pos[4]; ok {
		t.Errorf("KillOrder pulled in unrelated process 4, which was never a root or descendant")
	}
	if pos[3] >= pos[2] {
		t.Errorf("grandchild PID 3 (pos %d) must come before its parent PID 2 (pos %d)", pos[3], pos[2])
	}
	if pos[2] >= pos[1] {
		t.Errorf("child PID 2 (pos %d) must come before its parent PID 1 (pos %d)", pos[2], pos[1])
	}
}

// TestKillOrderMultipleRoots checks two independent matched roots each
// keep their own children ordered ahead of them, without cross-contaminating.
func TestKillOrderMultipleRoots(t *testing.T) {
	all := []Process{
		{PID: 10, PPID: 0, Name: "maltrack.exe"},
		{PID: 11, PPID: 10, Name: "child-of-10.exe"},
		{PID: 20, PPID: 0, Name: "maltrack.exe"},
		{PID: 21, PPID: 20, Name: "child-of-20.exe"},
	}
	roots := []Process{all[0], all[2]} // PID 10 and PID 20 both matched

	order := KillOrder(roots, all)
	pos := make(map[uint32]int, len(order))
	for i, p := range order {
		pos[p.PID] = i
	}

	if len(order) != 4 {
		t.Fatalf("KillOrder returned %d processes, want 4", len(order))
	}
	if pos[11] >= pos[10] {
		t.Errorf("PID 11 must come before its parent PID 10")
	}
	if pos[21] >= pos[20] {
		t.Errorf("PID 21 must come before its parent PID 20")
	}
}
