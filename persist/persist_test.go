//go:build windows

package persist

import "testing"

func TestExtractExePath(t *testing.T) {
	cases := map[string]string{
		`C:\Users\bob\AppData\Roaming\maltrack.exe`:           `C:\Users\bob\AppData\Roaming\maltrack.exe`,
		`"C:\Users\bob\AppData\Roaming\maltrack.exe"`:         `C:\Users\bob\AppData\Roaming\maltrack.exe`,
		`"C:\Users\bob\AppData\Roaming\maltrack.exe" -silent`: `C:\Users\bob\AppData\Roaming\maltrack.exe`,
		`C:\Windows\System32\cmd.exe /c C:\temp\maltrack.exe`: `C:\Windows\System32\cmd.exe`,
		`\??\C:\Users\bob\AppData\Roaming\maltrack.exe`:       `C:\Users\bob\AppData\Roaming\maltrack.exe`,
		`C:\Users\bob\AppData\Roaming\MALTRACK.EXE`:           `C:\Users\bob\AppData\Roaming\MALTRACK.EXE`,
	}

	for in, want := range cases {
		if got := extractExePath(in); got != want {
			t.Errorf("extractExePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchesTarget(t *testing.T) {
	want := "maltrack" // proc.Normalize("maltrack")

	cases := []struct {
		name, value string
		match       bool
	}{
		{"MalTrack", `C:\somewhere\unrelated.exe`, true},               // name itself matches
		{"Updater", `C:\Users\bob\AppData\Roaming\maltrack.exe`, true}, // value's exe matches
		{"Updater", `"C:\Users\bob\AppData\Roaming\Mal-Track.exe"`, true},
		{"Updater", `C:\Windows\System32\notepad.exe`, false},
		{"OneDrive", `C:\Program Files\Microsoft OneDrive\OneDrive.exe /background`, false},
	}

	for _, c := range cases {
		if got := matchesTarget(c.name, c.value, want); got != c.match {
			t.Errorf("matchesTarget(%q, %q, %q) = %v, want %v", c.name, c.value, want, got, c.match)
		}
	}
}
