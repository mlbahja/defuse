package cleaner

import "testing"

func TestIsProtected(t *testing.T) {
	cases := map[string]bool{
		`C:\Windows\System32\cmd.exe`:               true,
		`C:\WINDOWS\system32\notepad.exe`:           true,
		`C:\Users\bob\AppData\Roaming\maltrack.exe`: false,
		`C:\Windows2\evil.exe`:                      false, // must not match on prefix alone without separator
	}

	for path, want := range cases {
		if got := IsProtected(path); got != want {
			t.Errorf("IsProtected(%q) = %v, want %v", path, got, want)
		}
	}
}
