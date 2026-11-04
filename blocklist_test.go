package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestBlocklistAdblockHeaders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blocklist.txt")
	contents := `[Adblock Plus]
! Note: This one mostly won't cause restrictions either. Good pick if you don't have an admin handy to unblock anything.
  ! Comment: example.org
  [Adblock Plus 2.0]
# ignored.example
plain.example # inline.example
0.0.0.0 hosts.example
||ads.example^
`
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	previous := blocklist.Load()
	t.Cleanup(func() { blocklist.Store(previous) })
	if err := loadBlocklists([]string{path}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"example.one.", "example.to.", "example.org."} {
		if isBlocked(name) {
			t.Errorf("comment text blocked %s", name)
		}
	}
	want := map[string]struct{}{
		"plain.example.": {},
		"hosts.example.": {},
		"ads.example.":   {},
	}
	if got := *blocklist.Load(); !reflect.DeepEqual(got, want) {
		t.Errorf("blocked domains = %v, want %v", got, want)
	}
	for name := range want {
		if !isBlocked(name) || !isBlocked("sub."+name) {
			t.Errorf("expected %s and its subdomains to be blocked", name)
		}
	}
}
