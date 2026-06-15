package history

import "testing"

// no-op (keepRecent=false) bumps Applies but skips recent log.
func TestRecordCountsNoOpButKeepsRecentClean(t *testing.T) {
	dir := t.TempDir()

	if err := Record(dir, Entry{TargetID: "web", OK: true, Changed: false, Ranges: 5}, false); err != nil {
		t.Fatalf("record no-op: %v", err)
	}
	if err := Record(dir, Entry{TargetID: "web", OK: true, Changed: true, Ranges: 6}, true); err != nil {
		t.Fatalf("record change: %v", err)
	}
	if err := Record(dir, Entry{TargetID: "web", OK: false, Message: "boom"}, true); err != nil {
		t.Fatalf("record fail: %v", err)
	}

	store, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	c := store.Counters["web"]
	if c.Applies != 3 {
		t.Errorf("Applies = %d, want 3 (every apply counted)", c.Applies)
	}
	if c.Changes != 1 {
		t.Errorf("Changes = %d, want 1", c.Changes)
	}
	if c.Failures != 1 {
		t.Errorf("Failures = %d, want 1", c.Failures)
	}
	// recent: change+fail only, no-op excluded
	if len(store.Recent) != 2 {
		t.Errorf("Recent = %d entries, want 2 (no-op excluded)", len(store.Recent))
	}
}
