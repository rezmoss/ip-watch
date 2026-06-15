package state

import (
	"testing"
	"time"
)

func TestRecordAndLoad(t *testing.T) {
	dir := t.TempDir()
	store, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get("web1"); ok {
		t.Fatal("empty store should have no entry")
	}

	now := time.Now().Truncate(time.Second)
	if err := store.Record("web1", "abc123", "fp123", now); err != nil {
		t.Fatal(err)
	}

	// fresh load sees persisted
	reloaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := reloaded.Get("web1")
	if !ok {
		t.Fatal("entry not persisted")
	}
	if entry.Hash != "abc123" {
		t.Fatalf("hash = %q", entry.Hash)
	}
	if entry.Fingerprint != "fp123" {
		t.Fatalf("fingerprint = %q", entry.Fingerprint)
	}
	if !entry.AppliedAt.Equal(now) {
		t.Fatalf("appliedAt = %v, want %v", entry.AppliedAt, now)
	}
}

func TestLoadMissingDirIsEmpty(t *testing.T) {
	store, err := Load(t.TempDir() + "/does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get("x"); ok {
		t.Fatal("expected empty store")
	}
}
