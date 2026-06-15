// Package state: persists last apply/target; no-op if unchanged.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rezmoss/ip-watch/internal/config"
)

// Entry: last apply for one target.
type Entry struct {
	Hash string `json:"hash"` // provider CIDR hash (shown in status)
	// desired-state fingerprint for skip-check (empty = re-apply once)
	Fingerprint string    `json:"fingerprint,omitempty"`
	AppliedAt   time.Time `json:"applied_at"`
}

// Store: JSON map id -> Entry.
type Store struct {
	path    string
	mu      sync.Mutex
	entries map[string]Entry
}

// Load: dir/state.json; empty if absent.
func Load(dir string) (*Store, error) {
	store := &Store{
		path:    filepath.Join(dir, "state.json"),
		entries: map[string]Entry{},
	}
	data, err := os.ReadFile(store.path)
	if errors.Is(err, fs.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading state: %w", err)
	}
	if err := json.Unmarshal(data, &store.entries); err != nil {
		return nil, fmt.Errorf("parsing state: %w", err)
	}
	return store, nil
}

func (s *Store) Get(targetID string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[targetID]
	return entry, ok
}

// Record: store target hash + desired-state fingerprint, then persist.
func (s *Store) Record(targetID, hash, fingerprint string, when time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[targetID] = Entry{Hash: hash, Fingerprint: fingerprint, AppliedAt: when}
	return s.save()
}

// Forget: drop target state + persist.
func (s *Store) Forget(targetID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[targetID]; !ok {
		return nil
	}
	delete(s.entries, targetID)
	return s.save()
}

func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("creating state dir: %w", err)
	}
	data, err := json.MarshalIndent(s.entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}
	return config.WriteFileAtomic(s.path, append(data, '\n'), 0o644)
}
