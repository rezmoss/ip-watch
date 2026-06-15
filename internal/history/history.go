// Package history: apply outcomes + counters for UI & /metrics.
package history

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

const maxRecent = 500

// Entry: one apply outcome.
type Entry struct {
	TargetID string    `json:"target_id"`
	Provider string    `json:"provider"`
	Engine   string    `json:"engine"`
	OK       bool      `json:"ok"`
	Changed  bool      `json:"changed"`
	Ranges   int       `json:"ranges"`
	Message  string    `json:"message"`
	When     time.Time `json:"when"`
}

// Counter: totals + last-success per target.
type Counter struct {
	Applies     int       `json:"applies"`
	Changes     int       `json:"changes"`
	Failures    int       `json:"failures"`
	Ranges      int       `json:"ranges"`
	LastSuccess time.Time `json:"last_success"`
}

// Store: persisted history; capped recent + counters.
type Store struct {
	Recent   []Entry            `json:"recent"`
	Counters map[string]Counter `json:"counters"`

	path string
	mu   sync.Mutex
}

func file(dir string) string { return filepath.Join(dir, "history.json") }

// Load: read store from dir, empty if absent.
func Load(dir string) (*Store, error) {
	store := &Store{path: file(dir), Counters: map[string]Counter{}}
	data, err := os.ReadFile(store.path)
	if errors.Is(err, fs.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading history: %w", err)
	}
	if err := json.Unmarshal(data, store); err != nil {
		return nil, fmt.Errorf("parsing history: %w", err)
	}
	if store.Counters == nil {
		store.Counters = map[string]Counter{}
	}
	return store, nil
}

// Record: bump counters, append recent; reload first (concurrent)
func Record(dir string, e Entry, keepRecent bool) error {
	store, err := Load(dir)
	if err != nil {
		return fmt.Errorf("recording history: %w", err)
	}
	if keepRecent {
		store.Recent = append(store.Recent, e)
		if len(store.Recent) > maxRecent {
			store.Recent = store.Recent[len(store.Recent)-maxRecent:]
		}
	}
	c := store.Counters[e.TargetID]
	c.Applies++
	if e.Changed {
		c.Changes++
	}
	if !e.OK {
		c.Failures++
	}
	if e.OK {
		c.LastSuccess = e.When
		c.Ranges = e.Ranges
	}
	store.Counters[e.TargetID] = c
	return store.save()
}

func (s *Store) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("creating history dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling history: %w", err)
	}
	return config.WriteFileAtomic(s.path, append(data, '\n'), 0o644)
}
