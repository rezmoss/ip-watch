package scheduler

import (
	"testing"
	"time"
)

func TestUntilNext(t *testing.T) {
	loc := time.UTC
	// 01:00 -> 03:00 = 2h
	now := time.Date(2026, 1, 1, 1, 0, 0, 0, loc)
	if d := untilNext(now, 3); d != 2*time.Hour {
		t.Fatalf("got %s, want 2h", d)
	}
	// 05:00 -> 03:00 tmrw = 22h
	now = time.Date(2026, 1, 1, 5, 0, 0, 0, loc)
	if d := untilNext(now, 3); d != 22*time.Hour {
		t.Fatalf("got %s, want 22h", d)
	}
	// at the hour -> next day (strictly future)
	now = time.Date(2026, 1, 1, 3, 0, 0, 0, loc)
	if d := untilNext(now, 3); d != 24*time.Hour {
		t.Fatalf("got %s, want 24h", d)
	}
}
