// Package scheduler: daily apply tick + startup apply.
package scheduler

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/rezmoss/ip-watch/internal/applier"
	"github.com/rezmoss/ip-watch/internal/config"
	"github.com/rezmoss/ip-watch/internal/notify"
)

// Scheduler: ApplyAll on start, daily at cfg.UpdateHour.
type Scheduler struct {
	cfg *config.Config
	app *applier.Applier
}

func New(cfg *config.Config, app *applier.Applier) *Scheduler {
	return &Scheduler{cfg: cfg, app: app}
}

// Run: apply on start + daily til ctx done.
func (s *Scheduler) Run(ctx context.Context) {
	// startup forces; daily detects change
	s.runOnce(ctx, "startup", true)
	for {
		d := untilNext(time.Now(), s.cfg.UpdateHour)
		log.Printf("scheduler: next update in %s", d.Round(time.Minute))
		select {
		case <-ctx.Done():
			return
		case <-time.After(d):
			s.runOnce(ctx, "daily", false)
		}
	}
}

func (s *Scheduler) runOnce(ctx context.Context, reason string, force bool) {
	results := s.app.ApplyAll(ctx, force)
	changed, failed := 0, 0
	for _, r := range results {
		status := "ok"
		if !r.OK {
			status = "FAILED"
			failed++
		}
		if r.Changed {
			changed++
		}
		log.Printf("scheduler[%s]: target=%s %s: %s", reason, r.TargetID, status, r.Message)
	}
	s.maybeNotify(ctx, reason, results, changed, failed)
}

// maybeNotify: webhook summary when cfg'd + warranted.
func (s *Scheduler) maybeNotify(ctx context.Context, reason string, results []applier.Result, changed, failed int) {
	if s.cfg.Notify.Webhook == "" {
		return
	}
	if !s.cfg.Notify.Always && changed == 0 && failed == 0 {
		return
	}
	text := fmt.Sprintf("ip-watch %s run: %d target(s), %d changed, %d failed", reason, len(results), changed, failed)
	if failed > 0 {
		var names []string
		for _, r := range results {
			if !r.OK {
				names = append(names, r.TargetID)
			}
		}
		text += " — failures: " + strings.Join(names, ", ")
	}
	if err := notify.Post(ctx, s.cfg.Notify.Webhook, text, results); err != nil {
		log.Printf("scheduler: notify failed: %v", err)
	}
}

// untilNext: dur to next hour:00.
func untilNext(now time.Time, hour int) time.Duration {
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, now.Location())
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next.Sub(now)
}
