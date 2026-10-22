// SPDX-License-Identifier: AGPL-3.0-or-later

package archiver

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Health to stan pętli archiwizatora zapisywany dla panelu (bezpieczny dla
// wielu gorutyn; metody na nil nic nie robią).
type Health struct {
	mu          sync.Mutex
	free, total uint64
	paused      string
}

func (h *Health) set(free, total uint64, paused string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.free, h.total, h.paused = free, total, paused
}

// Get zwraca wolne i całkowite miejsce na dysku archiwum (0 = nieznane)
// oraz powód wstrzymania archiwizacji ("" = działa).
func (h *Health) Get() (free, total uint64, paused string) {
	if h == nil {
		return 0, 0, ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.free, h.total, h.paused
}

// CheckDisk mierzy wolne miejsce (najwyżej co 10 s) i zwraca powód
// wstrzymania archiwizacji albo "". Wstrzymanie nie gubi danych: paczki
// czekają w kolejce, a po jej zapełnieniu ingest odmawia przyjęcia (503).
func (r *Archiver) CheckDisk() string {
	now := time.Now()
	if now.Before(r.diskCheck) {
		return r.paused
	}
	r.diskCheck = now.Add(10 * time.Second)
	free, total, err := diskUsageFn(r.A.Dir)
	if err != nil || total == 0 {
		r.paused = ""
		r.Health.set(0, 0, "")
		return ""
	}
	pct := float64(free) / float64(total) * 100
	gb := float64(free) / (1 << 30)
	r.M.DiskFree.Set(float64(free))
	r.M.DiskTotal.Set(float64(total))

	reason := ""
	if free < r.Cfg.MinFreeBytes || pct < r.Cfg.MinFreePercent {
		reason = fmt.Sprintf("mało miejsca na dysku archiwum: wolne %.1f GB (%.1f%%) – archiwizacja wstrzymana, paczki czekają w kolejce", gb, pct)
	}
	switch {
	case reason != "" && (r.paused == "" || now.After(r.diskWarn)):
		r.Log.Error(reason, "free_gb", fmt.Sprintf("%.1f", gb), "min_free_percent", r.Cfg.MinFreePercent)
		r.diskWarn = now.Add(5 * time.Minute)
	case reason == "" && r.paused != "":
		r.Log.Info("miejsce na dysku archiwum wróciło – archiwizacja wznowiona", "free_gb", fmt.Sprintf("%.1f", gb))
	case reason == "" && pct < r.Cfg.WarnFreePercent && now.After(r.diskWarn):
		r.Log.Warn("kończy się miejsce na dysku archiwum", "free_gb", fmt.Sprintf("%.1f", gb), "free_percent", fmt.Sprintf("%.1f", pct))
		r.diskWarn = now.Add(time.Hour)
	}
	paused := 0.0
	if reason != "" {
		paused = 1
	}
	r.M.Paused.Set(paused)
	r.paused = reason
	r.Health.set(free, total, reason)
	return reason
}

// Pause zatwierdza otwarty segment i czeka (archiwizacja wstrzymana).
func (r *Archiver) Pause(ctx context.Context, d time.Duration) {
	if err := r.Flush(ctx); err != nil {
		r.Log.Error("zatwierdzenie segmentu przy wstrzymaniu nieudane", "err", err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// diskUsageFn pozwala testom podstawić pomiar miejsca.
var diskUsageFn = diskUsage
