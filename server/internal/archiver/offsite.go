// SPDX-License-Identifier: AGPL-3.0-or-later

package archiver

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"siem/internal/s3"
	"siem/internal/urd"
	"siem/server/internal/metrics"
)

// Offsite co Every wysyła zamknięte godziny archiwum do magazynu S3
// z blokadą obiektów (urd.Archive.Offsite). Przy starcie sprawdza, czy
// kubełek ma włączone Object Lock – bez niego kopia nie jest wysyłana
// (dane dałoby się usunąć, a to ma być kopia nie do usunięcia).
type Offsite struct {
	A       *urd.Archive
	Store   *s3.Client
	Catalog urd.OffsiteCatalog
	Opt     urd.OffsiteOptions
	// Retention: bieżąca retencja z polityki (blokada do końca retencji).
	Retention func() time.Duration
	Every     time.Duration
	Log       *slog.Logger
	M         *metrics.Offsite
	Lock      *sync.Mutex // wspólna z wygaszaniem danych (Maintain)
}

func (o *Offsite) Run(ctx context.Context) {
	if o.Every <= 0 {
		o.Every = 5 * time.Minute
	}
	checked := false
	for {
		if !checked {
			checked = o.checkBucket(ctx)
		}
		if checked {
			o.once(ctx)
		}
		t := time.NewTimer(o.Every)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// checkBucket: kubełek z Object Lock (inaczej kopia nie ma sensu).
func (o *Offsite) checkBucket(ctx context.Context) bool {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	on, mode, err := o.Store.LockConfig(cctx)
	switch {
	case err != nil:
		o.Log.Error("archive copy: cannot read the bucket object lock configuration", "bucket", o.Store.Bucket, "err", err)
	case !on:
		o.Log.Error("archive copy: the bucket has no Object Lock – nothing is sent (create the bucket with object lock enabled)",
			"bucket", o.Store.Bucket)
	default:
		o.Log.Info("archive copy to S3 enabled", "bucket", o.Store.Bucket, "prefix", o.Opt.Prefix, "mode", o.Opt.Mode,
			"bucket_default_mode", mode)
		o.M.Enabled.Set(1)
		return true
	}
	o.M.Errors.Inc()
	return false
}

func (o *Offsite) once(ctx context.Context) {
	if o.Lock != nil {
		o.Lock.Lock()
		defer o.Lock.Unlock()
	}
	opt := o.Opt
	opt.Retention = o.Retention()
	total := 0
	for ctx.Err() == nil {
		n, err := o.A.Offsite(ctx, o.Store, o.Catalog, opt)
		total += n
		if err != nil {
			o.M.Errors.Inc()
			o.Log.Error("archive copy to S3 failed – retried in a moment", "sent_hours", total, "err", err)
			break
		}
		if n == 0 {
			o.M.LastSuccess.SetToCurrentTime()
			break
		}
	}
	if total > 0 {
		o.M.Hours.Add(float64(total))
		o.Log.Info("archive hours copied to S3", "hours", total)
	}
	if n, oldest, err := o.Catalog.OffsiteBacklog(ctx); err == nil {
		o.M.Pending.Set(float64(n))
		age := 0.0
		if oldest != nil {
			age = time.Since(oldest.Add(time.Hour)).Seconds()
		}
		o.M.OldestPendingAge.Set(max(0, age))
	}
}
