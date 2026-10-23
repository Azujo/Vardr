// SPDX-License-Identifier: AGPL-3.0-or-later

package archiver

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"siem/internal/urd"
)

// RecoveryStore to zlecenia obsługi niezgodności archiwum (implementuje urd.PG).
type RecoveryStore interface {
	PendingRecoveries(ctx context.Context) ([]urd.Recovery, error)
	FinishRecovery(ctx context.Context, id int64, ok bool, res *urd.ReconcileResult, errText string, at time.Time) error
}

// ProcessRecoveries wykonuje oczekujące operacje uzgodnienia spisu z dyskiem
// (po przywróceniu kopii – restore.sh; decyzje administratora – panel).
// Wynik trafia do spisu i do pliku w katalogu archiwum recoveries/.
// Zwraca liczbę wykonanych operacji.
func ProcessRecoveries(ctx context.Context, a *urd.Archive, store RecoveryStore, log *slog.Logger, lock *sync.Mutex) int {
	pending, err := store.PendingRecoveries(ctx)
	if err != nil {
		if ctx.Err() == nil {
			log.Warn("reading inconsistency handling requests failed", "err", err)
		}
		return 0
	}
	for _, r := range pending {
		if lock != nil {
			lock.Lock()
		}
		res, err := a.Run(ctx, r)
		if lock != nil {
			lock.Unlock()
		}
		now := time.Now().UTC()
		ok, errText := err == nil, ""
		if err != nil {
			errText = a.Msg(err)
		}
		r.ProcessedAt, r.OK, r.Result, r.Error = &now, &ok, &res, errText
		if ferr := store.FinishRecovery(context.WithoutCancel(ctx), r.ID, ok, &res, errText, now); ferr != nil {
			log.Error("recording the inconsistency handling result failed", "id", r.ID, "err", ferr)
		}
		if lerr := a.LogRecovery(r); lerr != nil {
			log.Warn("writing the operation to the archive directory failed", "id", r.ID, "err", lerr)
		}
		args := []any{"id", r.ID, "kind", r.Kind, "by", r.RequestedBy, "reason", r.Reason, "result", res.Summary("en")}
		if len(res.Rejected) > 0 {
			args = append(args, "rejected", res.Rejected)
		}
		switch {
		case err != nil:
			log.Error("archive inconsistency handling failed", append(args, "err", err)...)
		case len(res.Rejected) > 0:
			log.Warn("archive inconsistency handling – some files rejected", args...)
		default:
			log.Info("archive inconsistency handling", args...)
		}
	}
	return len(pending)
}
