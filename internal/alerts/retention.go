// SPDX-License-Identifier: AGPL-3.0-or-later

package alerts

import (
	"context"
	"time"
)

// PruneResult to wynik sprzątania Gjallarhorna.
type PruneResult struct {
	Alerts int64 // zamknięte alerty (z ich zdarzeniami, osią czasu i outboxem)
	Outbox int64 // wysłane powiadomienia
}

// Prune usuwa alerty zamknięte przed closedBefore (kaskadowo: zdarzenia
// alertu, oś czasu, outbox) i wpisy outboxa wysłane przed sentBefore.
// Usuwa paczkami po batch wierszy – bez długich blokad przy dużych tabelach.
// Otwarte i analizowane alerty nie są usuwane nigdy.
func (p *PG) Prune(ctx context.Context, closedBefore, sentBefore time.Time, batch int) (PruneResult, error) {
	var res PruneResult
	for {
		tag, err := p.pool.Exec(ctx, `DELETE FROM gjallarhorn.alerts WHERE id IN (
			SELECT id FROM gjallarhorn.alerts WHERE status = 'closed' AND closed_at < $1 LIMIT $2)`, closedBefore, batch)
		if err != nil {
			return res, notConfigured(err)
		}
		res.Alerts += tag.RowsAffected()
		if tag.RowsAffected() < int64(batch) {
			break
		}
	}
	for {
		tag, err := p.pool.Exec(ctx, `DELETE FROM gjallarhorn.outbox WHERE id IN (
			SELECT id FROM gjallarhorn.outbox WHERE sent_at < $1 AND (NOT held OR digest_sent_at IS NOT NULL) LIMIT $2)`,
			sentBefore, batch)
		if err != nil {
			return res, notConfigured(err)
		}
		res.Outbox += tag.RowsAffected()
		if tag.RowsAffected() < int64(batch) {
			break
		}
	}
	return res, nil
}
