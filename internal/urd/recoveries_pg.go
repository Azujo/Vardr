// SPDX-License-Identifier: AGPL-3.0-or-later

package urd

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

const recoveryCols = `id, kind, requested_by, requested_at, reason, paths, backup, window_from, window_to, verification_id,
	processed_at, ok, result, error`

func scanRecovery(r pgx.Row) (Recovery, error) {
	var x Recovery
	var result []byte
	err := r.Scan(&x.ID, &x.Kind, &x.RequestedBy, &x.RequestedAt, &x.Reason, &x.Paths, &x.Backup, &x.WindowFrom, &x.WindowTo,
		&x.VerificationID, &x.ProcessedAt, &x.OK, &result, &x.Error)
	if err == nil && result != nil {
		var res ReconcileResult
		if err := json.Unmarshal(result, &res); err == nil {
			x.Result = &res
		}
	}
	if x.Paths == nil {
		x.Paths = []string{}
	}
	return x, err
}

// RequestRecovery zleca przyjęcie albo kwarantannę plików (panel,
// decyzja administratora); archiwizator wykonuje zlecenie w ciągu minuty.
func (p *PG) RequestRecovery(ctx context.Context, kind, by, reason string, paths []string, verification int64) (int64, error) {
	b, err := json.Marshal(paths)
	if err != nil {
		return 0, err
	}
	var id int64
	err = p.pool.QueryRow(ctx, `INSERT INTO urd.recoveries (kind, requested_by, reason, paths, verification_id)
		VALUES ($1, $2, $3, $4, $5) RETURNING id`, kind, by, reason, b, verification).Scan(&id)
	return id, notConfigured(err)
}

// PendingRecoveries zwraca niewykonane operacje (najstarsze pierwsze).
func (p *PG) PendingRecoveries(ctx context.Context) ([]Recovery, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+recoveryCols+` FROM urd.recoveries WHERE processed_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Recovery, error) { return scanRecovery(r) })
}

// FinishRecovery zapisuje wynik operacji.
func (p *PG) FinishRecovery(ctx context.Context, id int64, ok bool, res *ReconcileResult, errText string, at time.Time) error {
	var b []byte
	if res != nil {
		var err error
		if b, err = json.Marshal(res); err != nil {
			return err
		}
	}
	_, err := p.pool.Exec(ctx, `UPDATE urd.recoveries SET processed_at = $2, ok = $3, result = $4, error = $5 WHERE id = $1`,
		id, at, ok, b, errText)
	return err
}

// Recoveries zwraca ostatnie operacje (najnowsze pierwsze).
func (p *PG) Recoveries(ctx context.Context, limit int) ([]Recovery, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+recoveryCols+` FROM urd.recoveries ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, notConfigured(err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Recovery, error) { return scanRecovery(r) })
}
