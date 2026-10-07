package urd

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const exportCols = `id, requested_at, requested_by, reason, from_hour, to_hour, status, started_at, finished_at,
	error, file_name, bytes, sha256, manifests, segments, records`

func scanExport(r pgx.Row) (ExportJob, error) {
	var j ExportJob
	err := r.Scan(&j.ID, &j.RequestedAt, &j.RequestedBy, &j.Reason, &j.From, &j.To, &j.Status, &j.StartedAt, &j.FinishedAt,
		&j.Error, &j.FileName, &j.Bytes, &j.SHA256, &j.Manifests, &j.Segments, &j.Records)
	return j, err
}

// ErrExportNotFound: nie ma takiego zlecenia eksportu.
var ErrExportNotFound = errors.New("nie ma takiego eksportu")

// CreateExport składa zlecenie eksportu (panel).
func (p *PG) CreateExport(ctx context.Context, by, reason string, from, to time.Time) (ExportJob, error) {
	j, err := scanExport(p.pool.QueryRow(ctx, `INSERT INTO urd.exports (requested_by, reason, from_hour, to_hour)
		VALUES ($1, $2, $3, $4) RETURNING `+exportCols, by, reason, from, to))
	return j, notConfigured(err)
}

// Exports zwraca ostatnie zlecenia eksportu.
func (p *PG) Exports(ctx context.Context, limit int) ([]ExportJob, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+exportCols+` FROM urd.exports ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, notConfigured(err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ExportJob, error) { return scanExport(r) })
}

// ExportByID zwraca zlecenie eksportu.
func (p *PG) ExportByID(ctx context.Context, id int64) (ExportJob, error) {
	j, err := scanExport(p.pool.QueryRow(ctx, `SELECT `+exportCols+` FROM urd.exports WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return j, ErrExportNotFound
	}
	return j, notConfigured(err)
}

// ClaimExport bierze najstarsze oczekujące zlecenie (archiwizator).
func (p *PG) ClaimExport(ctx context.Context) (ExportJob, bool, error) {
	j, err := scanExport(p.pool.QueryRow(ctx, `UPDATE urd.exports SET status = 'running', started_at = now()
		WHERE id = (SELECT id FROM urd.exports WHERE status = 'pending' ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING `+exportCols))
	if errors.Is(err, pgx.ErrNoRows) {
		return j, false, nil
	}
	return j, err == nil, err
}

// FinishExport zapisuje wynik eksportu.
func (p *PG) FinishExport(ctx context.Context, j ExportJob) error {
	_, err := p.pool.Exec(ctx, `UPDATE urd.exports SET status = $2, finished_at = now(), error = $3, file_name = $4,
		bytes = $5, sha256 = $6, manifests = $7, segments = $8, records = $9 WHERE id = $1`,
		j.ID, j.Status, j.Error, j.FileName, j.Bytes, j.SHA256, j.Manifests, j.Segments, j.Records)
	return err
}

// FailInterruptedExports oznacza eksporty przerwane restartem archiwizatora.
func (p *PG) FailInterruptedExports(ctx context.Context) (int64, error) {
	tag, err := p.pool.Exec(ctx, `UPDATE urd.exports SET status = 'failed', finished_at = now(),
		error = 'przerwany restartem archiwizatora – zleć ponownie' WHERE status = 'running'`)
	return tag.RowsAffected(), err
}

// ExpireExports oznacza gotowe eksporty starsze niż before jako wygasłe
// i zwraca nazwy ich plików do usunięcia.
func (p *PG) ExpireExports(ctx context.Context, before time.Time) ([]string, error) {
	rows, err := p.pool.Query(ctx, `UPDATE urd.exports SET status = 'expired'
		WHERE status = 'done' AND finished_at < $1 RETURNING file_name`, before)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
