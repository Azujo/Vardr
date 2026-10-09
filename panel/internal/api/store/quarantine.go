package store

import (
	"context"
	"encoding/json"
	"time"
)

// QuarantineJob to zlecenie ponownego przetworzenia kwarantanny.
type QuarantineJob struct {
	ID         int64           `json:"id"`
	CreatedAt  time.Time       `json:"created_at"`
	CreatedBy  string          `json:"created_by"`
	Filter     json.RawMessage `json:"filter"`
	Status     string          `json:"status"` // running | done | failed
	Total      int             `json:"total"`
	Recovered  int             `json:"recovered"`
	Failed     int             `json:"failed"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// QuarantineOutcome to wynik ponownego przetworzenia wpisu.
type QuarantineOutcome struct {
	EventID   string    `json:"event_id"`
	JobID     int64     `json:"job_id"`
	Recovered bool      `json:"recovered"`
	Reason    string    `json:"reason,omitempty"`
	At        time.Time `json:"at"`
}

// CreateQuarantineJob zakłada zlecenie (status running).
func (s *PG) CreateQuarantineJob(ctx context.Context, by string, filter any, total int) (QuarantineJob, error) {
	f, err := json.Marshal(filter)
	if err != nil {
		return QuarantineJob{}, err
	}
	j := QuarantineJob{CreatedBy: by, Filter: f, Status: "running", Total: total}
	err = s.pool.QueryRow(ctx, `INSERT INTO quarantine_jobs (created_by, filter, total) VALUES ($1, $2, $3) RETURNING id, created_at`,
		by, f, total).Scan(&j.ID, &j.CreatedAt)
	return j, err
}

// RecordQuarantineOutcomes zapisuje wyniki części zlecenia i postęp.
func (s *PG) RecordQuarantineOutcomes(ctx context.Context, job int64, recovered []string, failed map[string]string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	ids := make([]string, 0, len(recovered)+len(failed))
	flags := make([]bool, 0, cap(ids))
	reasons := make([]string, 0, cap(ids))
	for _, id := range recovered {
		ids, flags, reasons = append(ids, id), append(flags, true), append(reasons, "")
	}
	for id, r := range failed {
		ids, flags, reasons = append(ids, id), append(flags, false), append(reasons, r)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO quarantine_outcomes (event_id, job_id, recovered, reason)
		SELECT * FROM unnest($1::text[], array_fill($2::bigint, ARRAY[cardinality($1::text[])]), $3::boolean[], $4::text[])
		ON CONFLICT (event_id) DO UPDATE SET job_id = EXCLUDED.job_id, recovered = EXCLUDED.recovered,
			reason = EXCLUDED.reason, at = now()`, ids, job, flags, reasons); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE quarantine_jobs SET recovered = recovered + $2, failed = failed + $3 WHERE id = $1`,
		job, len(recovered), len(failed)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// FinishQuarantineJob kończy zlecenie (errMsg ≠ "" – status failed).
func (s *PG) FinishQuarantineJob(ctx context.Context, job int64, errMsg string) error {
	status := "done"
	if errMsg != "" {
		status = "failed"
	}
	_, err := s.pool.Exec(ctx, `UPDATE quarantine_jobs SET status = $2, error = $3, finished_at = now() WHERE id = $1`, job, status, errMsg)
	return err
}

// AbortRunningQuarantineJobs oznacza zlecenia przerwane restartem panelu.
func (s *PG) AbortRunningQuarantineJobs(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE quarantine_jobs SET status = 'failed', error = 'przerwane (restart panelu) – zleć ponownie',
		finished_at = now() WHERE status = 'running'`)
	return tag.RowsAffected(), err
}

// ListQuarantineJobs zwraca ostatnie zlecenia.
func (s *PG) ListQuarantineJobs(ctx context.Context, limit int) ([]QuarantineJob, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, created_at, created_by, filter, status, total, recovered, failed, finished_at, error
		FROM quarantine_jobs ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QuarantineJob
	for rows.Next() {
		var j QuarantineJob
		if err := rows.Scan(&j.ID, &j.CreatedAt, &j.CreatedBy, &j.Filter, &j.Status, &j.Total, &j.Recovered, &j.Failed,
			&j.FinishedAt, &j.Error); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// QuarantineOutcomes zwraca wyniki dla wskazanych wpisów.
func (s *PG) QuarantineOutcomes(ctx context.Context, eventIDs []string) (map[string]QuarantineOutcome, error) {
	out := map[string]QuarantineOutcome{}
	if len(eventIDs) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT event_id, job_id, recovered, reason, at FROM quarantine_outcomes WHERE event_id = ANY($1)`, eventIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var o QuarantineOutcome
		if err := rows.Scan(&o.EventID, &o.JobID, &o.Recovered, &o.Reason, &o.At); err != nil {
			return nil, err
		}
		out[o.EventID] = o
	}
	return out, rows.Err()
}
