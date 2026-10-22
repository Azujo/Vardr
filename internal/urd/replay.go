// SPDX-License-Identifier: AGPL-3.0-or-later

package urd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
)

// Stany zlecenia odtworzenia.
const (
	ReplayPending = "pending"
	ReplayRunning = "running"
	ReplayDone    = "done"
	ReplayFailed  = "failed"
)

// ReplayJob to zlecenie odtworzenia paczek z archiwum: pełne godziny
// archiwizacji [From, To), opcjonalnie tylko wybrani agenci.
type ReplayJob struct {
	ID          int64      `json:"id"`
	RequestedAt time.Time  `json:"requested_at"`
	RequestedBy string     `json:"requested_by"`
	Reason      string     `json:"reason"`
	From        time.Time  `json:"from"`
	To          time.Time  `json:"to"`
	Agents      []string   `json:"agents"`
	Status      string     `json:"status"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	Error       string     `json:"error,omitempty"`
	Batches     int64      `json:"batches"` // paczki wysłane do ścieżki replay
	Skipped     int64      `json:"skipped"` // paczki innych agentów
	Bytes       int64      `json:"bytes"`
}

// ReplayStats to postęp odtwarzania.
type ReplayStats struct {
	Batches, Skipped, Bytes int64
}

// Replay czyta paczki z zamkniętych godzin [from, to) i przekazuje je do fn
// (agents puste = wszyscy). Każdy segment jest przy odczycie porównywany
// z sumą z manifestu, a każda paczka ze swoją sumą – niezgodne archiwum
// przerywa odtwarzanie.
func (a *Archive) Replay(ctx context.Context, from, to time.Time, agents []string,
	fn func(meta RecordMeta, payload []byte) error, progress func(ReplayStats)) (ReplayStats, error) {
	var st ReplayStats
	plan, err := a.PlanExport(ctx, from, to)
	if err != nil {
		return st, err
	}
	for _, m := range plan.InRange {
		for _, s := range plan.Bodies[m.Seq].Segments {
			if err := a.replaySegment(ctx, s, agents, fn, &st); err != nil {
				return st, err
			}
			if progress != nil {
				progress(st)
			}
		}
	}
	return st, nil
}

func (a *Archive) replaySegment(ctx context.Context, s Segment, agents []string,
	fn func(RecordMeta, []byte) error, st *ReplayStats) error {
	f, err := os.Open(a.abs(s.Path))
	if err != nil {
		return fmt.Errorf("segment %s: %w", s.Path, err)
	}
	defer f.Close()
	h := sha256.New()
	r, err := NewReader(io.TeeReader(f, h))
	if err != nil {
		return fmt.Errorf("segment %s: %w", s.Path, err)
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		meta, payload, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("segment %s: %w", s.Path, err)
		}
		if SumHex(payload) != meta.SHA256 {
			return fmt.Errorf("segment %s: paczka %s niezgodna ze swoją sumą – uruchom weryfikację archiwum", s.Path, meta.Batch)
		}
		if len(agents) > 0 && !slices.Contains(agents, meta.Agent) {
			st.Skipped++
			continue
		}
		if err := fn(meta, payload); err != nil {
			return err
		}
		st.Batches++
		st.Bytes += int64(len(payload))
	}
	// Reader buforuje odczyt – reszta pliku musi trafić do hasha.
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != s.SHA256 {
		return fmt.Errorf("segment %s: SHA-256 niezgodny z manifestem – uruchom weryfikację archiwum", s.Path)
	}
	return nil
}

// ---- spis zleceń (PostgreSQL) ----

// ErrReplayNotFound: nie ma takiego zlecenia odtworzenia.
var ErrReplayNotFound = errors.New("nie ma takiego odtworzenia")

const replayCols = `id, requested_at, requested_by, reason, from_hour, to_hour, agents, status, started_at, finished_at,
	error, batches, skipped, bytes`

func scanReplay(r pgx.Row) (ReplayJob, error) {
	var j ReplayJob
	err := r.Scan(&j.ID, &j.RequestedAt, &j.RequestedBy, &j.Reason, &j.From, &j.To, &j.Agents, &j.Status, &j.StartedAt,
		&j.FinishedAt, &j.Error, &j.Batches, &j.Skipped, &j.Bytes)
	if j.Agents == nil {
		j.Agents = []string{}
	}
	return j, err
}

// CreateReplay składa zlecenie odtworzenia (panel).
func (p *PG) CreateReplay(ctx context.Context, by, reason string, from, to time.Time, agents []string) (ReplayJob, error) {
	if agents == nil {
		agents = []string{}
	}
	j, err := scanReplay(p.pool.QueryRow(ctx, `INSERT INTO urd.replays (requested_by, reason, from_hour, to_hour, agents)
		VALUES ($1, $2, $3, $4, $5) RETURNING `+replayCols, by, reason, from, to, agents))
	return j, notConfigured(err)
}

// Replays zwraca ostatnie zlecenia odtworzenia.
func (p *PG) Replays(ctx context.Context, limit int) ([]ReplayJob, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+replayCols+` FROM urd.replays ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, notConfigured(err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ReplayJob, error) { return scanReplay(r) })
}

// ClaimReplay bierze najstarsze oczekujące zlecenie (archiwizator).
func (p *PG) ClaimReplay(ctx context.Context) (ReplayJob, bool, error) {
	j, err := scanReplay(p.pool.QueryRow(ctx, `UPDATE urd.replays SET status = 'running', started_at = now()
		WHERE id = (SELECT id FROM urd.replays WHERE status = 'pending' ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING `+replayCols))
	if errors.Is(err, pgx.ErrNoRows) {
		return j, false, nil
	}
	return j, err == nil, err
}

// ReplayProgress zapisuje postęp trwającego odtworzenia.
func (p *PG) ReplayProgress(ctx context.Context, id int64, st ReplayStats) error {
	_, err := p.pool.Exec(ctx, `UPDATE urd.replays SET batches = $2, skipped = $3, bytes = $4 WHERE id = $1`,
		id, st.Batches, st.Skipped, st.Bytes)
	return err
}

// FinishReplay zapisuje wynik odtworzenia.
func (p *PG) FinishReplay(ctx context.Context, j ReplayJob) error {
	_, err := p.pool.Exec(ctx, `UPDATE urd.replays SET status = $2, finished_at = now(), error = $3,
		batches = $4, skipped = $5, bytes = $6 WHERE id = $1`, j.ID, j.Status, j.Error, j.Batches, j.Skipped, j.Bytes)
	return err
}

// FailInterruptedReplays oznacza odtworzenia przerwane restartem archiwizatora.
func (p *PG) FailInterruptedReplays(ctx context.Context) (int64, error) {
	tag, err := p.pool.Exec(ctx, `UPDATE urd.replays SET status = 'failed', finished_at = now(),
		error = 'przerwane restartem archiwizatora – zleć ponownie' WHERE status = 'running'`)
	return tag.RowsAffected(), err
}
