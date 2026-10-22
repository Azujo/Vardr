// SPDX-License-Identifier: AGPL-3.0-or-later

package urd

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrNotConfigured: schemat urd nie istnieje (archiwizator nigdy nie działał).
var ErrNotConfigured = errors.New("archiwum nie jest skonfigurowane")

// ArchiverState to stan archiwizatora zapisywany co minutę.
type ArchiverState struct {
	Version           string     `json:"version"`
	RetentionDays     int        `json:"retention_days"`
	SegmentMaxMB      int        `json:"segment_max_mb"`
	SegmentMaxAgeS    int        `json:"segment_max_age_s"`
	VerifyEveryS      int        `json:"verify_every_s"`
	StartedAt         time.Time  `json:"started_at"`
	HeartbeatAt       time.Time  `json:"heartbeat_at"`
	VerifyRequestedAt *time.Time `json:"verify_requested_at,omitempty"`
	VerifyRequestedBy string     `json:"verify_requested_by,omitempty"`
	// Miejsce na dysku archiwum (0 = nieznane) i powód wstrzymania archiwizacji.
	DiskFreeBytes  int64  `json:"disk_free_bytes"`
	DiskTotalBytes int64  `json:"disk_total_bytes"`
	Paused         string `json:"paused,omitempty"`
	// Granice polityki z konfiguracji serwera i źródła wyłączone na stałe.
	MinRetentionDays int      `json:"min_retention_days"`
	MaxRetentionDays int      `json:"max_retention_days"`
	PolicyGraceS     int      `json:"policy_grace_s"`
	ExcludePrefixes  []string `json:"exclude_prefixes"`
}

// Summary podsumowuje zawartość archiwum.
type Summary struct {
	Manifests      int        `json:"manifests"`       // z danymi w retencji
	ManifestsTotal int        `json:"manifests_total"` // cały łańcuch (z wygasłymi)
	Bytes          int64      `json:"bytes"`
	Batches        int64      `json:"batches"`
	OldestHour     *time.Time `json:"oldest_hour,omitempty"`
	NewestHour     *time.Time `json:"newest_hour,omitempty"`
	OpenSegments   int        `json:"open_segments"`
	OpenBytes      int64      `json:"open_bytes"`
	OpenBatches    int64      `json:"open_batches"`
	LastSegmentAt  *time.Time `json:"last_segment_at,omitempty"`
}

// Overview to stan archiwum dla panelu.
type Overview struct {
	State            *ArchiverState `json:"archiver"`
	Summary          Summary        `json:"summary"`
	LastVerification *Verification  `json:"last_verification"`
	Policy           *Policy        `json:"policy"`
	ScheduledChange  *PolicyChange  `json:"scheduled_change"` // zaplanowane osłabienie polityki
}

func notConfigured(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && (pg.Code == "42P01" || pg.Code == "3F000") { // brak tabeli / schematu
		return ErrNotConfigured
	}
	return err
}

// SaveState zapisuje stan archiwizatora (przy starcie i co minutę).
// Nie nadpisuje zlecenia weryfikacji z panelu.
func (p *PG) SaveState(ctx context.Context, s ArchiverState) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO urd.archiver_state
		(id, version, retention_days, segment_max_mb, segment_max_age_s, verify_every_s, started_at, heartbeat_at,
		 disk_free_bytes, disk_total_bytes, paused_reason, min_retention_days, max_retention_days, policy_grace_s, exclude_prefixes)
		VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (id) DO UPDATE SET version = $1, retention_days = $2, segment_max_mb = $3,
			segment_max_age_s = $4, verify_every_s = $5, started_at = $6, heartbeat_at = $7,
			disk_free_bytes = $8, disk_total_bytes = $9, paused_reason = $10, min_retention_days = $11,
			max_retention_days = $12, policy_grace_s = $13, exclude_prefixes = $14`,
		s.Version, s.RetentionDays, s.SegmentMaxMB, s.SegmentMaxAgeS, s.VerifyEveryS, s.StartedAt, s.HeartbeatAt,
		s.DiskFreeBytes, s.DiskTotalBytes, s.Paused, s.MinRetentionDays, s.MaxRetentionDays, s.PolicyGraceS, nonNil(s.ExcludePrefixes))
	return err
}

func isPermission(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "42501"
}

// RequestVerify zleca weryfikację (panel); archiwizator sprawdza zlecenia co minutę.
func (p *PG) RequestVerify(ctx context.Context, by string, at time.Time) error {
	tag, err := p.pool.Exec(ctx, `UPDATE urd.archiver_state SET verify_requested_at = $1, verify_requested_by = $2 WHERE id = 1`, at, by)
	if err != nil {
		return notConfigured(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotConfigured
	}
	return nil
}

// TakeVerifyRequest odbiera zlecenie weryfikacji (archiwizator).
func (p *PG) TakeVerifyRequest(ctx context.Context) (by string, ok bool, err error) {
	var at *time.Time
	var who *string
	err = p.pool.QueryRow(ctx, `SELECT verify_requested_at, verify_requested_by FROM urd.archiver_state WHERE id = 1`).Scan(&at, &who)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && at == nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	// Warunek na czas: zlecenie złożone w międzyczasie nie zostanie skasowane.
	if _, err := p.pool.Exec(ctx, `UPDATE urd.archiver_state SET verify_requested_at = NULL, verify_requested_by = NULL
		WHERE id = 1 AND verify_requested_at = $1`, *at); err != nil {
		return "", false, err
	}
	if who != nil {
		by = *who
	}
	return by, true, nil
}

// Overview zbiera stan archiwum dla panelu.
func (p *PG) Overview(ctx context.Context) (Overview, error) {
	var o Overview
	var st ArchiverState
	err := p.pool.QueryRow(ctx, `SELECT version, retention_days, segment_max_mb, segment_max_age_s, verify_every_s,
		started_at, heartbeat_at, verify_requested_at, coalesce(verify_requested_by, ''),
		disk_free_bytes, disk_total_bytes, paused_reason, min_retention_days, max_retention_days, policy_grace_s,
		exclude_prefixes FROM urd.archiver_state WHERE id = 1`).
		Scan(&st.Version, &st.RetentionDays, &st.SegmentMaxMB, &st.SegmentMaxAgeS, &st.VerifyEveryS,
			&st.StartedAt, &st.HeartbeatAt, &st.VerifyRequestedAt, &st.VerifyRequestedBy,
			&st.DiskFreeBytes, &st.DiskTotalBytes, &st.Paused, &st.MinRetentionDays, &st.MaxRetentionDays,
			&st.PolicyGraceS, &st.ExcludePrefixes)
	switch {
	case err == nil:
		o.State = &st
	case errors.Is(err, pgx.ErrNoRows):
	default:
		return o, notConfigured(err)
	}
	s := &o.Summary
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE expired_at IS NULL), count(*),
		coalesce(sum(bytes) FILTER (WHERE expired_at IS NULL), 0), coalesce(sum(records) FILTER (WHERE expired_at IS NULL), 0),
		min(hour) FILTER (WHERE expired_at IS NULL), max(hour) FROM urd.manifests`).
		Scan(&s.Manifests, &s.ManifestsTotal, &s.Bytes, &s.Batches, &s.OldestHour, &s.NewestHour); err != nil {
		return o, notConfigured(err)
	}
	if err := p.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE manifest_seq IS NULL),
		coalesce(sum(bytes) FILTER (WHERE manifest_seq IS NULL), 0), coalesce(sum(records) FILTER (WHERE manifest_seq IS NULL), 0),
		max(created_at) FROM urd.segments`).
		Scan(&s.OpenSegments, &s.OpenBytes, &s.OpenBatches, &s.LastSegmentAt); err != nil {
		return o, notConfigured(err)
	}
	if v, ok, err := p.LastVerification(ctx); err != nil {
		return o, notConfigured(err)
	} else if ok {
		o.LastVerification = &v
	}
	if pol, err := p.Policy(ctx); err == nil {
		o.Policy = &pol
	} else if !errors.Is(err, ErrNoPolicy) {
		return o, err
	}
	sc, err := p.ScheduledChange(ctx)
	if err != nil {
		return o, err
	}
	o.ScheduledChange = sc
	return o, nil
}

// Verifications zwraca ostatnie weryfikacje (najnowsze pierwsze).
func (p *PG) Verifications(ctx context.Context, limit int) ([]Verification, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+verifCols+`
		FROM urd.verifications ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, notConfigured(err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Verification, error) {
		var v Verification
		err := r.Scan(verifDst(&v, &v.Problems, &v.Unknown)...)
		return v, err
	})
}
