// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// SyslogDecoder to dekoder syslog zmieniony w panelu.
type SyslogDecoder struct {
	ID        string    `json:"id"`
	Source    string    `json:"source"` // YAML; "" – tylko wyłączenie dekodera wbudowanego
	Enabled   bool      `json:"enabled"`
	Revision  int       `json:"revision"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
}

// DecoderVersion to wpis historii zmian dekodera.
type DecoderVersion struct {
	ID        int64     `json:"id"`
	DecoderID string    `json:"decoder_id"`
	Revision  int       `json:"revision"`
	Action    string    `json:"action"` // saved | enabled | disabled | reverted
	Source    string    `json:"source"`
	Enabled   bool      `json:"enabled"`
	Note      string    `json:"note,omitempty"`
	ChangedAt time.Time `json:"changed_at"`
	ChangedBy string    `json:"changed_by"`
}

// ListDecoders zwraca dekodery zmienione w panelu.
func (s *PG) ListDecoders(ctx context.Context) ([]SyslogDecoder, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, source, enabled, revision, updated_at, updated_by FROM syslog_decoders ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SyslogDecoder
	for rows.Next() {
		var d SyslogDecoder
		if err := rows.Scan(&d.ID, &d.Source, &d.Enabled, &d.Revision, &d.UpdatedAt, &d.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SaveDecoder zapisuje definicję i stan dekodera (nowa rewizja) z wpisem
// w historii.
func (s *PG) SaveDecoder(ctx context.Context, d SyslogDecoder, action, note string) (SyslogDecoder, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return d, err
	}
	defer tx.Rollback(ctx)
	// Rewizje rosną także po cofnięciu zmian i ponownym zapisie (historia).
	err = tx.QueryRow(ctx, `INSERT INTO syslog_decoders (id, source, enabled, updated_by, revision)
		VALUES ($1, $2, $3, $4, COALESCE((SELECT max(revision) FROM syslog_decoder_versions WHERE decoder_id = $1), 0) + 1)
		ON CONFLICT (id) DO UPDATE SET source = EXCLUDED.source, enabled = EXCLUDED.enabled,
			revision = syslog_decoders.revision + 1, updated_at = now(), updated_by = EXCLUDED.updated_by
		RETURNING revision, updated_at`, d.ID, d.Source, d.Enabled, d.UpdatedBy).Scan(&d.Revision, &d.UpdatedAt)
	if err != nil {
		return d, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO syslog_decoder_versions (decoder_id, revision, action, source, enabled, note, changed_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, d.ID, d.Revision, action, d.Source, d.Enabled, note, d.UpdatedBy); err != nil {
		return d, err
	}
	return d, tx.Commit(ctx)
}

// DeleteDecoder usuwa zmiany z panelu (dekoder wbudowany wraca do wersji
// z programu, własny znika); historia zostaje.
func (s *PG) DeleteDecoder(ctx context.Context, id, note, by string) (SyslogDecoder, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SyslogDecoder{}, err
	}
	defer tx.Rollback(ctx)
	var d SyslogDecoder
	err = tx.QueryRow(ctx, `DELETE FROM syslog_decoders WHERE id = $1 RETURNING id, source, enabled, revision, updated_at, updated_by`, id).
		Scan(&d.ID, &d.Source, &d.Enabled, &d.Revision, &d.UpdatedAt, &d.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO syslog_decoder_versions (decoder_id, revision, action, source, enabled, note, changed_by)
		VALUES ($1, $2, 'reverted', '', true, $3, $4)`, id, d.Revision+1, note, by); err != nil {
		return d, err
	}
	return d, tx.Commit(ctx)
}

// DecoderVersions zwraca historię zmian dekodera (najnowsze pierwsze).
func (s *PG) DecoderVersions(ctx context.Context, id string, limit int) ([]DecoderVersion, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, decoder_id, revision, action, source, enabled, note, changed_at, changed_by
		FROM syslog_decoder_versions WHERE decoder_id = $1 ORDER BY id DESC LIMIT $2`, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DecoderVersion
	for rows.Next() {
		var v DecoderVersion
		if err := rows.Scan(&v.ID, &v.DecoderID, &v.Revision, &v.Action, &v.Source, &v.Enabled, &v.Note, &v.ChangedAt, &v.ChangedBy); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
