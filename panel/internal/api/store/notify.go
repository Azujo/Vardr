// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Channel to kanał powiadomień. URL jest sekretem – nie trafia do JSON.
type Channel struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
	URL  string `json:"-"`
	// SigningSecret: sekret podpisu HMAC wiadomości (pusty – bez podpisu);
	// jak URL – nie trafia do JSON. Signed mówi panelowi, że podpis jest.
	SigningSecret string      `json:"-"`
	Signed        bool        `json:"signed"`
	Events        []string    `json:"events"`
	AlertFilter   AlertFilter `json:"alert_filter"`
	Enabled       bool        `json:"enabled"`
	CreatedAt     time.Time   `json:"created_at"`
	CreatedBy     string      `json:"created_by"`
	UpdatedAt     time.Time   `json:"updated_at"`
	LastOKAt      *time.Time  `json:"last_ok_at,omitempty"`
	LastError     string      `json:"last_error,omitempty"`
	LastErrorAt   *time.Time  `json:"last_error_at,omitempty"`
}

// AlertFilter wybiera alerty detekcji wysyłane na kanał.
type AlertFilter struct {
	// MinLevel: najniższy poziom (informational … critical); puste = wszystkie.
	MinLevel string `json:"min_level,omitempty"`
	// RulesMode: all (domyślnie) | only – tylko Rules | except – bez Rules.
	RulesMode string   `json:"rules_mode,omitempty"`
	Rules     []string `json:"rules,omitempty"`
}

// NotifyLogEntry to wpis dziennika wysyłek.
type NotifyLogEntry struct {
	ID           int64     `json:"id"`
	At           time.Time `json:"at"`
	ChannelID    *int64    `json:"channel_id,omitempty"`
	Channel      string    `json:"channel"`
	Event        string    `json:"event"`
	Title        string    `json:"title"`
	OK           bool      `json:"ok"`
	Error        string    `json:"error,omitempty"`
	AnchorSeq    *int64    `json:"anchor_seq,omitempty"`
	AnchorSHA256 string    `json:"anchor_sha256,omitempty"`
}

const channelCols = `id, name, kind, url, events, alert_filter, enabled, created_at, created_by, updated_at, last_ok_at,
	last_error, last_error_at, signing_secret`

func scanChannel(r pgx.Row) (Channel, error) {
	var c Channel
	err := r.Scan(&c.ID, &c.Name, &c.Kind, &c.URL, &c.Events, &c.AlertFilter, &c.Enabled, &c.CreatedAt, &c.CreatedBy, &c.UpdatedAt,
		&c.LastOKAt, &c.LastError, &c.LastErrorAt, &c.SigningSecret)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	c.Signed = c.SigningSecret != ""
	if c.Events == nil {
		c.Events = []string{}
	}
	return c, err
}

// ListChannels zwraca kanały powiadomień.
func (s *PG) ListChannels(ctx context.Context) ([]Channel, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+channelCols+` FROM notify_channels ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Channel, error) { return scanChannel(r) })
}

// ChannelByID zwraca kanał.
func (s *PG) ChannelByID(ctx context.Context, id int64) (Channel, error) {
	return scanChannel(s.pool.QueryRow(ctx, `SELECT `+channelCols+` FROM notify_channels WHERE id = $1`, id))
}

// CreateChannel dodaje kanał.
func (s *PG) CreateChannel(ctx context.Context, c Channel) (Channel, error) {
	out, err := scanChannel(s.pool.QueryRow(ctx, `INSERT INTO notify_channels (name, kind, url, events, alert_filter, enabled,
		created_by, signing_secret) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING `+channelCols, c.Name, c.Kind, c.URL, c.Events,
		c.AlertFilter, c.Enabled, c.CreatedBy, c.SigningSecret))
	if isUniqueViolation(err) {
		return out, ErrConflict
	}
	return out, err
}

// UpdateChannel zmienia nazwę, zdarzenia, włączenie i (gdy url != "") adres.
func (s *PG) UpdateChannel(ctx context.Context, c Channel) (Channel, error) {
	out, err := scanChannel(s.pool.QueryRow(ctx, `UPDATE notify_channels SET name = $2, events = $3, enabled = $4,
		url = CASE WHEN $5 = '' THEN url ELSE $5 END, alert_filter = $6, updated_at = now() WHERE id = $1 RETURNING `+channelCols,
		c.ID, c.Name, c.Events, c.Enabled, c.URL, c.AlertFilter))
	if isUniqueViolation(err) {
		return out, ErrConflict
	}
	return out, err
}

// SetChannelSecret ustawia sekret podpisu wiadomości ("" – bez podpisu).
func (s *PG) SetChannelSecret(ctx context.Context, id int64, secret string) (Channel, error) {
	return scanChannel(s.pool.QueryRow(ctx, `UPDATE notify_channels SET signing_secret = $2, updated_at = now()
		WHERE id = $1 RETURNING `+channelCols, id, secret))
}

// DeleteChannel usuwa kanał (wpisy dziennika zostają).
func (s *PG) DeleteChannel(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM notify_channels WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// RecordDelivery zapisuje wynik wysyłki w dzienniku i stanie kanału.
func (s *PG) RecordDelivery(ctx context.Context, e NotifyLogEntry) error {
	if _, err := s.pool.Exec(ctx, `INSERT INTO notify_log (at, channel_id, channel, event, title, ok, error, anchor_seq, anchor_sha256)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		e.At, e.ChannelID, e.Channel, e.Event, e.Title, e.OK, e.Error, e.AnchorSeq, nullIfEmpty(e.AnchorSHA256)); err != nil {
		return err
	}
	if e.ChannelID == nil {
		return nil
	}
	var err error
	if e.OK {
		_, err = s.pool.Exec(ctx, `UPDATE notify_channels SET last_ok_at = $2 WHERE id = $1`, *e.ChannelID, e.At)
	} else {
		_, err = s.pool.Exec(ctx, `UPDATE notify_channels SET last_error = $2, last_error_at = $3 WHERE id = $1`,
			*e.ChannelID, e.Error, e.At)
	}
	return err
}

// NotifyLog zwraca ostatnie wysyłki.
func (s *PG) NotifyLog(ctx context.Context, limit int) ([]NotifyLogEntry, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, at, channel_id, channel, event, title, ok, error, anchor_seq,
		coalesce(anchor_sha256, '') FROM notify_log ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (NotifyLogEntry, error) {
		var e NotifyLogEntry
		err := r.Scan(&e.ID, &e.At, &e.ChannelID, &e.Channel, &e.Event, &e.Title, &e.OK, &e.Error, &e.AnchorSeq, &e.AnchorSHA256)
		return e, err
	})
}

// LastAnchorAt zwraca czas ostatniej udanej wysyłki kotwicy.
func (s *PG) LastAnchorAt(ctx context.Context) (*time.Time, error) {
	var at *time.Time
	err := s.pool.QueryRow(ctx, `SELECT max(at) FROM notify_log WHERE event = 'anchor' AND ok`).Scan(&at)
	return at, err
}

// PruneNotifyLog usuwa stare wpisy dziennika poza kotwicami.
func (s *PG) PruneNotifyLog(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM notify_log WHERE at < $1 AND event <> 'anchor'`, before)
	return tag.RowsAffected(), err
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
