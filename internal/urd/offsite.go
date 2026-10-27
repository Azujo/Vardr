// SPDX-License-Identifier: AGPL-3.0-or-later

package urd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"siem/internal/s3"
)

// Kopia archiwum poza serwerem (1.7.1): zamknięte godziny – segmenty
// i manifest – trafiają do magazynu S3 z blokadą obiektów (Object Lock)
// do końca retencji. Nawet przejęcie serwera i konta magazynu nie pozwala
// ich usunąć ani nadpisać w trybie COMPLIANCE. Układ kluczy jak na dysku
// (prefiks + ścieżka względna), więc kopię czyta się tymi samymi
// narzędziami co archiwum (check-export, odczytaj).

// ObjectStore to magazyn kopii (s3.Client).
type ObjectStore interface {
	Put(ctx context.Context, key string, body []byte, lock *s3.Lock) error
}

// OffsiteCatalog to część spisu dla kopii poza serwerem.
type OffsiteCatalog interface {
	// PendingOffsite zwraca godziny (z treścią manifestu) jeszcze bez kopii,
	// których dane nie wygasły – rosnąco po numerze, najwyżej limit.
	PendingOffsite(ctx context.Context, limit int) ([]ManifestRecord, error)
	// MarkOffsite zapisuje czas wysłania kopii godziny.
	MarkOffsite(ctx context.Context, seq int64, at time.Time) error
	// OffsiteBacklog: liczba godzin bez kopii i najstarsza z nich.
	OffsiteBacklog(ctx context.Context) (int, *time.Time, error)
}

// OffsiteOptions to ustawienia wysyłki.
type OffsiteOptions struct {
	Prefix    string        // np. "vardr/" – klucz = prefiks + ścieżka w archiwum
	Mode      string        // s3.ModeCompliance albo s3.ModeGovernance
	Retention time.Duration // blokada do końca godziny + retencja
	Limit     int           // godzin w jednym przebiegu (0 = 24)
}

// Offsite wysyła kolejne godziny bez kopii i zwraca ich liczbę. Segment
// niezgodny z manifestem nie jest wysyłany (błąd – do weryfikacji
// archiwum). Ponowna wysyłka po przerwie tworzy nową wersję obiektu;
// poprzednia też jest zablokowana.
func (a *Archive) Offsite(ctx context.Context, st ObjectStore, cat OffsiteCatalog, opt OffsiteOptions) (int, error) {
	if opt.Limit <= 0 {
		opt.Limit = 24
	}
	pending, err := cat.PendingOffsite(ctx, opt.Limit)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range pending {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		if SumHex(m.Body) != m.SHA256 {
			return n, fmt.Errorf("manifest %d: the catalog content does not match its SHA-256", m.Seq)
		}
		var body Manifest
		if err := json.Unmarshal(m.Body, &body); err != nil {
			return n, fmt.Errorf("manifest %d: %w", m.Seq, err)
		}
		lock := &s3.Lock{Mode: opt.Mode, RetainUntil: m.Hour.UTC().Add(time.Hour + opt.Retention)}
		for _, s := range body.Segments {
			data, err := os.ReadFile(a.abs(s.Path))
			if err != nil {
				return n, fmt.Errorf("segment %s: %w", s.Path, err)
			}
			if SumHex(data) != s.SHA256 {
				return n, fmt.Errorf("segment %s does not match the manifest – not copied (run the archive verification)", s.Path)
			}
			if err := st.Put(ctx, opt.Prefix+s.Path, data, lock); err != nil {
				return n, fmt.Errorf("segment %s: %w", s.Path, err)
			}
		}
		// Manifest na końcu: jego obecność w magazynie oznacza pełną godzinę.
		if err := st.Put(ctx, opt.Prefix+ManifestPath(m.Hour), m.Body, lock); err != nil {
			return n, fmt.Errorf("manifest %d: %w", m.Seq, err)
		}
		if err := cat.MarkOffsite(ctx, m.Seq, a.now()); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// ---- spis w PG ----

func (p *PG) PendingOffsite(ctx context.Context, limit int) ([]ManifestRecord, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+manifestCols+`, body FROM urd.manifests
		WHERE offsite_at IS NULL AND expired_at IS NULL ORDER BY seq LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ManifestRecord, error) { return scanManifest(r, true) })
}

func (p *PG) MarkOffsite(ctx context.Context, seq int64, at time.Time) error {
	_, err := p.pool.Exec(ctx, `UPDATE urd.manifests SET offsite_at = $2 WHERE seq = $1`, seq, at)
	return err
}

func (p *PG) OffsiteBacklog(ctx context.Context) (int, *time.Time, error) {
	var n int
	var oldest *time.Time
	err := p.pool.QueryRow(ctx, `SELECT count(*), min(hour) FROM urd.manifests
		WHERE offsite_at IS NULL AND expired_at IS NULL`).Scan(&n, &oldest)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, nil
	}
	return n, oldest, err
}

// ---- spis w pamięci (testy) ----

func (c *MemCatalog) PendingOffsite(_ context.Context, limit int) ([]ManifestRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []ManifestRecord
	for _, m := range c.manifests {
		if _, done := c.offsite[m.Seq]; done || m.ExpiredAt != nil {
			continue
		}
		if len(out) == limit {
			break
		}
		out = append(out, m)
	}
	return out, nil
}

func (c *MemCatalog) MarkOffsite(_ context.Context, seq int64, at time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.offsite == nil {
		c.offsite = map[int64]time.Time{}
	}
	c.offsite[seq] = at
	return nil
}

func (c *MemCatalog) OffsiteBacklog(context.Context) (int, *time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	var oldest *time.Time
	for _, m := range c.manifests {
		if _, done := c.offsite[m.Seq]; done || m.ExpiredAt != nil {
			continue
		}
		if n == 0 {
			h := m.Hour
			oldest = &h
		}
		n++
	}
	return n, oldest, nil
}
