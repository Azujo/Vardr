package urd

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// migrationLock: inny klucz niż migracje panelu (oba programy używają Sagi).
const migrationLock = 0x5572645f6d696772 // "Urd_migr"

// PG to katalog archiwum w bazie Saga (schemat urd).
type PG struct {
	pool *pgxpool.Pool
}

// OpenPG łączy się z bazą.
func OpenPG(ctx context.Context, url string) (*PG, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("adres bazy: %w", err)
	}
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &PG{pool: pool}, nil
}

// NewPG używa istniejącej puli (panel).
func NewPG(pool *pgxpool.Pool) *PG { return &PG{pool: pool} }

func (p *PG) Close() { p.pool.Close() }

// Migrate tworzy lub aktualizuje schemat urd.
func (p *PG) Migrate(ctx context.Context) (applied []string, err error) {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(migrationLock)); err != nil {
		return nil, err
	}
	defer conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", int64(migrationLock)) //nolint:errcheck

	// Schemat zwykle zakłada administrator (rola bez prawa CREATE w bazie);
	// tworzymy go tylko, gdy go brak (np. baza testowa).
	var exists bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_namespace WHERE nspname = 'urd')").Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		if _, err := conn.Exec(ctx, "CREATE SCHEMA urd"); err != nil {
			return nil, err
		}
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS urd.schema_migrations (
		version integer PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	done := map[int]bool{}
	rows, err := conn.Query(ctx, "SELECT version FROM urd.schema_migrations")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		done[v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	names, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	for _, path := range names {
		name := strings.TrimPrefix(path, "migrations/")
		num, _, _ := strings.Cut(name, "_")
		version, err := strconv.Atoi(num)
		if err != nil {
			return applied, fmt.Errorf("niepoprawna nazwa migracji %s", name)
		}
		if done[version] {
			continue
		}
		sql, err := migrationFiles.ReadFile(path)
		if err != nil {
			return applied, err
		}
		if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(sql)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO urd.schema_migrations (version, name) VALUES ($1, $2)", version, name)
			return err
		}); err != nil {
			return applied, fmt.Errorf("migracja %s: %w", name, err)
		}
		applied = append(applied, name)
	}
	return applied, nil
}

// LockWriter zajmuje blokadę jedynego archiwizatora (manifesty muszą
// powstawać w jednym miejscu). Blokada trwa do zamknięcia zwróconego
// połączenia; druga kopia czeka.
func (p *PG) LockWriter(ctx context.Context) (release func(), err error) {
	conn, err := p.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(writerLock)); err != nil {
		conn.Release()
		return nil, err
	}
	return func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", int64(writerLock))
		conn.Release()
	}, nil
}

const writerLock = 0x5572645f77726974 // "Urd_writ"

func (p *PG) AddSegment(ctx context.Context, s Segment) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO urd.segments
		(path, hour, sha256, bytes, records, first_received_at, last_received_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		s.Path, s.Hour, s.SHA256, s.Bytes, s.Records, s.FirstReceivedAt, s.LastReceivedAt, s.CreatedAt)
	return err
}

func (p *PG) OpenSegments(ctx context.Context) ([]Segment, error) {
	rows, err := p.pool.Query(ctx, `SELECT path, hour, sha256, bytes, records, first_received_at, last_received_at, created_at
		FROM urd.segments WHERE manifest_seq IS NULL ORDER BY created_at, path`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Segment, error) {
		var s Segment
		err := r.Scan(&s.Path, &s.Hour, &s.SHA256, &s.Bytes, &s.Records, &s.FirstReceivedAt, &s.LastReceivedAt, &s.CreatedAt)
		return s, err
	})
}

const manifestCols = `seq, hour, sha256, prev_sha256, segments, records, bytes, created_at, expired_at`

func scanManifest(r pgx.Row, withBody bool) (ManifestRecord, error) {
	var m ManifestRecord
	dst := []any{&m.Seq, &m.Hour, &m.SHA256, &m.PrevSHA256, &m.Segments, &m.Records, &m.Bytes, &m.CreatedAt, &m.ExpiredAt}
	if withBody {
		dst = append(dst, &m.Body)
	}
	err := r.Scan(dst...)
	return m, err
}

func (p *PG) LastManifest(ctx context.Context) (ManifestRecord, bool, error) {
	m, err := scanManifest(p.pool.QueryRow(ctx, `SELECT `+manifestCols+` FROM urd.manifests ORDER BY seq DESC LIMIT 1`), false)
	if errors.Is(err, pgx.ErrNoRows) {
		return m, false, nil
	}
	return m, err == nil, err
}

func (p *PG) AddManifest(ctx context.Context, m ManifestRecord, segPaths []string) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO urd.manifests
			(seq, hour, sha256, prev_sha256, segments, records, bytes, created_at, body)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			m.Seq, m.Hour, m.SHA256, m.PrevSHA256, m.Segments, m.Records, m.Bytes, m.CreatedAt, m.Body); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE urd.segments SET manifest_seq = $1 WHERE path = ANY($2) AND manifest_seq IS NULL`,
			m.Seq, segPaths)
		if err != nil {
			return err
		}
		if int(tag.RowsAffected()) != len(segPaths) {
			return fmt.Errorf("manifest %d: oznaczono %d z %d segmentów", m.Seq, tag.RowsAffected(), len(segPaths))
		}
		return nil
	})
}

func (p *PG) Manifests(ctx context.Context) ([]ManifestRecord, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+manifestCols+`, CASE WHEN expired_at IS NULL THEN body END
		FROM urd.manifests ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ManifestRecord, error) { return scanManifest(r, true) })
}

// RecentManifests zwraca ostatnie manifesty bez treści (panel).
func (p *PG) RecentManifests(ctx context.Context, limit int) ([]ManifestRecord, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+manifestCols+` FROM urd.manifests ORDER BY seq DESC LIMIT $1`, limit)
	if err != nil {
		return nil, notConfigured(err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ManifestRecord, error) { return scanManifest(r, false) })
}

func (p *PG) ExpireManifest(ctx context.Context, seq int64, at time.Time) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE urd.manifests SET expired_at = $2 WHERE seq = $1 AND expired_at IS NULL`, seq, at); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM urd.segments WHERE manifest_seq = $1`, seq)
		return err
	})
}

func (p *PG) SaveVerification(ctx context.Context, v Verification) (int64, error) {
	problems, err := json.Marshal(v.Problems)
	if err != nil {
		return 0, err
	}
	var id int64
	err = p.pool.QueryRow(ctx, `INSERT INTO urd.verifications
		(started_at, finished_at, ok, manifests, segments, records, bytes, problems)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		v.StartedAt, v.FinishedAt, v.OK, v.Manifests, v.Segments, v.Records, v.Bytes, problems).Scan(&id)
	return id, err
}

func (p *PG) LastVerification(ctx context.Context) (Verification, bool, error) {
	var v Verification
	var problems []byte
	err := p.pool.QueryRow(ctx, `SELECT id, started_at, finished_at, ok, manifests, segments, records, bytes, problems
		FROM urd.verifications ORDER BY id DESC LIMIT 1`).
		Scan(&v.ID, &v.StartedAt, &v.FinishedAt, &v.OK, &v.Manifests, &v.Segments, &v.Records, &v.Bytes, &problems)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, false, nil
	}
	if err != nil {
		return v, false, err
	}
	return v, true, json.Unmarshal(problems, &v.Problems)
}
