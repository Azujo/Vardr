package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// IdentityAlias to alias konta (nazwa → osoba).
type IdentityAlias struct {
	Alias     string    `json:"alias"`
	Identity  string    `json:"identity"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// IdentityDomains zwraca domeny organizacji.
func (s *PG) IdentityDomains(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT domain FROM identity_domains ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// SetIdentityDomains zastępuje listę domen organizacji.
func (s *PG) SetIdentityDomains(ctx context.Context, domains []string, by string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM identity_domains WHERE NOT (domain = ANY($1))`, domains); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO identity_domains (domain, created_by) SELECT unnest($1::text[]), $2
		ON CONFLICT (domain) DO NOTHING`, domains, by); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// IdentitySharedAccounts zwraca konta wspólne urządzeń.
func (s *PG) IdentitySharedAccounts(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT account FROM identity_shared_accounts ORDER BY account`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// SetIdentitySharedAccounts zastępuje listę kont wspólnych urządzeń.
func (s *PG) SetIdentitySharedAccounts(ctx context.Context, accounts []string, by string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM identity_shared_accounts WHERE NOT (account = ANY($1))`, accounts); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO identity_shared_accounts (account, created_by) SELECT unnest($1::text[]), $2
		ON CONFLICT (account) DO NOTHING`, accounts, by); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// IdentityAliases zwraca aliasy kont.
func (s *PG) IdentityAliases(ctx context.Context) ([]IdentityAlias, error) {
	rows, err := s.pool.Query(ctx, `SELECT alias, identity, note, created_at, created_by FROM identity_aliases ORDER BY identity, alias`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (IdentityAlias, error) {
		var a IdentityAlias
		err := r.Scan(&a.Alias, &a.Identity, &a.Note, &a.CreatedAt, &a.CreatedBy)
		return a, err
	})
}

// SetIdentityAlias zapisuje alias (nadpisuje istniejący).
func (s *PG) SetIdentityAlias(ctx context.Context, a IdentityAlias) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO identity_aliases (alias, identity, note, created_by) VALUES ($1, $2, $3, $4)
		ON CONFLICT (alias) DO UPDATE SET identity = EXCLUDED.identity, note = EXCLUDED.note,
			created_at = now(), created_by = EXCLUDED.created_by`, a.Alias, a.Identity, a.Note, a.CreatedBy)
	return err
}

// DeleteIdentityAlias usuwa alias.
func (s *PG) DeleteIdentityAlias(ctx context.Context, alias string) (IdentityAlias, error) {
	var a IdentityAlias
	err := s.pool.QueryRow(ctx, `DELETE FROM identity_aliases WHERE alias = $1 RETURNING alias, identity, note, created_at, created_by`, alias).
		Scan(&a.Alias, &a.Identity, &a.Note, &a.CreatedAt, &a.CreatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}
