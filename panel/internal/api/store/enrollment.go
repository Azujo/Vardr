package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrTokenInvalid: token nie istnieje, wygasł, został unieważniony albo
// wyczerpał limit użyć (bez rozróżniania – nie podpowiadamy atakującemu).
var ErrTokenInvalid = errors.New("token rejestracyjny jest nieważny")

// EnrollToken to token rejestracyjny agentów.
type EnrollToken struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	TokenHash string     `json:"-"`
	Profile   string     `json:"profile"`
	MaxUses   int        `json:"max_uses"`
	Uses      int        `json:"uses"`
	ExpiresAt time.Time  `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	CreatedBy string     `json:"created_by"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// AgentCert to certyfikat wystawiony agentowi.
type AgentCert struct {
	Serial       string     `json:"serial"`
	AgentID      string     `json:"agent_id"`
	IssuedAt     time.Time  `json:"issued_at"`
	NotAfter     time.Time  `json:"not_after"`
	TokenID      *int64     `json:"token_id,omitempty"`
	RenewedFrom  string     `json:"renewed_from,omitempty"`
	Hostname     string     `json:"hostname"`
	RemoteIP     string     `json:"remote_ip"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	RevokeReason string     `json:"revoke_reason,omitempty"`
}

const tokenCols = `id, name, token_hash, profile, max_uses, uses, expires_at, created_at, created_by, revoked_at`

func scanToken(row pgx.Row) (EnrollToken, error) {
	var t EnrollToken
	err := row.Scan(&t.ID, &t.Name, &t.TokenHash, &t.Profile, &t.MaxUses, &t.Uses, &t.ExpiresAt, &t.CreatedAt, &t.CreatedBy, &t.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

// CreateEnrollToken zapisuje token (tylko skrót).
func (s *PG) CreateEnrollToken(ctx context.Context, t EnrollToken) (EnrollToken, error) {
	return scanToken(s.pool.QueryRow(ctx, `INSERT INTO enrollment_tokens (name, token_hash, profile, max_uses, expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+tokenCols, t.Name, t.TokenHash, t.Profile, t.MaxUses, t.ExpiresAt, t.CreatedBy))
}

// ListEnrollTokens zwraca tokeny od najnowszych.
func (s *PG) ListEnrollTokens(ctx context.Context) ([]EnrollToken, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+tokenCols+` FROM enrollment_tokens ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeEnrollToken unieważnia token (wydane już certyfikaty działają dalej).
func (s *PG) RevokeEnrollToken(ctx context.Context, id int64) (EnrollToken, error) {
	return scanToken(s.pool.QueryRow(ctx, `UPDATE enrollment_tokens SET revoked_at = COALESCE(revoked_at, now())
		WHERE id = $1 RETURNING `+tokenCols, id))
}

// UseEnrollToken atomowo zużywa jedno użycie ważnego tokenu.
func (s *PG) UseEnrollToken(ctx context.Context, tokenHash string, now time.Time) (EnrollToken, error) {
	t, err := scanToken(s.pool.QueryRow(ctx, `UPDATE enrollment_tokens SET uses = uses + 1
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2 AND (max_uses = 0 OR uses < max_uses)
		RETURNING `+tokenCols, tokenHash, now))
	if errors.Is(err, ErrNotFound) {
		return t, ErrTokenInvalid
	}
	return t, err
}

// AgentIDTaken mówi, czy identyfikator był już komuś wydany.
func (s *PG) AgentIDTaken(ctx context.Context, agentID string) (bool, error) {
	var taken bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_certs WHERE agent_id = $1)
		OR EXISTS (SELECT 1 FROM agents WHERE id = $1)`, agentID).Scan(&taken)
	return taken, err
}

// RecordAgentCert zapisuje wystawiony certyfikat.
func (s *PG) RecordAgentCert(ctx context.Context, c AgentCert) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO agent_certs (serial, agent_id, issued_at, not_after, token_id, renewed_from, hostname, remote_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, c.Serial, c.AgentID, c.IssuedAt, c.NotAfter, c.TokenID, c.RenewedFrom, c.Hostname, c.RemoteIP)
	return err
}

// AgentCertBySerial zwraca certyfikat po numerze seryjnym.
func (s *PG) AgentCertBySerial(ctx context.Context, serial string) (AgentCert, error) {
	var c AgentCert
	err := s.pool.QueryRow(ctx, `SELECT serial, agent_id, issued_at, not_after, token_id, renewed_from, hostname, remote_ip, revoked_at, revoke_reason
		FROM agent_certs WHERE serial = $1`, serial).Scan(&c.Serial, &c.AgentID, &c.IssuedAt, &c.NotAfter, &c.TokenID,
		&c.RenewedFrom, &c.Hostname, &c.RemoteIP, &c.RevokedAt, &c.RevokeReason)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}

// RevokeAgentCerts unieważnia wszystkie ważne certyfikaty agenta i zwraca
// ich numery seryjne (do rozesłania do siem-ingest).
func (s *PG) RevokeAgentCerts(ctx context.Context, agentID, reason string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `UPDATE agent_certs SET revoked_at = now(), revoke_reason = $2
		WHERE agent_id = $1 AND revoked_at IS NULL RETURNING serial`, agentID, reason)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var serial string
		if err := rows.Scan(&serial); err != nil {
			return nil, err
		}
		out = append(out, serial)
	}
	return out, rows.Err()
}

// RevokedSerials zwraca unieważnione, jeszcze nie wygasłe certyfikaty.
func (s *PG) RevokedSerials(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT serial FROM agent_certs WHERE revoked_at IS NOT NULL AND not_after > $1`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var serial string
		if err := rows.Scan(&serial); err != nil {
			return nil, err
		}
		out = append(out, serial)
	}
	return out, rows.Err()
}

// EnrollTokenByHash zwraca ważny token bez zużywania go (np. do zbudowania
// paczki instalacyjnej).
func (s *PG) EnrollTokenByHash(ctx context.Context, tokenHash string, now time.Time) (EnrollToken, error) {
	t, err := scanToken(s.pool.QueryRow(ctx, `SELECT `+tokenCols+` FROM enrollment_tokens
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2 AND (max_uses = 0 OR uses < max_uses)`, tokenHash, now))
	if errors.Is(err, ErrNotFound) {
		return t, ErrTokenInvalid
	}
	return t, err
}
