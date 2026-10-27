// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// APIToken to token dostępu programu do API (konto serwisowe). Sam token
// zna tylko jego właściciel; w bazie jest skrót (TokenHash) i początek
// (Prefix – do rozpoznania tokenu na liście).
type APIToken struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	TokenHash   string     `json:"-"`
	Prefix      string     `json:"prefix"`
	Profile     string     `json:"profile"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP  string     `json:"last_used_ip,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	RevokedBy   string     `json:"revoked_by,omitempty"`
	// Kind: integration (programy) albo ai (serwer MCP – polityka AI).
	Kind string `json:"kind"`
}

// Rodzaje tokenów API.
const (
	TokenIntegration = "integration"
	TokenAI          = "ai"
)

const apiTokenCols = `id, name, description, token_hash, prefix, profile, created_by, created_at, expires_at,
	last_used_at, last_used_ip, revoked_at, revoked_by, kind`

func scanAPIToken(row pgx.Row) (APIToken, error) {
	var t APIToken
	err := row.Scan(&t.ID, &t.Name, &t.Description, &t.TokenHash, &t.Prefix, &t.Profile, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt,
		&t.LastUsedAt, &t.LastUsedIP, &t.RevokedAt, &t.RevokedBy, &t.Kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

// CreateAPIToken zapisuje nowy token (ErrConflict – aktywny token o tej nazwie istnieje).
func (s *PG) CreateAPIToken(ctx context.Context, t APIToken) (APIToken, error) {
	if t.Kind == "" {
		t.Kind = TokenIntegration
	}
	created, err := scanAPIToken(s.pool.QueryRow(ctx, `INSERT INTO api_tokens
		(name, description, token_hash, prefix, profile, created_by, created_at, expires_at, kind)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING `+apiTokenCols,
		t.Name, t.Description, t.TokenHash, t.Prefix, t.Profile, t.CreatedBy, t.CreatedAt, t.ExpiresAt, t.Kind))
	if isUniqueViolation(err) {
		return created, ErrConflict
	}
	return created, err
}

// ListAPITokens zwraca tokeny: aktywne i wygasłe, unieważnione z ostatnich 90 dni.
func (s *PG) ListAPITokens(ctx context.Context, now time.Time) ([]APIToken, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+apiTokenCols+` FROM api_tokens
		WHERE revoked_at IS NULL OR revoked_at > $1::timestamptz - interval '90 days'
		ORDER BY revoked_at IS NOT NULL, lower(name), id DESC`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// APITokenByHash zwraca ważny token (nieunieważniony i niewygasły).
func (s *PG) APITokenByHash(ctx context.Context, hash string, now time.Time) (APIToken, error) {
	return scanAPIToken(s.pool.QueryRow(ctx, `SELECT `+apiTokenCols+` FROM api_tokens
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2`, hash, now))
}

// TouchAPIToken zapisuje ostatnie użycie tokenu.
func (s *PG) TouchAPIToken(ctx context.Context, id int64, at time.Time, ip string) error {
	_, err := s.pool.Exec(ctx, `UPDATE api_tokens SET last_used_at = $2, last_used_ip = $3 WHERE id = $1`, id, at, ip)
	return err
}

// RevokeAPIToken unieważnia token (ErrNotFound – nie ma takiego aktywnego).
func (s *PG) RevokeAPIToken(ctx context.Context, id int64, by string, now time.Time) (APIToken, error) {
	return scanAPIToken(s.pool.QueryRow(ctx, `UPDATE api_tokens SET revoked_at = $3, revoked_by = $2
		WHERE id = $1 AND revoked_at IS NULL RETURNING `+apiTokenCols, id, by, now))
}

// APIRequest to zapytanie wykonane tokenem (historia w panelu).
type APIRequest struct {
	ID         int64     `json:"id"`
	TokenID    int64     `json:"token_id"`
	At         time.Time `json:"at"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Status     int       `json:"status"`
	DurationMS int       `json:"duration_ms"`
	IP         string    `json:"ip"`
}

// RecordAPIRequests zapisuje paczkę zapytań (jedno polecenie COPY).
func (s *PG) RecordAPIRequests(ctx context.Context, reqs []APIRequest) error {
	_, err := s.pool.CopyFrom(ctx, pgx.Identifier{"api_token_requests"},
		[]string{"token_id", "at", "method", "path", "status", "duration_ms", "ip"},
		pgx.CopyFromSlice(len(reqs), func(i int) ([]any, error) {
			r := reqs[i]
			return []any{r.TokenID, r.At, r.Method, r.Path, r.Status, r.DurationMS, r.IP}, nil
		}))
	return err
}

// APIRequests zwraca zapytania tokenu od najnowszych; beforeID > 0 – starsze niż ten wpis.
func (s *PG) APIRequests(ctx context.Context, tokenID int64, limit int, beforeID int64) ([]APIRequest, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT id, token_id, at, method, path, status, duration_ms, ip FROM api_token_requests
		WHERE token_id = $1 AND ($3 = 0 OR id < $3) ORDER BY id DESC LIMIT $2`, tokenID, limit, beforeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIRequest{}
	for rows.Next() {
		var r APIRequest
		if err := rows.Scan(&r.ID, &r.TokenID, &r.At, &r.Method, &r.Path, &r.Status, &r.DurationMS, &r.IP); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// APIRequestCounts liczy zapytania tokenów od chwili since (token → liczba).
func (s *PG) APIRequestCounts(ctx context.Context, since time.Time) (map[int64]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT token_id, count(*) FROM api_token_requests WHERE at > $1 GROUP BY token_id`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// DeleteOldAPIRequests usuwa historię zapytań starszą niż before.
func (s *PG) DeleteOldAPIRequests(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM api_token_requests WHERE at < $1`, before)
	return tag.RowsAffected(), err
}

// ProfileTokens liczy ważne tokeny z każdym profilem.
func (s *PG) ProfileTokens(ctx context.Context, now time.Time) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT profile, count(*) FROM api_tokens
		WHERE revoked_at IS NULL AND expires_at > $1 GROUP BY profile`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// KindRequest to zapytanie tokenu z nazwą tokenu (historia zapytań AI).
type KindRequest struct {
	APIRequest
	TokenName string `json:"token_name"`
}

// APIRequestsByKind: zapytania tokenów danego rodzaju od najnowszych
// (beforeID > 0 – starsze niż ten wpis).
func (s *PG) APIRequestsByKind(ctx context.Context, kind string, limit int, beforeID int64) ([]KindRequest, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT r.id, r.token_id, r.at, r.method, r.path, r.status, r.duration_ms, r.ip, t.name
		FROM api_token_requests r JOIN api_tokens t ON t.id = r.token_id
		WHERE t.kind = $1 AND ($3 = 0 OR r.id < $3) ORDER BY r.id DESC LIMIT $2`, kind, limit, beforeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []KindRequest{}
	for rows.Next() {
		var r KindRequest
		if err := rows.Scan(&r.ID, &r.TokenID, &r.At, &r.Method, &r.Path, &r.Status, &r.DurationMS, &r.IP, &r.TokenName); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Pseudonym to pseudonim danych maskowanych dla AI.
type Pseudonym struct {
	Pseudonym string    `json:"pseudonym"`
	Kind      string    `json:"kind"`
	Value     string    `json:"value"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// SavePseudonyms zapisuje pseudonimy (pseudonim → rodzaj i wartość);
// istniejące – tylko czas ostatniego użycia.
func (s *PG) SavePseudonyms(ctx context.Context, ps []Pseudonym, now time.Time) error {
	if len(ps) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for _, p := range ps {
		b.Queue(`INSERT INTO ai_pseudonyms (pseudonym, kind, value, first_seen, last_seen) VALUES ($1, $2, $3, $4, $4)
			ON CONFLICT (pseudonym) DO UPDATE SET last_seen = $4`, p.Pseudonym, p.Kind, p.Value, now)
	}
	return s.pool.SendBatch(ctx, b).Close()
}

// PseudonymOf zwraca wartość pseudonimu (ErrNotFound – nieznany).
func (s *PG) PseudonymOf(ctx context.Context, pseudonym string) (Pseudonym, error) {
	var p Pseudonym
	err := s.pool.QueryRow(ctx, `SELECT pseudonym, kind, value, first_seen, last_seen FROM ai_pseudonyms WHERE pseudonym = $1`,
		pseudonym).Scan(&p.Pseudonym, &p.Kind, &p.Value, &p.FirstSeen, &p.LastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// AlertAnalysis to analiza AI alertu zapisana przy alercie.
type AlertAnalysis struct {
	ID        int64     `json:"id"`
	AlertID   int64     `json:"alert_id"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	Model     string    `json:"model"`
	Question  string    `json:"question,omitempty"`
	Answer    string    `json:"answer"`
	Steps     int       `json:"steps"`
	Tools     []string  `json:"tools"`
	Tokens    int       `json:"tokens"`
	TookMS    int       `json:"took_ms"`
}

// SaveAlertAnalysis zapisuje analizę i zwraca ją z nadanym identyfikatorem.
func (s *PG) SaveAlertAnalysis(ctx context.Context, a AlertAnalysis) (AlertAnalysis, error) {
	if a.Tools == nil {
		a.Tools = []string{}
	}
	err := s.pool.QueryRow(ctx, `INSERT INTO alert_ai_analyses (alert_id, created_at, created_by, model, question, answer, steps, tools, tokens, took_ms)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
		a.AlertID, a.CreatedAt, a.CreatedBy, a.Model, a.Question, a.Answer, a.Steps, a.Tools, a.Tokens, a.TookMS).Scan(&a.ID)
	return a, err
}

// AlertAnalyses zwraca analizy alertu (najnowsze pierwsze).
func (s *PG) AlertAnalyses(ctx context.Context, alertID int64, limit int) ([]AlertAnalysis, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, alert_id, created_at, created_by, model, question, answer, steps, tools, tokens, took_ms
		FROM alert_ai_analyses WHERE alert_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2`, alertID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AlertAnalysis{}
	for rows.Next() {
		var a AlertAnalysis
		if err := rows.Scan(&a.ID, &a.AlertID, &a.CreatedAt, &a.CreatedBy, &a.Model, &a.Question, &a.Answer, &a.Steps, &a.Tools,
			&a.Tokens, &a.TookMS); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAlertAnalysis usuwa analizę alertu (ErrNotFound – nie ma takiej).
func (s *PG) DeleteAlertAnalysis(ctx context.Context, alertID, id int64) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM alert_ai_analyses WHERE alert_id = $1 AND id = $2`, alertID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
