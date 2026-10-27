// SPDX-License-Identifier: AGPL-3.0-or-later

// Package store to dostęp do bazy Saga (PostgreSQL): konta panelu, sesje
// i dziennik audytu.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("already exists")
)

// Role użytkowników panelu.
const (
	RoleAdmin   = "admin"   // wszystko, w tym konta i konfiguracja
	RoleAnalyst = "analyst" // praca z danymi (zdarzenia, alerty), bez administracji
	RoleViewer  = "viewer"  // tylko odczyt
)

// ValidRole sprawdza nazwę roli.
func ValidRole(r string) bool { return r == RoleAdmin || r == RoleAnalyst || r == RoleViewer }

// User to konto panelu.
type User struct {
	ID                 int64      `json:"id"`
	Username           string     `json:"username"`
	DisplayName        string     `json:"display_name"`
	PasswordHash       string     `json:"-"`
	Role               string     `json:"role"`
	Disabled           bool       `json:"disabled"`
	MustChangePassword bool       `json:"must_change_password"`
	FailedLogins       int        `json:"-"`
	LockedUntil        *time.Time `json:"locked_until,omitempty"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	// Source: local – hasło w panelu; ldap – konto domenowe (hasło i
	// profil z AD). ExternalID: SID konta w AD, LDAPDN: jego DN.
	Source     string `json:"source"`
	ExternalID string `json:"-"`
	LDAPDN     string `json:"-"`
	// Language: język panelu wybrany przez użytkownika; pusty – z przeglądarki.
	Language string `json:"language"`
}

// Źródła kont.
const (
	SourceLocal = "local"
	SourceLDAP  = "ldap"
)

// Session to sesja zalogowanego użytkownika.
type Session struct {
	ID         string // SHA-256 tokenu z ciasteczka
	UserID     int64
	CSRF       string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	IP         string
	UserAgent  string
	MFA        bool // potwierdzona drugim składnikiem
	// ReauthAt: ostatnie potwierdzenie tożsamości u dostawcy OIDC (konta SSO
	// nie mają hasła do ponownego podania).
	ReauthAt *time.Time
}

// AuditEntry to wpis dziennika audytu.
type AuditEntry struct {
	ID       int64          `json:"id"`
	At       time.Time      `json:"at"`
	UserID   *int64         `json:"user_id,omitempty"`
	Username string         `json:"username"`
	Action   string         `json:"action"`
	Target   string         `json:"target,omitempty"`
	IP       string         `json:"ip,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
}

// UserPatch to zmiana konta (nil = bez zmian).
type UserPatch struct {
	DisplayName *string
	Role        *string
	Disabled    *bool
	Language    *string
}

// PG to implementacja na PostgreSQL.
type PG struct {
	pool *pgxpool.Pool
}

// Open łączy się z bazą (URL w formacie postgres://…).
func Open(ctx context.Context, url string) (*PG, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("database address: %w", err)
	}
	cfg.MaxConns = 10
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

// Close zamyka pulę połączeń.
func (s *PG) Close() { s.pool.Close() }

// Ping sprawdza połączenie (dla /api/v1/health).
func (s *PG) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

const userCols = `id, username, display_name, password_hash, role, disabled, must_change_password,
	failed_logins, locked_until, last_login_at, created_at, updated_at, source, coalesce(external_id, ''), ldap_dn, language`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, &u.Role, &u.Disabled, &u.MustChangePassword,
		&u.FailedLogins, &u.LockedUntil, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt, &u.Source, &u.ExternalID, &u.LDAPDN, &u.Language)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	return u, err
}

func isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

// CreateUser zakłada konto.
func (s *PG) CreateUser(ctx context.Context, u User) (User, error) {
	row := s.pool.QueryRow(ctx, `INSERT INTO users (username, display_name, password_hash, role, must_change_password)
		VALUES ($1, $2, $3, $4, $5) RETURNING `+userCols,
		u.Username, u.DisplayName, u.PasswordHash, u.Role, u.MustChangePassword)
	created, err := scanUser(row)
	if isUniqueViolation(err) {
		return created, ErrConflict
	}
	return created, err
}

// UserByUsername szuka konta bez rozróżniania wielkości liter.
func (s *PG) UserByUsername(ctx context.Context, username string) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE lower(username) = lower($1)`, username))
}

// UserByID zwraca konto.
func (s *PG) UserByID(ctx context.Context, id int64) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = $1`, id))
}

// ListUsers zwraca wszystkie konta.
func (s *PG) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY lower(username)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUser zmienia nazwę wyświetlaną, rolę lub blokadę konta.
func (s *PG) UpdateUser(ctx context.Context, id int64, p UserPatch) (User, error) {
	return scanUser(s.pool.QueryRow(ctx, `UPDATE users SET
			display_name = COALESCE($2, display_name),
			role         = COALESCE($3, role),
			disabled     = COALESCE($4, disabled),
			language     = COALESCE($5, language),
			updated_at   = now()
		WHERE id = $1 RETURNING `+userCols, id, p.DisplayName, p.Role, p.Disabled, p.Language))
}

// SetPassword ustawia nowy hash hasła i zdejmuje blokadę po nieudanych logowaniach.
func (s *PG) SetPassword(ctx context.Context, id int64, hash string, mustChange bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE users SET password_hash = $2, must_change_password = $3,
		failed_logins = 0, locked_until = NULL, updated_at = now() WHERE id = $1`, id, hash, mustChange)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// RecordLoginFailure zwiększa licznik nieudanych logowań; po lockAfter
// kolejnych porażkach blokuje konto na lockFor. Zwraca czas końca blokady.
func (s *PG) RecordLoginFailure(ctx context.Context, id int64, lockAfter int, lockFor time.Duration) (*time.Time, error) {
	var until *time.Time
	err := s.pool.QueryRow(ctx, `UPDATE users SET
			failed_logins = failed_logins + 1,
			locked_until  = CASE WHEN failed_logins + 1 >= $2 THEN now() + make_interval(secs => $3) ELSE locked_until END
		WHERE id = $1 RETURNING locked_until`, id, lockAfter, lockFor.Seconds()).Scan(&until)
	return until, err
}

// RecordLoginSuccess zeruje licznik porażek i zapisuje czas logowania.
func (s *PG) RecordLoginSuccess(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = now() WHERE id = $1`, id)
	return err
}

// CountActiveAdmins liczy aktywne konta administratorów (nie wolno usunąć ostatniego).
func (s *PG) CountActiveAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE role = 'admin' AND NOT disabled`).Scan(&n)
	return n, err
}

// CreateSession zapisuje nową sesję.
func (s *PG) CreateSession(ctx context.Context, ss Session) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO sessions (id, user_id, csrf, created_at, last_seen_at, expires_at, ip, user_agent, mfa)
		VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8)`, ss.ID, ss.UserID, ss.CSRF, ss.CreatedAt, ss.ExpiresAt, ss.IP, ss.UserAgent, ss.MFA)
	return err
}

// SessionWithUser zwraca ważną sesję razem z kontem.
func (s *PG) SessionWithUser(ctx context.Context, id string, now time.Time) (Session, User, error) {
	var ss Session
	row := s.pool.QueryRow(ctx, `SELECT s.id, s.user_id, s.csrf, s.created_at, s.last_seen_at, s.expires_at, s.ip, s.user_agent, s.mfa, s.reauth_at,
			u.id, u.username, u.display_name, u.password_hash, u.role, u.disabled, u.must_change_password,
			u.failed_logins, u.locked_until, u.last_login_at, u.created_at, u.updated_at, u.source, coalesce(u.external_id, ''), u.ldap_dn
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.id = $1 AND s.expires_at > $2`, id, now)
	var u User
	err := row.Scan(&ss.ID, &ss.UserID, &ss.CSRF, &ss.CreatedAt, &ss.LastSeenAt, &ss.ExpiresAt, &ss.IP, &ss.UserAgent, &ss.MFA, &ss.ReauthAt,
		&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, &u.Role, &u.Disabled, &u.MustChangePassword,
		&u.FailedLogins, &u.LockedUntil, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt, &u.Source, &u.ExternalID, &u.LDAPDN)
	if errors.Is(err, pgx.ErrNoRows) {
		return ss, u, ErrNotFound
	}
	return ss, u, err
}

// TouchSession przedłuża sesję (przesuwa limit bezczynności).
func (s *PG) TouchSession(ctx context.Context, id string, seen, expires time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at = $2, expires_at = $3 WHERE id = $1`, id, seen, expires)
	return err
}

// DeleteSession kończy sesję (wylogowanie).
func (s *PG) DeleteSession(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	return err
}

// DeleteUserSessions kończy wszystkie sesje konta poza exceptID (np. po zmianie hasła).
func (s *PG) DeleteUserSessions(ctx context.Context, userID int64, exceptID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND id <> $2`, userID, exceptID)
	return err
}

// DeleteExpiredSessions usuwa wygasłe sesje.
func (s *PG) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= $1`, now)
	return tag.RowsAffected(), err
}

// Audit dopisuje wpis do dziennika audytu.
func (s *PG) Audit(ctx context.Context, e AuditEntry) error {
	details, err := json.Marshal(e.Details)
	if err != nil || e.Details == nil {
		details = []byte("{}")
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO audit_log (user_id, username, action, target, ip, details)
		VALUES ($1, $2, $3, $4, $5, $6)`, e.UserID, e.Username, e.Action, e.Target, e.IP, details)
	return err
}

// ListAudit zwraca wpisy od najnowszych; beforeID > 0 – strona starsza niż ten wpis.
func (s *PG) ListAudit(ctx context.Context, limit int, beforeID int64) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT id, at, user_id, username, action, target, ip, details FROM audit_log
		WHERE ($2 = 0 OR id < $2) ORDER BY id DESC LIMIT $1`, limit, beforeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var details []byte
		if err := rows.Scan(&e.ID, &e.At, &e.UserID, &e.Username, &e.Action, &e.Target, &e.IP, &details); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(details, &e.Details)
		if len(e.Details) == 0 {
			e.Details = nil
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
